use crate::{AUTHORITY, MAX_BODY, ORIGIN, PlatformError};
use hyper::{HeaderMap, Request};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use std::{collections::HashMap, fmt};

pub(crate) fn opaque(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
pub(crate) fn encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}
fn decode(value: &str) -> Result<String, PlatformError> {
    let mut bytes = value.bytes();
    let mut result = Vec::new();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => result.push(b' '),
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(|v| char::from(v).to_digit(16))
                    .ok_or(PlatformError::InvalidRequest)?;
                let low = bytes
                    .next()
                    .and_then(|v| char::from(v).to_digit(16))
                    .ok_or(PlatformError::InvalidRequest)?;
                result.push((high * 16 + low) as u8);
            }
            value => result.push(value),
        }
    }
    if result.iter().any(|byte| *byte < 32 || *byte == 127) {
        return Err(PlatformError::InvalidRequest);
    }
    String::from_utf8(result).map_err(|_| PlatformError::InvalidRequest)
}
pub(crate) fn query(value: &str) -> Result<HashMap<String, String>, PlatformError> {
    if value.len() > 8192 {
        return Err(PlatformError::InvalidRequest);
    }
    let mut output = HashMap::new();
    for pair in value.split('&') {
        if output.len() >= 16 {
            return Err(PlatformError::InvalidRequest);
        }
        let (key, value) = pair.split_once('=').ok_or(PlatformError::InvalidRequest)?;
        let key = decode(key)?;
        if key.is_empty() || output.insert(key, decode(value)?).is_some() {
            return Err(PlatformError::InvalidRequest);
        }
    }
    Ok(output)
}
pub(crate) fn cookies(headers: &HeaderMap) -> Result<HashMap<String, String>, PlatformError> {
    if headers.get_all("cookie").iter().count() > 1 {
        return Err(PlatformError::InvalidRequest);
    }
    let mut output = HashMap::new();
    if let Some(header) = headers.get("cookie") {
        let header = header.to_str().map_err(|_| PlatformError::InvalidRequest)?;
        if header.len() > 8192 {
            return Err(PlatformError::InvalidRequest);
        }
        for pair in header.split(';') {
            if output.len() >= 32 {
                return Err(PlatformError::InvalidRequest);
            }
            let (name, value) = pair
                .trim()
                .split_once('=')
                .ok_or(PlatformError::InvalidRequest)?;
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || !value.bytes().all(|b| {
                    b == 0x21
                        || (0x23..=0x2b).contains(&b)
                        || (0x2d..=0x3a).contains(&b)
                        || (0x3c..=0x5b).contains(&b)
                        || (0x5d..=0x7e).contains(&b)
                })
                || output.insert(name.to_owned(), value.to_owned()).is_some()
            {
                return Err(PlatformError::InvalidRequest);
            }
        }
    }
    Ok(output)
}
pub(crate) fn validate_request<B>(request: &Request<B>) -> Result<(), PlatformError> {
    let headers = request.headers();
    if request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || request.uri().path().len() > 1024
        || request.uri().path().contains('%')
        || headers.len() > 32
        || headers
            .iter()
            .map(|(key, value)| key.as_str().len() + value.len())
            .sum::<usize>()
            > 16384
        || headers.get_all("host").iter().count() != 1
        || headers.get("host").and_then(|v| v.to_str().ok()) != Some(AUTHORITY)
        || headers.contains_key("content-encoding")
        || headers.contains_key("expect")
        || headers.get_all("content-length").iter().count() > 1
        || headers.get("content-length").is_some_and(|v| {
            v.to_str()
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .is_none_or(|v| v > MAX_BODY)
        })
    {
        return Err(PlatformError::InvalidRequest);
    }
    if let Some(value) = request.uri().query() {
        query(value)?;
        if request.uri().path() != "/auth/callback" && !request.uri().path().starts_with("/v1/") {
            return Err(PlatformError::InvalidRequest);
        }
    }
    cookies(headers)?;
    if !matches!(request.method().as_str(), "GET" | "HEAD")
        && (!matches!(
            request.method().as_str(),
            "POST" | "PUT" | "PATCH" | "DELETE"
        ) || headers.get_all("origin").iter().count() != 1
            || headers.get("origin").and_then(|v| v.to_str().ok()) != Some(ORIGIN)
            || headers.get_all("content-type").iter().count() != 1
            || !headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v == "application/json" || v == "application/json; charset=utf-8"))
    {
        return Err(PlatformError::InvalidRequest);
    }
    Ok(())
}

// Reject duplicate top-level token response fields before selecting the ID token.
// Access/refresh tokens are ignored and never retained. Body has a separate 64KiB cap.
struct TokenResponse(String);
impl<'de> Deserialize<'de> for TokenResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TokenVisitor;
        impl<'de> Visitor<'de> for TokenVisitor {
            type Value = TokenResponse;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("token response")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut keys = std::collections::HashSet::<String>::new();
                let mut token = None;
                while let Some(key) = map.next_key::<String>()? {
                    if keys.len() >= 32 || !keys.insert(key.clone()) {
                        return Err(serde::de::Error::custom("invalid token response"));
                    }
                    if key == "id_token" {
                        token = Some(map.next_value::<String>()?);
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                token
                    .map(TokenResponse)
                    .ok_or_else(|| serde::de::Error::custom("missing token"))
            }
        }
        deserializer.deserialize_map(TokenVisitor)
    }
}
pub(crate) fn token(bytes: &[u8]) -> Result<String, PlatformError> {
    let TokenResponse(token) =
        serde_json::from_slice(bytes).map_err(|_| PlatformError::Unauthenticated)?;
    if token.is_empty() || token.len() > contour_auth::MAX_ID_TOKEN_BYTES {
        return Err(PlatformError::Unauthenticated);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_and_malformed_queries_are_rejected_after_decoding() {
        assert_eq!(query("code=a%2Bb&state=abc").unwrap()["code"], "a+b");
        for value in [
            "state=a&%73tate=b",
            "a=%",
            "a=%Q1",
            "a=%00",
            "a=%ff",
            "=b",
            "a",
            "a=1&a=2",
        ] {
            assert!(query(value).is_err(), "{value}");
        }
        assert!(query(&format!("a={}", "x".repeat(8192))).is_err());
        assert!(
            query(
                &(0..17)
                    .map(|i| format!("a{i}=b"))
                    .collect::<Vec<_>>()
                    .join("&")
            )
            .is_err()
        );
        assert_eq!(decode(&encode("x +&=%/")).unwrap(), "x +&=%/");
    }
    #[test]
    fn duplicate_cookie_headers_and_names_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            "__Host-contour-session=a; other=b".parse().unwrap(),
        );
        assert_eq!(cookies(&headers).unwrap()["other"], "b");
        headers.insert(
            "cookie",
            "__Host-contour-session=a; __Host-contour-session=b"
                .parse()
                .unwrap(),
        );
        assert!(cookies(&headers).is_err());
        headers.insert("cookie", "a=b".parse().unwrap());
        headers.append("cookie", "c=d".parse().unwrap());
        assert!(cookies(&headers).is_err());
    }
    fn request(method: &str, origin: Option<&str>, content: &str) -> Request<()> {
        let mut builder = Request::builder()
            .method(method)
            .uri("/auth/logout")
            .header("host", AUTHORITY)
            .header("content-type", content);
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        builder.body(()).unwrap()
    }
    #[test]
    fn exact_origin_json_and_host_required_before_mutations() {
        assert!(validate_request(&request("POST", Some(ORIGIN), "application/json")).is_ok());
        for origin in [
            None,
            Some("null"),
            Some("https://localhost:9443.evil"),
            Some("http://localhost:9443"),
            Some("https://localhost:8444"),
        ] {
            assert!(validate_request(&request("POST", origin, "application/json")).is_err());
        }
        assert!(validate_request(&request("POST", Some(ORIGIN), "text/plain")).is_err());
        let mut req = request("POST", Some(ORIGIN), "application/json");
        req.headers_mut().append("origin", ORIGIN.parse().unwrap());
        assert!(validate_request(&req).is_err());
        let mut req = request("GET", None, "text/plain");
        req.headers_mut()
            .insert("host", "evil.invalid".parse().unwrap());
        assert!(validate_request(&req).is_err());
        let mut req = request("GET", None, "text/plain");
        *req.uri_mut() = "https://localhost:9443/auth/session".parse().unwrap();
        assert!(validate_request(&req).is_err());
        assert!(validate_request(&request("OPTIONS", Some(ORIGIN), "application/json")).is_err());
    }
    #[test]
    fn token_response_does_not_accept_duplicate_selected_fields_or_oversized_token() {
        assert_eq!(
            token(br#"{"id_token":"example","access_token":"ignored"}"#).unwrap(),
            "example"
        );
        for bytes in [
            br#"{"id_token":"a","id_token":"b"}"#.as_slice(),
            br#"{"id_token":"a","scope":"a","scope":"b"}"#,
            br#"{"access_token":"only"}"#,
            br#"{"id_token":""}"#,
            br#"{"id_token":null}"#,
        ] {
            assert!(token(bytes).is_err());
        }
        assert!(
            token(
                serde_json::to_string(&serde_json::json!({"id_token":"a".repeat(16385)}))
                    .unwrap()
                    .as_bytes()
            )
            .is_err()
        );
    }
}
