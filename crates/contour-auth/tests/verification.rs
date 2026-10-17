use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contour_auth::{AuthError, IdTokenVerifier, MAX_ID_TOKEN_BYTES, MAX_JWKS_BYTES};
use jsonwebtoken::{Algorithm, EncodingKey, crypto::sign};
use serde_json::{Value, json};
const ISSUER: &str = "https://idp.example.test/realms/demo";
const CLIENT: &str = "apicontour";
const NONCE: &str = "server-generated-one-use-nonce";
const NOW: u64 = 1_800_000_000;
const JWKS: &[u8] = include_bytes!("fixtures/public-jwks.json");
fn verifier() -> IdTokenVerifier {
    IdTokenVerifier::new(ISSUER, CLIENT, JWKS).unwrap()
}
fn claims() -> Value {
    json!({"iss":ISSUER,"sub":"synthetic-user","aud":CLIENT,"exp":NOW+300,"iat":NOW,"nonce":NONCE})
}
fn token_raw(header: &str, claims: &str, algorithm: Algorithm) -> String {
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let key = EncodingKey::from_rsa_der(include_bytes!("fixtures/synthetic-rsa.der"));
    format!(
        "{}.{}",
        message,
        sign(message.as_bytes(), &key, algorithm).unwrap()
    )
}
fn token(claims: &Value) -> String {
    token_raw(
        r#"{"alg":"RS256","kid":"synthetic-rsa","typ":"JWT"}"#,
        &claims.to_string(),
        Algorithm::RS256,
    )
}
fn rejected(body: &Value) {
    assert!(matches!(
        verifier().verify(&token(body), NONCE, NOW),
        Err(AuthError::InvalidToken)
    ));
}

#[test]
fn valid_identity_is_checked_but_not_an_actor() {
    let verified = verifier().verify(&token(&claims()), NONCE, NOW).unwrap();
    assert_eq!(verified.issuer(), ISSUER);
    assert_eq!(verified.subject(), "synthetic-user");
    assert_eq!(verified.expires_at(), NOW + 300);
    assert_eq!(format!("{verified:?}"), "VerifiedIdentity");
    assert_eq!(format!("{:?}", verifier()), "IdTokenVerifier");
    assert_eq!(AuthError::InvalidToken.to_string(), "InvalidToken");
    let mut extra = claims();
    extra["email"] = json!("synthetic@example.test");
    assert!(verifier().verify(&token(&extra), NONCE, NOW).is_ok());
}
#[test]
fn required_claims_types_and_duplicates_are_strict() {
    for name in ["iss", "sub", "aud", "exp", "iat", "nonce"] {
        let mut missing = claims();
        missing.as_object_mut().unwrap().remove(name);
        rejected(&missing);
        let mut null = claims();
        null[name] = Value::Null;
        rejected(&null);
        let mut object = claims();
        object[name] = json!({"unexpected":null});
        rejected(&object);
    }
    for name in ["exp", "iat", "nbf"] {
        for value in [
            json!("1800000000"),
            json!(false),
            json!(-1),
            json!(1.5),
            Value::Null,
        ] {
            let mut body = claims();
            body[name] = value;
            rejected(&body);
        }
    }
    let raw = claims().to_string();
    for extra in [r#", "sub":"another"}"#, r#", "nbf":0,"nbf":1}"#] {
        let duplicate = format!("{}{}", &raw[..raw.len() - 1], extra);
        assert!(
            verifier()
                .verify(
                    &token_raw(
                        r#"{"alg":"RS256","kid":"synthetic-rsa"}"#,
                        &duplicate,
                        Algorithm::RS256
                    ),
                    NONCE,
                    NOW
                )
                .is_err()
        );
    }
    let array = format!(
        r#"["{ISSUER}","synthetic-user","{CLIENT}",{}, {},"{NONCE}"]"#,
        NOW + 300,
        NOW
    );
    assert!(
        verifier()
            .verify(
                &token_raw(
                    r#"{"alg":"RS256","kid":"synthetic-rsa"}"#,
                    &array,
                    Algorithm::RS256
                ),
                NONCE,
                NOW
            )
            .is_err()
    );
}
#[test]
fn issuer_audience_nonce_and_subject_are_bound() {
    for (name, value) in [
        ("iss", json!("https://other.example.test")),
        ("aud", json!("another-client")),
        ("nonce", json!("attacker")),
        ("sub", json!("")),
        ("sub", json!("é")),
        ("sub", json!("x".repeat(256))),
    ] {
        let mut body = claims();
        body[name] = value;
        rejected(&body);
    }
    let mut body = claims();
    body["sub"] = json!("x".repeat(255));
    assert!(verifier().verify(&token(&body), NONCE, NOW).is_ok());
    assert!(
        verifier()
            .verify(&token(&claims()), "different-transaction", NOW)
            .is_err()
    );
    assert!(matches!(
        verifier().verify(&token(&claims()), "", NOW),
        Err(AuthError::Configuration)
    ));
}
#[test]
fn time_boundaries_and_malformed_optional_nbf() {
    let valid = token(&claims());
    assert!(verifier().verify(&valid, NONCE, NOW + 299).is_ok());
    assert!(verifier().verify(&valid, NONCE, NOW + 300).is_err());
    assert!(verifier().verify(&valid, NONCE, NOW - 1).is_err());
    for value in [
        json!(NOW + 1),
        json!(u64::MAX),
        json!("9999999999999999999"),
        Value::Null,
    ] {
        let mut body = claims();
        body["nbf"] = value;
        rejected(&body);
    }
    let mut body = claims();
    body["nbf"] = json!(NOW);
    assert!(verifier().verify(&token(&body), NONCE, NOW).is_ok());
    body["exp"] = json!(NOW);
    rejected(&body);
    body["exp"] = json!(u64::MAX);
    assert!(verifier().verify(&token(&body), NONCE, NOW).is_ok());
}
#[test]
fn multiple_audiences_require_matching_authorized_party() {
    for audience in [
        json!([]),
        json!([CLIENT, 1]),
        json!([CLIENT, null]),
        json!(""),
        json!(["x".repeat(257)]),
    ] {
        let mut body = claims();
        body["aud"] = audience;
        rejected(&body);
    }
    let mut body = claims();
    body["aud"] = json!([CLIENT, "second-client"]);
    rejected(&body);
    for azp in [json!("second-client"), Value::Null, json!(true)] {
        body["azp"] = azp;
        rejected(&body);
    }
    body["azp"] = json!(CLIENT);
    assert!(verifier().verify(&token(&body), NONCE, NOW).is_ok());
    body["aud"] = json!(vec![CLIENT; 16]);
    assert!(verifier().verify(&token(&body), NONCE, NOW).is_ok());
    body["aud"] = json!(vec![CLIENT; 17]);
    rejected(&body);
}
#[test]
fn signatures_algorithms_and_header_trust_are_closed() {
    let valid = token(&claims());
    let mut tampered = valid.into_bytes();
    let last = tampered.len() - 10;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    assert!(
        verifier()
            .verify(std::str::from_utf8(&tampered).unwrap(), NONCE, NOW)
            .is_err()
    );
    let wrong_alg = token_raw(
        r#"{"alg":"RS512","kid":"synthetic-rsa"}"#,
        &claims().to_string(),
        Algorithm::RS512,
    );
    assert!(verifier().verify(&wrong_alg, NONCE, NOW).is_err());
    for header in [
        r#"{"alg":"RS256","kid":"unapproved"}"#,
        r#"{"alg":"RS256"}"#,
        r#"{"alg":{"RS256":null},"kid":"synthetic-rsa"}"#,
        r#"{"alg":"RS256","kid":"synthetic-rsa","kid":"unapproved"}"#,
        r#"["RS256","synthetic-rsa"]"#,
        r#"{"alg":"RS256","kid":"synthetic-rsa","crit":[]}"#,
        r#"{"alg":"RS256","kid":"synthetic-rsa","jku":"https://attacker.test/keys"}"#,
        r#"{"alg":"RS256","kid":"synthetic-rsa","jwk":{}}"#,
        r#"{"alg":"RS256","kid":"synthetic-rsa","typ":"at+jwt"}"#,
    ] {
        assert!(
            verifier()
                .verify(
                    &token_raw(header, &claims().to_string(), Algorithm::RS256),
                    NONCE,
                    NOW
                )
                .is_err()
        );
    }
    assert!(
        verifier()
            .verify("eyJhbGciOiJub25lIn0.e30.", NONCE, NOW)
            .is_err()
    );
}
#[test]
fn configuration_and_allocation_bounds() {
    for issuer in [
        "",
        "http://idp.test",
        "https://",
        "https://idp.test?query",
        "https://user@idp.test",
    ] {
        assert!(IdTokenVerifier::new(issuer, CLIENT, JWKS).is_err());
    }
    assert!(IdTokenVerifier::new(ISSUER, "", JWKS).is_err());
    let mut padded = JWKS.to_vec();
    padded.resize(MAX_JWKS_BYTES, b' ');
    assert!(IdTokenVerifier::new(ISSUER, CLIENT, &padded).is_ok());
    padded.push(b' ');
    assert!(IdTokenVerifier::new(ISSUER, CLIENT, &padded).is_err());
    assert!(matches!(
        verifier().verify(&"x".repeat(MAX_ID_TOKEN_BYTES), NONCE, NOW),
        Err(AuthError::InvalidToken)
    ));
    assert!(matches!(
        verifier().verify(&"x".repeat(MAX_ID_TOKEN_BYTES + 1), NONCE, NOW),
        Err(AuthError::TooLarge)
    ));
    for body in [
        r#"{"keys":[]}"#,
        r#"{"keys":[[]]}"#,
        r#"[]"#,
        r#"{"keys":[],"keys":[]}"#,
    ] {
        assert!(IdTokenVerifier::new(ISSUER, CLIENT, body.as_bytes()).is_err());
    }
    let original: Value = serde_json::from_slice(JWKS).unwrap();
    for (name, value) in [
        ("d", json!("private-key-component")),
        ("kty", json!("oct")),
        ("use", json!("enc")),
        ("alg", json!("HS256")),
        ("key_ops", json!(["sign"])),
        ("e", json!("Ag")),
        ("n", json!("AQ")),
        ("kid", json!("")),
    ] {
        let mut body = original.clone();
        body["keys"][0][name] = value;
        assert!(IdTokenVerifier::new(ISSUER, CLIENT, &serde_json::to_vec(&body).unwrap()).is_err());
    }
    let mut duplicate = original.clone();
    duplicate["keys"] = json!([original["keys"][0], original["keys"][0]]);
    assert!(
        IdTokenVerifier::new(ISSUER, CLIENT, &serde_json::to_vec(&duplicate).unwrap()).is_err()
    );
    let keys: Vec<_> = (0..33)
        .map(|i| {
            let mut key = original["keys"][0].clone();
            key["kid"] = json!(format!("key-{i}"));
            key
        })
        .collect();
    assert!(
        IdTokenVerifier::new(
            ISSUER,
            CLIENT,
            &serde_json::to_vec(&json!({"keys":&keys[..32]})).unwrap()
        )
        .is_ok()
    );
    assert!(
        IdTokenVerifier::new(
            ISSUER,
            CLIENT,
            &serde_json::to_vec(&json!({"keys":keys})).unwrap()
        )
        .is_err()
    );
}
