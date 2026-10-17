//! Checked public review write bodies. IDs prove syntax, never authorization.
use crate::{UnsignedInteger, batch::uuid};
use serde::{Deserialize, Serialize, de};
use std::fmt;

/// Closed errors never contain submitted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewRequestError {
    TooLarge,
    InvalidJson,
    InvalidId,
    InvalidRevision,
}
impl fmt::Display for ReviewRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ReviewRequestError {}

/// A canonical lowercase UUID. Resource scope must be checked separately.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ReviewResourceId(String);
impl ReviewResourceId {
    pub fn new(value: &str) -> Result<Self, ReviewRequestError> {
        if !uuid(value) {
            return Err(ReviewRequestError::InvalidId);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for ReviewResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReviewResourceId")
    }
}
impl<'de> Deserialize<'de> for ReviewResourceId {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Id;
        impl de::Visitor<'_> for Id {
            type Value = ReviewResourceId;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("canonical UUID")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                ReviewResourceId::new(value).map_err(|_| E::custom("invalid UUID"))
            }
        }
        decoder.deserialize_str(Id)
    }
}

macro_rules! string_enum {
    ($ty:ty, $($name:literal => $variant:path),+ $(,)?) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                struct Text;
                impl de::Visitor<'_> for Text {
                    type Value = $ty;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("closed string enum")
                    }
                    fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
                        match text {
                            $($name => Ok($variant),)+
                            _ => Err(E::custom("invalid enum")),
                        }
                    }
                }
                decoder.deserialize_str(Text)
            }
        }
    };
}
string_enum!(ComparisonVersionKind,
    "observed" => ComparisonVersionKind::Observed,
    "declared" => ComparisonVersionKind::Declared,
    "approved" => ComparisonVersionKind::Approved,
);
string_enum!(ReviewDecisionKind,
    "approve" => ReviewDecisionKind::Approve,
    "reject" => ReviewDecisionKind::Reject,
);

// Calling deserialize_map prevents serde's positional struct-array fallback.
fn object_only<'de, D: de::Deserializer<'de>, T: Deserialize<'de>>(
    decoder: D,
) -> Result<T, D::Error> {
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("JSON object")
        }
        fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> Result<T, M::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }
    decoder.deserialize_map(Object(std::marker::PhantomData))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonVersionKind {
    Observed,
    Declared,
    Approved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ComparisonRequest {
    operation_id: ReviewResourceId,
    left_id: ReviewResourceId,
    left_kind: ComparisonVersionKind,
    right_id: ReviewResourceId,
    right_kind: ComparisonVersionKind,
}
impl<'de> Deserialize<'de> for ComparisonRequest {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            operation_id: ReviewResourceId,
            left_id: ReviewResourceId,
            left_kind: ComparisonVersionKind,
            right_id: ReviewResourceId,
            right_kind: ComparisonVersionKind,
        }
        let wire: Wire = object_only(decoder)?;
        Ok(Self {
            operation_id: wire.operation_id,
            left_id: wire.left_id,
            left_kind: wire.left_kind,
            right_id: wire.right_id,
            right_kind: wire.right_kind,
        })
    }
}
impl ComparisonRequest {
    pub fn new(
        operation_id: ReviewResourceId,
        left_id: ReviewResourceId,
        left_kind: ComparisonVersionKind,
        right_id: ReviewResourceId,
        right_kind: ComparisonVersionKind,
    ) -> Self {
        Self {
            operation_id,
            left_id,
            left_kind,
            right_id,
            right_kind,
        }
    }
    pub fn operation_id(&self) -> &ReviewResourceId {
        &self.operation_id
    }
    pub fn left_id(&self) -> &ReviewResourceId {
        &self.left_id
    }
    pub fn left_kind(&self) -> ComparisonVersionKind {
        self.left_kind
    }
    pub fn right_id(&self) -> &ReviewResourceId {
        &self.right_id
    }
    pub fn right_kind(&self) -> ComparisonVersionKind {
        self.right_kind
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewRequest {
    operation_id: ReviewResourceId,
    comparison_id: ReviewResourceId,
    candidate_contract_id: ReviewResourceId,
    expected_baseline_id: Option<ReviewResourceId>,
}
fn required_nullable_id<'de, D: de::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<ReviewResourceId>, D::Error> {
    Option::<ReviewResourceId>::deserialize(decoder)
}
impl<'de> Deserialize<'de> for ReviewRequest {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            operation_id: ReviewResourceId,
            comparison_id: ReviewResourceId,
            candidate_contract_id: ReviewResourceId,
            #[serde(deserialize_with = "required_nullable_id")]
            expected_baseline_id: Option<ReviewResourceId>,
        }
        let wire: Wire = object_only(decoder)?;
        Ok(Self {
            operation_id: wire.operation_id,
            comparison_id: wire.comparison_id,
            candidate_contract_id: wire.candidate_contract_id,
            expected_baseline_id: wire.expected_baseline_id,
        })
    }
}
impl ReviewRequest {
    pub fn new(
        operation_id: ReviewResourceId,
        comparison_id: ReviewResourceId,
        candidate_contract_id: ReviewResourceId,
        expected_baseline_id: Option<ReviewResourceId>,
    ) -> Self {
        Self {
            operation_id,
            comparison_id,
            candidate_contract_id,
            expected_baseline_id,
        }
    }
    pub fn operation_id(&self) -> &ReviewResourceId {
        &self.operation_id
    }
    pub fn comparison_id(&self) -> &ReviewResourceId {
        &self.comparison_id
    }
    pub fn candidate_contract_id(&self) -> &ReviewResourceId {
        &self.candidate_contract_id
    }
    pub fn expected_baseline_id(&self) -> Option<&ReviewResourceId> {
        self.expected_baseline_id.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecisionKind {
    Approve,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewDecision {
    decision: ReviewDecisionKind,
    expected_revision: UnsignedInteger,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionWire {
    decision: ReviewDecisionKind,
    expected_revision: UnsignedInteger,
}
impl ReviewDecision {
    pub fn new(
        decision: ReviewDecisionKind,
        expected_revision: u64,
    ) -> Result<Self, ReviewRequestError> {
        if expected_revision == 0 {
            return Err(ReviewRequestError::InvalidRevision);
        }
        Ok(Self {
            decision,
            expected_revision: UnsignedInteger::new(expected_revision),
        })
    }
    pub fn decision(&self) -> ReviewDecisionKind {
        self.decision
    }
    pub fn expected_revision(&self) -> u64 {
        self.expected_revision.get()
    }
    /// The byte cap is trusted endpoint policy, never a value from the request.
    pub fn from_json(bytes: &[u8], max_bytes: usize) -> Result<Self, ReviewRequestError> {
        let wire: DecisionWire = decode(bytes, max_bytes)?;
        Self::new(wire.decision, wire.expected_revision.get())
    }
}
fn decode<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    max_bytes: usize,
) -> Result<T, ReviewRequestError> {
    if bytes.len() > max_bytes {
        return Err(ReviewRequestError::TooLarge);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = object_only(&mut decoder).map_err(|_| ReviewRequestError::InvalidJson)?;
    decoder.end().map_err(|_| ReviewRequestError::InvalidJson)?;
    Ok(value)
}
macro_rules! json_codec {
    ($ty:ty) => {
        impl $ty {
            /// Enforce a trusted server policy byte cap before JSON decoding or allocation.
            /// The limit must come from endpoint configuration, never the request.
            pub fn from_json(bytes: &[u8], max_bytes: usize) -> Result<Self, ReviewRequestError> {
                decode(bytes, max_bytes)
            }
            pub fn to_json(&self) -> Result<Vec<u8>, ReviewRequestError> {
                serde_json::to_vec(self).map_err(|_| ReviewRequestError::InvalidJson)
            }
        }
    };
}
json_codec!(ComparisonRequest);
json_codec!(ReviewRequest);
impl ReviewDecision {
    pub fn to_json(&self) -> Result<Vec<u8>, ReviewRequestError> {
        serde_json::to_vec(self).map_err(|_| ReviewRequestError::InvalidJson)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "00000000-0000-0000-0000-000000000001";
    fn comparison() -> String {
        format!(
            r#"{{"operation_id":"{ID}","left_id":"{ID}","left_kind":"observed","right_id":"{ID}","right_kind":"declared"}}"#
        )
    }
    fn review() -> String {
        format!(
            r#"{{"operation_id":"{ID}","comparison_id":"{ID}","candidate_contract_id":"{ID}","expected_baseline_id":null}}"#
        )
    }
    #[test]
    fn comparison_requires_object() {
        let body = format!(r#"["{ID}","{ID}","observed","{ID}","declared"]"#);
        assert!(ComparisonRequest::from_json(body.as_bytes(), 4096).is_err());
        assert!(serde_json::from_str::<ComparisonRequest>(&body).is_err());
    }
    #[test]
    fn review_requires_object() {
        let body = format!(r#"["{ID}","{ID}","{ID}",null]"#);
        assert!(ReviewRequest::from_json(body.as_bytes(), 4096).is_err());
        assert!(serde_json::from_str::<ReviewRequest>(&body).is_err());
    }
    #[test]
    fn decision_requires_object() {
        assert!(ReviewDecision::from_json(br#"["approve",1]"#, 4096).is_err());
    }
    #[test]
    fn decision_requires_string_enum() {
        for name in ["approve", "reject"] {
            let object = format!(r#"{{"{name}":null}}"#);
            assert!(serde_json::from_str::<ReviewDecisionKind>(&object).is_err());
            let body = format!(r#"{{"decision":{object},"expected_revision":1}}"#);
            assert!(ReviewDecision::from_json(body.as_bytes(), 4096).is_err());
        }
    }
    #[test]
    fn comparison_requires_string_enum() {
        for name in ["observed", "declared", "approved"] {
            let object = format!(r#"{{"{name}":null}}"#);
            assert!(serde_json::from_str::<ComparisonVersionKind>(&object).is_err());
            let body = comparison().replace("\"observed\"", &object);
            assert!(ComparisonRequest::from_json(body.as_bytes(), 4096).is_err());
        }
    }
    #[test]
    fn strict_comparison_fields_and_ids() {
        let valid = comparison();
        let parsed = ComparisonRequest::from_json(valid.as_bytes(), valid.len()).unwrap();
        assert_eq!(parsed.operation_id().as_str(), ID);
        assert_eq!(parsed.left_kind(), ComparisonVersionKind::Observed);
        assert_eq!(
            ComparisonRequest::from_json(&parsed.to_json().unwrap(), 4096).unwrap(),
            parsed
        );
        for invalid in [
            valid.replace("\"left_kind\":\"observed\",", ""),
            valid.replace("\"observed\"", "\"OBSERVED\""),
            valid.replace("}", ",\"extra\":1}"),
            valid.replace("}", ",\"left_kind\":\"declared\"}"),
            valid.replace(ID, "00000000-0000-0000-0000-00000000000A"),
            valid.replace(ID, "00000000000000000000000000000001"),
            format!("{valid} null"),
        ] {
            assert!(ComparisonRequest::from_json(invalid.as_bytes(), 4096).is_err());
        }
        assert_eq!(
            ComparisonRequest::from_json(valid.as_bytes(), valid.len() - 1),
            Err(ReviewRequestError::TooLarge)
        );
        assert_eq!(
            ComparisonRequest::from_json(b"garbage", 0),
            Err(ReviewRequestError::TooLarge)
        );
        // Escaped JSON text is valid when its decoded UUID is canonical.
        let escaped = valid.replacen('0', "\\u0030", 1);
        assert!(ComparisonRequest::from_json(escaped.as_bytes(), 4096).is_ok());
    }
    #[test]
    fn nullable_baseline_is_required() {
        let valid = review();
        let parsed = ReviewRequest::from_json(valid.as_bytes(), valid.len()).unwrap();
        assert!(parsed.expected_baseline_id().is_none());
        let with_id = valid.replace("null", &format!("\"{ID}\""));
        assert_eq!(
            ReviewRequest::from_json(with_id.as_bytes(), 4096)
                .unwrap()
                .expected_baseline_id()
                .unwrap()
                .as_str(),
            ID
        );
        for invalid in [
            valid.replace(",\"expected_baseline_id\":null", ""),
            valid.replace("null", "false"),
            valid.replace("}", ",\"expected_baseline_id\":null}"),
            valid.replace("}", ",\"extra\":null}"),
            valid.replace("\"comparison_id\"", "\"comparison\""),
        ] {
            assert!(ReviewRequest::from_json(invalid.as_bytes(), 4096).is_err());
        }
        assert_eq!(
            ReviewRequest::from_json(valid.as_bytes(), valid.len() - 1),
            Err(ReviewRequestError::TooLarge)
        );
        assert_eq!(
            ReviewRequest::from_json(&parsed.to_json().unwrap(), 4096).unwrap(),
            parsed
        );
    }
    #[test]
    fn exact_positive_revision_and_closed_decision() {
        for token in [
            "1",
            "1.0",
            "10e-1",
            "18446744073709551615",
            "184467440737095516150e-1",
        ] {
            let body = format!(r#"{{"decision":"approve","expected_revision":{token}}}"#);
            let parsed = ReviewDecision::from_json(body.as_bytes(), body.len()).unwrap();
            assert!(parsed.expected_revision() > 0);
            assert_eq!(
                ReviewDecision::from_json(&parsed.to_json().unwrap(), 4096).unwrap(),
                parsed
            );
            assert_eq!(
                ReviewDecision::from_json(body.as_bytes(), body.len() - 1),
                Err(ReviewRequestError::TooLarge)
            );
        }
        for token in [
            "0",
            "-0",
            "-1",
            "1.5",
            "1e-1",
            "18446744073709551616",
            "1e999",
            "null",
            "true",
            "\"1\"",
        ] {
            let body = format!(r#"{{"decision":"reject","expected_revision":{token}}}"#);
            assert!(ReviewDecision::from_json(body.as_bytes(), 4096).is_err());
        }
        for body in [
            r#"{"decision":"approve"}"#,
            r#"{"expected_revision":1}"#,
            r#"{"decision":"approved","expected_revision":1}"#,
            r#"{"decision":"approve","expected_revision":1,"expected_revision":2}"#,
            r#"{"decision":"approve","expected_revision":1,"extra":null}"#,
        ] {
            assert!(ReviewDecision::from_json(body.as_bytes(), 4096).is_err());
        }
        assert_eq!(
            ReviewDecision::new(ReviewDecisionKind::Reject, 0),
            Err(ReviewRequestError::InvalidRevision)
        );
        let long = format!(
            r#"{{"decision":"approve","expected_revision":1.{}}}"#,
            "0".repeat(255)
        );
        assert!(ReviewDecision::from_json(long.as_bytes(), 4096).is_err());
    }
}
