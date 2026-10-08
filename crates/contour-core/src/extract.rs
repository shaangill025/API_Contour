use crate::{
    Error, Kind, MAX_CANONICAL_BYTES, MAX_DEPTH, MAX_FIELDS, MAX_NAME_SCALARS, Shape, UnknownReason,
};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::{
    collections::HashSet,
    fmt,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default)]
pub struct ExtractionPolicy {
    fields: Vec<(String, Self)>,
    additional: Option<Box<Self>>,
    items: Option<Box<Self>>,
    denied: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completeness {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationReason {
    Limit,
    Permission,
    Malformed,
}

#[derive(Debug)]
pub struct Observation {
    pub shape: Shape,
    pub completeness: Completeness,
    pub reasons: Vec<ObservationReason>,
}

impl ExtractionPolicy {
    /// Static names must be independently approved by the caller's capture policy.
    pub fn object(fields: Vec<(String, Self)>, additional: Option<Self>) -> Result<Self, Error> {
        if fields.len() > MAX_FIELDS {
            return Err(Error::TooManyFields);
        }
        for (name, _) in &fields {
            if name.is_empty() {
                return Err(Error::EmptyName);
            }
            if name.chars().take(MAX_NAME_SCALARS + 1).count() > MAX_NAME_SCALARS {
                return Err(Error::NameTooLong);
            }
        }
        let placeholder = Shape::primitive(Kind::Null)?;
        Shape::object(
            fields
                .iter()
                .map(|(name, _)| (name.clone(), placeholder.clone()))
                .collect(),
            None,
        )?;
        Ok(Self {
            fields,
            additional: additional.map(Box::new),
            items: None,
            denied: false,
        })
    }
    pub fn array(items: Self) -> Self {
        Self {
            items: Some(Box::new(items)),
            ..Self::default()
        }
    }
    /// Explicit denial takes precedence over dynamic additional-value inspection.
    pub fn deny() -> Self {
        Self {
            denied: true,
            ..Self::default()
        }
    }
}

/// Local extraction only: authorization, persistence and transport are caller concerns.
pub fn extract_json(bytes: &[u8], policy: &ExtractionPolicy) -> Observation {
    let start = Instant::now();
    run(bytes, policy, &mut || start.elapsed())
}

#[derive(Clone, Copy)]
enum Failure {
    Limit,
    Malformed,
}
struct Context<'a> {
    elapsed: &'a mut dyn FnMut() -> Duration,
    failure: Option<Failure>,
    permission: bool,
}
impl Context<'_> {
    fn checkpoint(&mut self) -> Result<(), Failure> {
        if (self.elapsed)() >= Duration::from_millis(2) {
            Err(Failure::Limit)
        } else {
            Ok(())
        }
    }
    fn fail<E: de::Error>(&mut self, failure: Failure) -> E {
        self.failure = Some(failure);
        E::custom("inspection stopped")
    }
}

fn run(
    bytes: &[u8],
    policy: &ExtractionPolicy,
    elapsed: &mut dyn FnMut() -> Duration,
) -> Observation {
    let mut context = Context {
        elapsed,
        failure: None,
        permission: false,
    };
    let result = (|| {
        preflight(bytes, &mut context)?;
        let raw: &RawValue = serde_json::from_slice(bytes).map_err(|_| Failure::Malformed)?;
        let shape = inspect(raw, policy, 1, &mut context)?;
        shape.to_wire_json().map_err(|_| Failure::Limit)?;
        context.checkpoint()?;
        Ok(shape)
    })();
    match result {
        Ok(shape) => Observation {
            shape,
            completeness: if context.permission {
                Completeness::Partial
            } else {
                Completeness::Complete
            },
            reasons: if context.permission {
                vec![ObservationReason::Permission]
            } else {
                vec![]
            },
        },
        Err(Failure::Limit) => Observation {
            shape: Shape::unknown(UnknownReason::Limit),
            completeness: Completeness::Partial,
            reasons: vec![ObservationReason::Limit],
        },
        Err(Failure::Malformed) => Observation {
            shape: Shape::unknown(UnknownReason::Malformed),
            completeness: Completeness::Unavailable,
            reasons: vec![ObservationReason::Malformed],
        },
    }
}

// Scan bytes without copying values; strings shield their brackets and number-like text.
fn preflight(bytes: &[u8], context: &mut Context<'_>) -> Result<(), Failure> {
    if bytes.len() > MAX_CANONICAL_BYTES {
        return Err(Failure::Limit);
    }
    let (mut quoted, mut escaped, mut depth, mut index) = (false, false, 0usize, 0usize);
    while index < bytes.len() {
        if index % 64 == 0 {
            context.checkpoint()?;
        }
        let byte = bytes[index];
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(Failure::Limit);
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                b'-' | b'0'..=b'9' => {
                    let start = index;
                    while index < bytes.len()
                        && matches!(bytes[index], b'0'..=b'9' | b'e' | b'E' | b'+' | b'-' | b'.')
                    {
                        if index - start == 256 {
                            return Err(Failure::Limit);
                        }
                        index += 1;
                    }
                    continue;
                }
                _ => {}
            }
        }
        index += 1;
    }
    context.checkpoint()
}

fn inspect(
    raw: &RawValue,
    policy: &ExtractionPolicy,
    depth: usize,
    context: &mut Context<'_>,
) -> Result<Shape, Failure> {
    context.checkpoint()?;
    if depth > MAX_DEPTH {
        return Err(Failure::Limit);
    }
    if policy.denied {
        context.permission = true;
        return Ok(Shape::unknown(UnknownReason::Unsupported));
    }
    let text = raw.get();
    let shape = match text.as_bytes()[0] {
        b'{' => {
            let mut decoder = serde_json::Deserializer::from_str(text);
            let children = de::Deserializer::deserialize_map(&mut decoder, RawObject(context))
                .map_err(|_| context.failure.take().unwrap_or(Failure::Malformed))?;
            let (mut fields, mut additional) = (Vec::new(), Vec::new());
            for (name, child) in children {
                context.checkpoint()?;
                if let Some((approved, child_policy)) =
                    policy.fields.iter().find(|(approved, _)| approved == &name)
                {
                    if child_policy.denied {
                        context.permission = true;
                        continue;
                    }
                    fields.push((
                        approved.clone(),
                        inspect(child, child_policy, depth + 1, context)?,
                    ));
                } else if let Some(child_policy) =
                    policy.additional.as_deref().filter(|policy| !policy.denied)
                {
                    let shape = inspect(child, child_policy, depth + 1, context)?;
                    if !additional.contains(&shape) {
                        if additional.len() == crate::MAX_ALTERNATIVES {
                            return Err(Failure::Limit);
                        }
                        additional.push(shape);
                    }
                } else {
                    context.permission = true;
                }
            }
            let additional = if additional.is_empty() {
                None
            } else {
                Some(Shape::union(additional).map_err(|_| Failure::Limit)?)
            };
            Shape::object(fields, additional)
        }
        b'[' => {
            let mut decoder = serde_json::Deserializer::from_str(text);
            let children = de::Deserializer::deserialize_seq(&mut decoder, RawArray(context))
                .map_err(|_| context.failure.take().unwrap_or(Failure::Malformed))?;
            if children.is_empty() {
                Shape::empty_array()
            } else if let Some(items) = policy.items.as_deref().filter(|policy| !policy.denied) {
                let mut shapes = Vec::new();
                for child in children {
                    shapes.push(inspect(child, items, depth + 1, context)?);
                }
                Shape::array(Shape::union(shapes).map_err(|_| Failure::Limit)?)
            } else {
                context.permission = true;
                Shape::array(Shape::unknown(UnknownReason::Unsupported))
            }
        }
        b'"' => {
            // Validate escaped Unicode too; the decoded value never enters a Shape.
            serde_json::from_str::<String>(text).map_err(|_| Failure::Malformed)?;
            Shape::primitive(Kind::String)
        }
        b'n' => Shape::primitive(Kind::Null),
        b't' | b'f' => Shape::primitive(Kind::Boolean),
        _ => Shape::primitive(if integer_token(text) {
            Kind::Integer
        } else {
            Kind::Number
        }),
    }
    .map_err(|_| Failure::Limit)?;
    context.checkpoint()?;
    Ok(shape)
}

// Grammar was validated by serde's RawValue scanner; no float or big integer conversion.
fn integer_token(text: &str) -> bool {
    let (coefficient, exponent) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
    let negative = exponent.starts_with('-');
    let magnitude = exponent
        .trim_start_matches(['+', '-'])
        .bytes()
        .fold(0i32, |n, digit| {
            (n * 10 + i32::from(digit - b'0')).min(1024)
        });
    let exponent = if negative { -magnitude } else { magnitude };
    let fraction = coefficient
        .split_once('.')
        .map_or(0, |(_, digits)| digits.len() as i32);
    let digits = coefficient
        .bytes()
        .filter(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    if digits.iter().all(|digit| *digit == b'0') {
        return true;
    }
    let trailing = digits
        .iter()
        .rev()
        .take_while(|digit| **digit == b'0')
        .count() as i32;
    exponent + trailing >= fraction
}

struct RawObject<'a, 'b>(&'a mut Context<'b>);
impl<'de> Visitor<'de> for RawObject<'_, '_> {
    type Value = Vec<(String, &'de RawValue)>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("object")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut children = Vec::new();
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if self.0.checkpoint().is_err() || children.len() == MAX_FIELDS {
                return Err(self.0.fail(Failure::Limit));
            }
            if !names.insert(name.clone()) {
                return Err(self.0.fail(Failure::Malformed));
            }
            children.push((name, map.next_value::<&RawValue>()?));
        }
        Ok(children)
    }
}

struct RawArray<'a, 'b>(&'a mut Context<'b>);
impl<'de> Visitor<'de> for RawArray<'_, '_> {
    type Value = Vec<&'de RawValue>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("array")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Self::Value, S::Error> {
        let mut children = Vec::new();
        while let Some(child) = sequence.next_element::<&RawValue>()? {
            if self.0.checkpoint().is_err() || children.len() == 64 {
                return Err(self.0.fail(Failure::Limit));
            }
            children.push(child);
        }
        Ok(children)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_clock_exhaustion_is_partial() {
        let mut calls = 0;
        let observation = run(
            b"[1,2]",
            &ExtractionPolicy::array(ExtractionPolicy::default()),
            &mut || {
                calls += 1;
                if calls >= 5 {
                    Duration::from_millis(2)
                } else {
                    Duration::ZERO
                }
            },
        );
        assert_eq!(observation.completeness, Completeness::Partial);
        assert_eq!(observation.reasons, vec![ObservationReason::Limit]);
        assert_eq!(observation.shape, Shape::unknown(UnknownReason::Limit));
    }

    #[test]
    fn elapsed_cutoff_is_exactly_two_milliseconds() {
        let policy = ExtractionPolicy::default();
        let before = run(b"0", &policy, &mut || Duration::from_nanos(1_999_999));
        assert_eq!(before.completeness, Completeness::Complete);
        assert_eq!(before.shape.kind(), Kind::Integer);
        assert!(before.reasons.is_empty());
        for elapsed in [Duration::from_millis(2), Duration::from_nanos(2_000_001)] {
            let stopped = run(b"0", &policy, &mut || elapsed);
            assert_eq!(stopped.completeness, Completeness::Partial);
            assert_eq!(stopped.reasons, vec![ObservationReason::Limit]);
            assert_eq!(stopped.shape, Shape::unknown(UnknownReason::Limit));
        }
    }

    #[test]
    fn expiry_at_final_checkpoint_discards_the_completed_structure() {
        let mut checkpoints = 0;
        let observation = run(b"0", &ExtractionPolicy::default(), &mut || {
            checkpoints += 1;
            if checkpoints >= 5 {
                Duration::from_millis(2)
            } else {
                Duration::from_nanos(1_999_999)
            }
        });
        assert_eq!(checkpoints, 5);
        assert_eq!(observation.completeness, Completeness::Partial);
        assert_eq!(observation.reasons, vec![ObservationReason::Limit]);
        assert_eq!(observation.shape, Shape::unknown(UnknownReason::Limit));
    }

    fn deterministic(bytes: &[u8], policy: &ExtractionPolicy) -> Observation {
        run(bytes, policy, &mut || Duration::ZERO)
    }

    #[test]
    fn exact_inspection_boundaries() {
        let policy = ExtractionPolicy::object(vec![], Some(ExtractionPolicy::default())).unwrap();
        for count in [256, 257] {
            let fields = (0..count)
                .map(|i| format!("\"{i}\":0"))
                .collect::<Vec<_>>()
                .join(",");
            let observation = deterministic(format!("{{{fields}}}").as_bytes(), &policy);
            assert_eq!(
                observation.completeness,
                if count == 256 {
                    Completeness::Complete
                } else {
                    Completeness::Partial
                }
            );
        }
        // The cap includes denied keys, and skipped contents never establish completeness.
        let denied = format!(
            "{{{}}}",
            (0..257)
                .map(|i| format!("\"{i}\":0"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            deterministic(denied.as_bytes(), &ExtractionPolicy::default()).reasons,
            vec![ObservationReason::Limit]
        );
        let array = ExtractionPolicy::array(ExtractionPolicy::default());
        for count in [64, 65] {
            let input = format!("[{}]", vec!["0"; count].join(","));
            assert_eq!(
                deterministic(input.as_bytes(), &array).completeness,
                if count == 64 {
                    Completeness::Complete
                } else {
                    Completeness::Partial
                }
            );
        }
        for length in [256, 257] {
            let input = format!("1{}", "0".repeat(length - 1));
            assert_eq!(
                deterministic(input.as_bytes(), &array).completeness,
                if length == 256 {
                    Completeness::Complete
                } else {
                    Completeness::Partial
                }
            );
        }
        let mut bytes = b"0".to_vec();
        bytes.resize(65_536, b' ');
        assert_eq!(
            deterministic(&bytes, &array).completeness,
            Completeness::Complete
        );
        bytes.push(b' ');
        assert_eq!(
            deterministic(&bytes, &array).reasons,
            vec![ObservationReason::Limit]
        );
        let mut policy = ExtractionPolicy::default();
        let mut input = "0".to_string();
        for _ in 1..32 {
            policy = ExtractionPolicy::array(policy);
            input = format!("[{input}]");
        }
        assert_eq!(deterministic(input.as_bytes(), &policy).shape.depth(), 32);
        input = format!("[{input}]");
        assert_eq!(
            deterministic(input.as_bytes(), &policy).reasons,
            vec![ObservationReason::Limit]
        );
    }

    #[test]
    fn structure_size_and_dynamic_union_bounds_are_partial() {
        let names = (0..99)
            .map(|i| format!("f{i:02}"))
            .chain((0..64).map(|i| format!("u{i:02}")))
            .collect::<Vec<_>>();
        let child = ExtractionPolicy::object(
            names
                .iter()
                .map(|name| (name.clone(), ExtractionPolicy::default()))
                .collect(),
            None,
        )
        .unwrap();
        let policy = ExtractionPolicy::object(vec![], Some(child)).unwrap();
        let values = (0..64)
            .map(|i| {
                let mut fields = names[..99]
                    .iter()
                    .map(|name| format!("\"{name}\":0"))
                    .collect::<Vec<_>>();
                fields.push(format!("\"u{i:02}\":0"));
                format!("\"SECRET_{i}\":{{{}}}", fields.join(","))
            })
            .collect::<Vec<_>>()
            .join(",");
        let input = format!("{{{values}}}");
        assert!(input.len() < MAX_CANONICAL_BYTES);
        assert_eq!(
            deterministic(input.as_bytes(), &policy).reasons,
            vec![ObservationReason::Limit]
        );
        let child = ExtractionPolicy::object(
            (0..65)
                .map(|i| (i.to_string(), ExtractionPolicy::default()))
                .collect(),
            None,
        )
        .unwrap();
        let policy = ExtractionPolicy::object(vec![], Some(child)).unwrap();
        let input = format!(
            "{{{}}}",
            (0..65)
                .map(|i| format!("\"SECRET_{i}\":{{\"{i}\":0}}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            deterministic(input.as_bytes(), &policy).reasons,
            vec![ObservationReason::Limit]
        );
    }

    #[test]
    fn wire_output_expansion_is_partial() {
        let names = (0..256)
            .map(|i| format!("{i:03}{}aaa", "😀".repeat(58)))
            .collect::<Vec<_>>();
        let policy = ExtractionPolicy::object(
            names
                .iter()
                .map(|name| (name.clone(), ExtractionPolicy::default()))
                .collect(),
            None,
        )
        .unwrap();
        let input = format!(
            "{{{}}}",
            names
                .iter()
                .map(|name| format!("{}:null", serde_json::to_string(name).unwrap()))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(input.len() < MAX_CANONICAL_BYTES);
        assert_eq!(
            deterministic(input.as_bytes(), &policy).reasons,
            vec![ObservationReason::Limit]
        );
    }
    #[test]
    fn decimal_tokens_are_classified_exactly() {
        for input in [
            "1",
            "1.0",
            "1e3",
            "-0.000",
            "123456789012345678901234567890",
            "1e999999999999999999999",
        ] {
            let observation = deterministic(input.as_bytes(), &ExtractionPolicy::default());
            assert_eq!(observation.completeness, Completeness::Complete);
            assert_eq!(observation.shape.kind(), Kind::Integer, "{input}");
        }
        for input in ["1.0000000000000001", "1e-999999999999999999999", "12.01"] {
            assert_eq!(
                deterministic(input.as_bytes(), &ExtractionPolicy::default())
                    .shape
                    .kind(),
                Kind::Number
            );
        }
    }

    #[test]
    fn observed_secrets_never_enter_output_or_debug() {
        let policy = ExtractionPolicy::object(
            vec![("safe".into(), ExtractionPolicy::default())],
            Some(ExtractionPolicy::default()),
        )
        .unwrap();
        let observation = deterministic(br#"{"safe":"VALUE_SECRET","DYNAMIC_SECRET":12}"#, &policy);
        assert_eq!(observation.completeness, Completeness::Complete);
        let sinks = [
            String::from_utf8(observation.shape.canonical_bytes().unwrap()).unwrap(),
            String::from_utf8(observation.shape.to_wire_json().unwrap()).unwrap(),
            format!("{observation:?}"),
        ];
        for sink in sinks {
            assert!(!sink.contains("VALUE_SECRET"));
            assert!(!sink.contains("DYNAMIC_SECRET"));
            assert!(sink.contains("safe"));
        }
    }

    #[test]
    fn default_denial_is_partial_and_never_exports_names() {
        let observation = deterministic(
            br#"{"SECRET_KEY":{"nested":1,"nested":2}}"#,
            &ExtractionPolicy::default(),
        );
        assert_eq!(observation.completeness, Completeness::Partial);
        assert_eq!(observation.reasons, vec![ObservationReason::Permission]);
        assert_eq!(observation.shape, Shape::object(vec![], None).unwrap());
        assert!(!format!("{observation:?}").contains("SECRET_KEY"));
        let array = deterministic(b"[1]", &ExtractionPolicy::default());
        assert_eq!(array.completeness, Completeness::Partial);
        assert_eq!(
            array.shape,
            Shape::array(Shape::unknown(UnknownReason::Unsupported)).unwrap()
        );
        for input in [b"[]".as_slice(), b"{}"] {
            assert_eq!(
                deterministic(input, &ExtractionPolicy::default()).completeness,
                Completeness::Complete
            );
        }
    }

    #[test]
    fn decoded_duplicates_and_malformed_inputs_invalidate_the_observation() {
        let child = ExtractionPolicy::object(vec![("x".into(), ExtractionPolicy::default())], None)
            .unwrap();
        let policy = ExtractionPolicy::object(vec![("safe".into(), child)], None).unwrap();
        for input in [
            r#"{"DENIED_SECRET":1,"DENIED_SECRET":2}"#,
            r#"{"x":1,"\u0078":2}"#,
            r#"{"safe":{"x":1,"x":2}}"#,
            r#"{"safe":NaN}"#,
            r#"{"safe":1,}"#,
            "1 2",
            "01",
            "1e",
            r#""\ud800""#,
        ] {
            let observation = deterministic(input.as_bytes(), &policy);
            assert_eq!(
                observation.completeness,
                Completeness::Unavailable,
                "{input}"
            );
            assert_eq!(observation.reasons, vec![ObservationReason::Malformed]);
            assert_eq!(observation.shape, Shape::unknown(UnknownReason::Malformed));
            assert!(!format!("{observation:?}").contains("DENIED_SECRET"));
        }
        assert_eq!(
            deterministic(&[0xff], &policy).completeness,
            Completeness::Unavailable
        );
    }

    #[test]
    fn child_array_and_dynamic_policies_preserve_only_structures() {
        let child = ExtractionPolicy::object(vec![("x".into(), ExtractionPolicy::default())], None)
            .unwrap();
        let policy =
            ExtractionPolicy::object(vec![("items".into(), ExtractionPolicy::array(child))], None)
                .unwrap();
        let observation = deterministic(br#"{"items":[{"x":null},{"x":"SECRET"}]}"#, &policy);
        assert_eq!(observation.completeness, Completeness::Complete);
        assert_eq!(
            String::from_utf8(observation.shape.canonical_bytes().unwrap()).unwrap(),
            r#"["object",[["items",["array",["union",[["object",[["x",["null"]]],null],["object",[["x",["string"]]],null]]]]]],null]"#
        );
        let policy = ExtractionPolicy::object(vec![], Some(ExtractionPolicy::default())).unwrap();
        let observation = deterministic(
            br#"{"SECRET_ONE":true,"SECRET_TWO":"VALUE_SECRET"}"#,
            &policy,
        );
        assert_eq!(observation.completeness, Completeness::Complete);
        assert_eq!(
            String::from_utf8(observation.shape.canonical_bytes().unwrap()).unwrap(),
            r#"["object",[],["union",[["boolean"],["string"]]]]"#
        );
    }

    #[test]
    fn policy_names_are_checked_without_echoing_them() {
        for (name, error) in [
            (String::new(), Error::EmptyName),
            ("😀".repeat(65), Error::NameTooLong),
        ] {
            assert_eq!(
                ExtractionPolicy::object(vec![(name, ExtractionPolicy::default())], None)
                    .unwrap_err(),
                error
            );
        }
        assert_eq!(
            ExtractionPolicy::object(
                vec![
                    ("SAFE".into(), ExtractionPolicy::default()),
                    ("SAFE".into(), ExtractionPolicy::default())
                ],
                None
            )
            .unwrap_err(),
            Error::DuplicateField
        );
    }

    #[test]
    fn policy_input_limits_are_checked_before_copying_names() {
        let excess = (0..257)
            .map(|i| (i.to_string(), ExtractionPolicy::default()))
            .collect();
        assert_eq!(
            ExtractionPolicy::object(excess, None).unwrap_err(),
            Error::TooManyFields
        );
        let oversized = "😀".repeat(1_000_000);
        assert_eq!(
            ExtractionPolicy::object(vec![(oversized, ExtractionPolicy::default())], None)
                .unwrap_err(),
            Error::NameTooLong
        );
    }

    #[test]
    fn explicit_denied_paths_override_dynamic_inspection() {
        let policy = ExtractionPolicy::object(
            vec![("DENIED_PATH".into(), ExtractionPolicy::deny())],
            Some(ExtractionPolicy::default()),
        )
        .unwrap();
        let observation = deterministic(
            br#"{"DENIED_PATH":{"x":1,"x":2},"DYNAMIC_SECRET":true}"#,
            &policy,
        );
        assert_eq!(observation.completeness, Completeness::Partial);
        assert_eq!(observation.reasons, vec![ObservationReason::Permission]);
        assert_eq!(
            String::from_utf8(observation.shape.canonical_bytes().unwrap()).unwrap(),
            r#"["object",[],["boolean"]]"#
        );
        let observation = deterministic(b"[1]", &ExtractionPolicy::array(ExtractionPolicy::deny()));
        assert_eq!(observation.completeness, Completeness::Partial);
        let observation = deterministic(b"0", &ExtractionPolicy::deny());
        assert_eq!(
            observation.shape,
            Shape::unknown(UnknownReason::Unsupported)
        );
        assert_eq!(observation.completeness, Completeness::Partial);
    }
}
