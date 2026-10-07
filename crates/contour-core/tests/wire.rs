use contour_core::{Error, Kind, Shape};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    id: String,
    node: serde_json::Value,
    canonical: String,
}

#[test]
fn actual_golden_fixture_and_wire_round_trips() {
    let vectors: Vec<Vector> = serde_json::from_slice(include_bytes!(
        "../../../docs/specification/fixtures/canonical.json"
    ))
    .unwrap();
    for vector in vectors {
        let input = serde_json::to_vec(&vector.node).unwrap();
        let shape = Shape::from_wire_json(&input).unwrap();
        assert_eq!(
            shape.canonical_bytes().unwrap(),
            vector.canonical.as_bytes(),
            "{}",
            vector.id
        );
        assert_eq!(
            Shape::from_wire_json(&shape.to_wire_json().unwrap()).unwrap(),
            shape
        );
    }
}

#[test]
fn independent_domain_separated_fingerprint() {
    let shape = Shape::primitive(Kind::String).unwrap();
    assert_eq!(
        shape.fingerprint().unwrap(),
        "ec7e9370325498e73147c4a639f1f23c8f3c4b907aadd55bb4a41516e9e9b85d"
    );
}

#[test]
fn malformed_unknown_duplicate_and_value_fields_are_rejected_safely() {
    for input in [
        "",
        "null",
        "[]",
        "1",
        "true",
        "{}",
        r#"{"kind":"STRING"}"#,
        r#"{"kind":"string"} {}"#,
        r#"{"kind":"string","value":"secret-payload"}"#,
        r#"{"kind":"string","reason":"empty"}"#,
        r#"{"kind":"string","kind":"null"}"#,
        r#"{"kind":"string","\u006bind":"string"}"#,
        r#"{"kind":null}"#,
        r#"{"kind":"unknown"}"#,
        r#"{"kind":"unknown","reason":"other"}"#,
        r#"{"kind":"array","items":null}"#,
        r#"{"kind":"array"}"#,
        r#"{"kind":"object","fields":{},"additional":null,"extra":0}"#,
        r#"{"kind":"object","fields":{},"additional":false}"#,
        r#"{"kind":"object","fields":{},"additional":null,"fields":{}}"#,
        r#"{"kind":"object","fields":[] ,"additional":null}"#,
        r#"{"kind":"object","fields":{"x":{"kind":"null"},"\u0078":{"kind":"null"}},"additional":null}"#,
        r#"{"kind":"object","fields":{"":{"kind":"null"}},"additional":null}"#,
        r#"{"kind":"object","fields":{"\ud800":{"kind":"null"}},"additional":null}"#,
        r#"{"kind":"union","alternatives":[]}"#,
        r#"{"kind":"union","alternatives":[{"kind":"null"}]}"#,
        r#"{"kind":"union","alternatives":[{"kind":"null"},{"kind":"null"}]}"#,
        r#"{"kind":"union","alternatives":[{"kind":"union","alternatives":[{"kind":"null"},{"kind":"string"}]},{"kind":"number"}]}"#,
    ] {
        let error = Shape::from_wire_json(input.as_bytes()).unwrap_err();
        assert_eq!(error, Error::InvalidWireJson);
        assert_eq!(format!("{error:?}"), "InvalidWireJson");
        assert_eq!(error.to_string(), "InvalidWireJson");
    }
    assert_eq!(Shape::from_wire_json(&[0xff]), Err(Error::InvalidWireJson));
}

fn object_input(names: impl IntoIterator<Item = String>) -> Vec<u8> {
    let fields = names
        .into_iter()
        .map(|name| {
            format!(
                "{}:{{\"kind\":\"null\"}}",
                serde_json::to_string(&name).unwrap()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"kind\":\"object\",\"fields\":{{{fields}}},\"additional\":null}}").into_bytes()
}

#[test]
fn wire_names_fields_depth_and_alternative_limits() {
    assert!(Shape::from_wire_json(&object_input(["😀".repeat(64)])).is_ok());
    assert_eq!(
        Shape::from_wire_json(&object_input(["😀".repeat(65)])),
        Err(Error::InvalidWireJson)
    );
    assert!(Shape::from_wire_json(&object_input((0..256).map(|i| i.to_string()))).is_ok());
    assert_eq!(
        Shape::from_wire_json(&object_input((0..257).map(|i| i.to_string()))),
        Err(Error::InvalidWireJson)
    );
    let mut input = r#"{"kind":"null"}"#.to_string();
    for _ in 1..32 {
        input = format!(r#"{{"kind":"array","items":{input}}}"#);
    }
    assert_eq!(Shape::from_wire_json(input.as_bytes()).unwrap().depth(), 32);
    input = format!(r#"{{"kind":"array","items":{input}}}"#);
    assert_eq!(
        Shape::from_wire_json(input.as_bytes()),
        Err(Error::InvalidWireJson)
    );
    for count in [64, 65] {
        let alternatives = (0..count)
            .map(|i| String::from_utf8(object_input([i.to_string()])).unwrap())
            .collect::<Vec<_>>()
            .join(",");
        let input = format!(r#"{{"kind":"union","alternatives":[{alternatives}]}}"#);
        assert_eq!(Shape::from_wire_json(input.as_bytes()).is_ok(), count == 64);
    }
}

#[test]
fn byte_limits_apply_before_decode_and_before_output_growth() {
    let mut input = br#"{"kind":"null"}"#.to_vec();
    input.resize(65_536, b' ');
    assert!(Shape::from_wire_json(&input).is_ok());
    input.push(b' ');
    assert_eq!(Shape::from_wire_json(&input), Err(Error::WireTooLarge));
    // Short JSON newline escapes expand to six-byte canonical escapes.
    let input = object_input((0..256).map(|i| format!("{i:03}{}", "\n".repeat(61))));
    assert!(input.len() < 65_536);
    assert_eq!(Shape::from_wire_json(&input), Err(Error::InvalidWireJson));
    let fields = (0..256)
        .map(|i| {
            (
                format!("{i:03}{}aaa", "😀".repeat(58)),
                Shape::primitive(Kind::Null).unwrap(),
            )
        })
        .collect();
    let shape = Shape::object(fields, None).unwrap();
    assert_eq!(shape.to_wire_json(), Err(Error::WireTooLarge));
}

#[test]
fn normalization_is_order_independent_and_union_uniqueness_is_structural() {
    let first = r#"{"kind":"object","fields":{"z":{"kind":"null"},"a":{"kind":"string"}},"additional":null}"#;
    let second = r#"{"additional":null,"fields":{"a":{"kind":"string"},"z":{"kind":"null"}},"kind":"object"}"#;
    let a = Shape::from_wire_json(first.as_bytes()).unwrap();
    let b = Shape::from_wire_json(second.as_bytes()).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.fingerprint().unwrap(), b.fingerprint().unwrap());
    assert_eq!(
        String::from_utf8(a.to_wire_json().unwrap()).unwrap(),
        r#"{"kind":"object","fields":{"a":{"kind":"string"},"z":{"kind":"null"}},"additional":null}"#
    );
    let input = format!(r#"{{"kind":"union","alternatives":[{first},{second}]}}"#);
    assert_eq!(
        Shape::from_wire_json(input.as_bytes()),
        Err(Error::InvalidWireJson)
    );
}
