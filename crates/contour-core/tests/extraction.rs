use contour_core::{ExtractionPolicy, Shape, extract_json};

#[test]
fn public_real_clock_output_is_checked_bounded_and_value_free() {
    let policy = ExtractionPolicy::object(
        vec![("safe".into(), ExtractionPolicy::default())],
        Some(ExtractionPolicy::default()),
    )
    .unwrap();
    let observation = extract_json(br#"{"safe":"VALUE_SECRET","DYNAMIC_SECRET":12}"#, &policy);
    let wire = observation.shape.to_wire_json().unwrap();
    assert!(wire.len() <= contour_core::MAX_CANONICAL_BYTES);
    assert_eq!(Shape::from_wire_json(&wire).unwrap(), observation.shape);
    for sink in [
        String::from_utf8(observation.shape.canonical_bytes().unwrap()).unwrap(),
        String::from_utf8(wire).unwrap(),
        format!("{observation:?}"),
    ] {
        assert!(!sink.contains("VALUE_SECRET"));
        assert!(!sink.contains("DYNAMIC_SECRET"));
    }
}
