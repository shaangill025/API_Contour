use contour_core::{
    Completeness, Error, ExtractionPolicy, Kind, ObservationReason, Shape, UnknownReason,
    extract_json,
};

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
        let observation = extract_json(input.as_bytes(), &ExtractionPolicy::default());
        assert_eq!(observation.completeness, Completeness::Complete);
        assert_eq!(observation.shape.kind(), Kind::Integer, "{input}");
    }
    for input in ["1.0000000000000001", "1e-999999999999999999999", "12.01"] {
        assert_eq!(
            extract_json(input.as_bytes(), &ExtractionPolicy::default())
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
    let observation = extract_json(br#"{"safe":"VALUE_SECRET","DYNAMIC_SECRET":12}"#, &policy);
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
    let observation = extract_json(
        br#"{"SECRET_KEY":{"nested":1,"nested":2}}"#,
        &ExtractionPolicy::default(),
    );
    assert_eq!(observation.completeness, Completeness::Partial);
    assert_eq!(observation.reasons, vec![ObservationReason::Permission]);
    assert_eq!(observation.shape, Shape::object(vec![], None).unwrap());
    assert!(!format!("{observation:?}").contains("SECRET_KEY"));
    let array = extract_json(b"[1]", &ExtractionPolicy::default());
    assert_eq!(array.completeness, Completeness::Partial);
    assert_eq!(
        array.shape,
        Shape::array(Shape::unknown(UnknownReason::Unsupported)).unwrap()
    );
    for input in [b"[]".as_slice(), b"{}"] {
        assert_eq!(
            extract_json(input, &ExtractionPolicy::default()).completeness,
            Completeness::Complete
        );
    }
}

#[test]
fn decoded_duplicates_and_malformed_inputs_invalidate_the_observation() {
    let child =
        ExtractionPolicy::object(vec![("x".into(), ExtractionPolicy::default())], None).unwrap();
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
        let observation = extract_json(input.as_bytes(), &policy);
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
        extract_json(&[0xff], &policy).completeness,
        Completeness::Unavailable
    );
}

#[test]
fn child_array_and_dynamic_policies_preserve_only_structures() {
    let child =
        ExtractionPolicy::object(vec![("x".into(), ExtractionPolicy::default())], None).unwrap();
    let policy =
        ExtractionPolicy::object(vec![("items".into(), ExtractionPolicy::array(child))], None)
            .unwrap();
    let observation = extract_json(br#"{"items":[{"x":null},{"x":"SECRET"}]}"#, &policy);
    assert_eq!(observation.completeness, Completeness::Complete);
    assert_eq!(
        String::from_utf8(observation.shape.canonical_bytes().unwrap()).unwrap(),
        r#"["object",[["items",["array",["union",[["object",[["x",["null"]]],null],["object",[["x",["string"]]],null]]]]]],null]"#
    );
    let policy = ExtractionPolicy::object(vec![], Some(ExtractionPolicy::default())).unwrap();
    let observation = extract_json(
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
            ExtractionPolicy::object(vec![(name, ExtractionPolicy::default())], None).unwrap_err(),
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
        ExtractionPolicy::object(vec![(oversized, ExtractionPolicy::default())], None).unwrap_err(),
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
    let observation = extract_json(
        br#"{"DENIED_PATH":{"x":1,"x":2},"DYNAMIC_SECRET":true}"#,
        &policy,
    );
    assert_eq!(observation.completeness, Completeness::Partial);
    assert_eq!(observation.reasons, vec![ObservationReason::Permission]);
    assert_eq!(
        String::from_utf8(observation.shape.canonical_bytes().unwrap()).unwrap(),
        r#"["object",[],["boolean"]]"#
    );
    let observation = extract_json(b"[1]", &ExtractionPolicy::array(ExtractionPolicy::deny()));
    assert_eq!(observation.completeness, Completeness::Partial);
    let observation = extract_json(b"0", &ExtractionPolicy::deny());
    assert_eq!(
        observation.shape,
        Shape::unknown(UnknownReason::Unsupported)
    );
    assert_eq!(observation.completeness, Completeness::Partial);
}
