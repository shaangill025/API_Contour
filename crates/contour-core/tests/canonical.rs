use contour_core::{Error, Kind, Shape, UnknownReason};

fn primitive(kind: Kind) -> Shape {
    Shape::primitive(kind).unwrap()
}
fn bytes(shape: &Shape) -> String {
    String::from_utf8(shape.canonical_bytes().unwrap()).unwrap()
}

#[test]
fn controls_use_lowercase_unicode_escapes() {
    for control in 0u8..32 {
        let shape = Shape::object(
            vec![(char::from(control).to_string(), primitive(Kind::Null))],
            None,
        )
        .unwrap();
        assert_eq!(
            bytes(&shape),
            format!(r#"["object",[["\u00{control:02x}",["null"]]],null]"#)
        );
    }
}

#[test]
fn golden_vectors_and_distinctions() {
    for (kind, name) in [
        (Kind::Null, "null"),
        (Kind::Boolean, "boolean"),
        (Kind::Integer, "integer"),
        (Kind::Number, "number"),
        (Kind::String, "string"),
        (Kind::Binary, "binary"),
    ] {
        assert_eq!(bytes(&primitive(kind)), format!(r#"["{name}"]"#));
    }
    assert_eq!(
        bytes(&Shape::object(vec![], None).unwrap()),
        r#"["object",[],null]"#
    );
    assert_eq!(
        bytes(&Shape::empty_array().unwrap()),
        r#"["array",["unknown","empty"]]"#
    );
    assert_eq!(
        bytes(&Shape::object(vec![], Some(primitive(Kind::Boolean))).unwrap()),
        r#"["object",[],["boolean"]]"#
    );
    let fields = vec![
        ("z".into(), primitive(Kind::String)),
        ("a".into(), primitive(Kind::Integer)),
    ];
    assert_eq!(
        bytes(&Shape::object(fields, None).unwrap()),
        r#"["object",[["a",["integer"]],["z",["string"]]],null]"#
    );
    let fields = vec![
        ("é".into(), primitive(Kind::String)),
        ("a".into(), primitive(Kind::Boolean)),
    ];
    assert_eq!(
        bytes(&Shape::object(fields, None).unwrap()),
        r#"["object",[["a",["boolean"]],["é",["string"]]],null]"#
    );
    assert_eq!(
        bytes(&Shape::unknown(UnknownReason::Limit)),
        r#"["unknown","limit"]"#
    );
    let absent = Shape::object(vec![], None).unwrap();
    let null = Shape::object(vec![("x".into(), primitive(Kind::Null))], None).unwrap();
    assert_ne!(absent, null);
    assert_ne!(absent, Shape::unknown(UnknownReason::Empty));
    assert_ne!(primitive(Kind::Integer), primitive(Kind::Number));
    for kind in [Kind::Object, Kind::Array, Kind::Union, Kind::Unknown] {
        assert_eq!(Shape::primitive(kind), Err(Error::NonPrimitiveKind));
    }
    for (reason, name) in [
        (UnknownReason::Empty, "empty"),
        (UnknownReason::Unsupported, "unsupported"),
        (UnknownReason::Malformed, "malformed"),
        (UnknownReason::Encrypted, "encrypted"),
    ] {
        assert_eq!(
            bytes(&Shape::unknown(reason)),
            format!(r#"["unknown","{name}"]"#)
        );
    }
}

#[test]
fn names_preserve_unicode_and_escape_quotes() {
    let shape = Shape::object(vec![("\"\\é😀".into(), primitive(Kind::Null))], None).unwrap();
    assert_eq!(bytes(&shape), r#"["object",[["\"\\é😀",["null"]]],null]"#);
    let fields = vec![
        ("é".into(), primitive(Kind::Null)),
        ("e\u{301}".into(), primitive(Kind::Null)),
    ];
    assert_eq!(Shape::object(fields, None).unwrap().kind(), Kind::Object);
    assert!(Shape::object(vec![("😀".repeat(64), primitive(Kind::Null))], None).is_ok());
    assert_eq!(
        Shape::object(vec![("😀".repeat(65), primitive(Kind::Null))], None),
        Err(Error::NameTooLong)
    );
    assert_eq!(
        Shape::object(
            vec![
                ("x".into(), primitive(Kind::Null)),
                ("x".into(), primitive(Kind::String))
            ],
            None
        ),
        Err(Error::DuplicateField)
    );
}

#[test]
fn union_flattens_deduplicates_sorts_and_collapses() {
    let null = primitive(Kind::Null);
    let string = primitive(Kind::String);
    let nested = Shape::union(vec![string.clone(), null.clone()]).unwrap();
    let normalized = Shape::union(vec![nested.clone(), null.clone(), string.clone()]).unwrap();
    assert_eq!(nested, normalized);
    assert_eq!(bytes(&normalized), r#"["union",[["null"],["string"]]]"#);
    assert_eq!(Shape::union(vec![null.clone(); 64]).unwrap(), null);
    assert_eq!(
        Shape::union(vec![null; 65]),
        Err(Error::TooManyAlternatives)
    );
    assert_eq!(Shape::union(vec![]), Err(Error::EmptyUnion));
    let alternatives = (0..64)
        .map(|i| Shape::object(vec![(i.to_string(), primitive(Kind::Null))], None).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        Shape::union(alternatives.clone()).unwrap().kind(),
        Kind::Union
    );
    let flattened = Shape::union(alternatives.clone()).unwrap();
    assert_eq!(
        Shape::union(vec![flattened.clone(), alternatives[0].clone()]).unwrap(),
        flattened
    );
    assert_eq!(
        Shape::union(vec![flattened, Shape::empty_array().unwrap()]),
        Err(Error::TooManyAlternatives)
    );
    let mut excess = alternatives;
    excess.push(Shape::empty_array().unwrap());
    assert_eq!(Shape::union(excess), Err(Error::TooManyAlternatives));
    assert_eq!(
        Shape::union(vec![primitive(Kind::Number), primitive(Kind::Integer)])
            .unwrap()
            .kind(),
        Kind::Union
    );
}

#[test]
fn object_rejects_empty_names() {
    assert_eq!(
        Shape::object(vec![(String::new(), primitive(Kind::Null))], None),
        Err(Error::EmptyName)
    );
    assert_eq!(
        Shape::object(vec![("😀".repeat(1_000_000), primitive(Kind::Null))], None),
        Err(Error::NameTooLong)
    );
}

#[test]
fn field_and_depth_boundaries_include_additional_nodes() {
    let fields = (0..256)
        .map(|i| (i.to_string(), primitive(Kind::Null)))
        .collect::<Vec<_>>();
    assert!(Shape::object(fields.clone(), None).is_ok());
    let mut excess = fields;
    excess.push(("extra".into(), primitive(Kind::Null)));
    assert_eq!(Shape::object(excess, None), Err(Error::TooManyFields));
    let mut shape = primitive(Kind::Null);
    for _ in 1..32 {
        shape = Shape::array(shape).unwrap();
    }
    assert_eq!(shape.depth(), 32);
    assert_eq!(Shape::array(shape.clone()), Err(Error::TooDeep));
    assert_eq!(
        Shape::object(vec![], Some(shape.clone())),
        Err(Error::TooDeep)
    );
    assert_eq!(
        Shape::object(vec![("x".into(), shape.clone())], None),
        Err(Error::TooDeep)
    );
    assert_eq!(
        Shape::union(vec![shape.clone(), primitive(Kind::Null)]),
        Err(Error::TooDeep)
    );
    assert_eq!(
        Shape::union(vec![shape.clone(), shape.clone()]).unwrap(),
        shape
    );
}

// Tune UTF-8 name widths without exceeding 64 scalars or 256 fields.
fn sized_fields(target: usize) -> Vec<(String, Shape)> {
    let base = (0..256)
        .map(|i| (format!("{i:03}{}", "a".repeat(61)), primitive(Kind::Null)))
        .collect::<Vec<_>>();
    let base_size = Shape::object(base, None)
        .unwrap()
        .canonical_bytes()
        .unwrap()
        .len();
    let mut extra = target - base_size;
    let fields = (0..256)
        .map(|i| {
            let mut name = format!("{i:03}");
            for _ in 0..61 {
                let growth = extra.min(3);
                name.push(match growth {
                    3 => '😀',
                    2 => '€',
                    1 => 'é',
                    _ => 'a',
                });
                extra -= growth;
            }
            (name, primitive(Kind::Null))
        })
        .collect();
    assert_eq!(extra, 0);
    fields
}

#[test]
fn exact_canonical_size_and_aggregate_union_bounds() {
    let exact = Shape::object(sized_fields(65_536), None).unwrap();
    assert_eq!(exact.canonical_bytes().unwrap().len(), 65_536);
    assert_eq!(
        Shape::object(sized_fields(65_537), None),
        Err(Error::CanonicalTooLarge)
    );
    assert_eq!(Shape::array(exact.clone()), Err(Error::CanonicalTooLarge));
    assert_eq!(Shape::union(vec![exact.clone(); 64]).unwrap(), exact);
    let large = Shape::object(sized_fields(40_000), None).unwrap();
    let other = Shape::object(sized_fields(40_001), None).unwrap();
    assert_eq!(
        Shape::union(vec![large, other]),
        Err(Error::CanonicalTooLarge)
    );
}
