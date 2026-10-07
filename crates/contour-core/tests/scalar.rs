use contour_core::{ScalarError, Timestamp, UnsignedInteger};

#[test]
fn unsigned_numbers_are_exact_and_bounded() {
    for (token, expected) in [
        ("1.0", 1),
        ("1e0", 1),
        ("100e-2", 1),
        ("-0.0", 0),
        ("18446744073709551615", u64::MAX),
        ("1844674407370955161500e-2", u64::MAX),
    ] {
        assert_eq!(UnsignedInteger::parse(token).unwrap().get(), expected);
    }
}

#[test]
fn timestamp_preserves_text_and_compares_instants() {
    let text = "2026-10-06T12:00:00.123456789+01:00";
    let timestamp = Timestamp::parse(text).unwrap();
    assert_eq!(timestamp.as_str(), text);
    let utc = Timestamp::parse("2026-10-06T11:00:00.123456789Z").unwrap();
    assert_eq!(timestamp.instant(), utc.instant());
}

#[test]
fn unsigned_zero_fraction_exponent_and_overflow_cases() {
    for token in [
        "0",
        "-0",
        "0.000e999999999999999999999",
        "-0e-999999999999999999",
        "0e0",
    ] {
        assert_eq!(UnsignedInteger::parse(token).unwrap().get(), 0);
    }
    for (token, expected) in [
        ("0.01e2", 1),
        ("1e19", 10_000_000_000_000_000_000),
        ("18446744073709551615.000", u64::MAX),
        ("123.000e-0", 123),
    ] {
        assert_eq!(UnsignedInteger::parse(token).unwrap().get(), expected);
    }
    for token in [
        "-1",
        "-1.0",
        "0.1",
        "1.0000000000000001",
        "1e-999999999999999999",
        "1e999999999999999999999",
        "18446744073709551616",
        "18446744073709551615.1",
        "1e20",
        "01",
        "+1",
        "1e",
        "NaN",
        "Infinity",
        "true",
        "null",
        "{}",
        "[]",
        "\"SECRET\"",
        "1 2",
        " 1",
        "1 ",
    ] {
        assert_eq!(
            UnsignedInteger::parse(token).unwrap_err(),
            ScalarError::InvalidUnsigned
        );
    }
    let maximum_token = format!("0.{}", "0".repeat(254));
    assert_eq!(UnsignedInteger::parse(&maximum_token).unwrap().get(), 0);
    assert_eq!(
        UnsignedInteger::parse(&(maximum_token + "0")).unwrap_err(),
        ScalarError::TokenTooLong
    );
    assert_eq!(UnsignedInteger::new(u64::MAX).get(), u64::MAX);
}

#[test]
fn strict_timestamp_format_calendar_and_precision() {
    for text in [
        "0001-01-01T00:00:00Z",
        "9999-12-31T23:59:59Z",
        "2024-02-29T00:00:00Z",
        "2026-10-06T12:00:00.1Z",
        "2026-10-06T12:00:00+23:59",
        "2026-10-06T12:00:00-23:59",
        "2026-10-06T12:00:00-00:00",
    ] {
        assert_eq!(Timestamp::parse(text).unwrap().as_str(), text);
    }
    for text in [
        "0000-01-01T00:00:00Z",
        "2023-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-10-06t12:00:00Z",
        "2026-10-06T12:00:00z",
        "2026-10-06 12:00:00Z",
        "2026-10-06T12:00Z",
        "2026-10-06T12:00:00",
        "2026-10-06T24:00:00Z",
        "2026-10-06T12:60:00Z",
        "2026-10-06T12:00:60Z",
        "2026-10-06T12:00:00.Z",
        "2026-10-06T12:00:00.1234567890Z",
        "2026-10-06T12:00:00+24:00",
        "2026-10-06T12:00:00+00:60",
        "2026-10-06T12:00:00+0000",
        "2026-10-06T12:00:00Z\n",
        "SECRET",
    ] {
        assert!(Timestamp::parse(text).is_err());
    }
    let maximum = "2026-10-06T12:00:00.123456789+01:00";
    assert_eq!(maximum.len(), 35);
    assert_eq!(Timestamp::parse(maximum).unwrap().as_str(), maximum);
    assert_eq!(
        Timestamp::parse(&"S".repeat(1_000_000)).unwrap_err(),
        ScalarError::TimestampTooLong
    );
}

#[test]
fn serde_preserves_timestamps_normalizes_numbers_and_redacts_errors() {
    let text = "2026-10-06T12:00:00.123400-00:00";
    let timestamp: Timestamp = serde_json::from_str(&format!("\"{text}\"")).unwrap();
    assert_eq!(
        serde_json::to_string(&timestamp).unwrap(),
        format!("\"{text}\"")
    );
    assert_eq!(format!("{timestamp:?}"), "Timestamp");
    for token in ["1", "1.0", "100e-2"] {
        let number: UnsignedInteger = serde_json::from_str(token).unwrap();
        assert_eq!(serde_json::to_string(&number).unwrap(), "1");
        assert_eq!(format!("{number:?}"), "UnsignedInteger");
    }
    for input in ["123456789", "false", "null", "{}", "[]", "\"SECRET\""] {
        let error = serde_json::from_str::<Timestamp>(input)
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("invalid timestamp"));
        assert!(!error.contains("SECRET"));
        assert!(!error.contains("123456789"));
    }
    let error = serde_json::from_str::<UnsignedInteger>("\"SECRET\"")
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("invalid unsigned integer"));
    assert!(!error.contains("SECRET"));
    for error in [
        ScalarError::InvalidTimestamp,
        ScalarError::TimestampTooLong,
        ScalarError::InvalidUnsigned,
        ScalarError::TokenTooLong,
    ] {
        assert_eq!(error.to_string(), format!("{error:?}"));
    }
}
