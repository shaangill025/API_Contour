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

#[test]
fn adapter_clock_fails_closed_on_missing_rollback_and_deadline() {
    use contour_core::{Completeness, InspectionClock, ObservationReason, extract_json_with_clock};
    use std::time::Duration;

    struct Clock {
        ticks: std::vec::IntoIter<Option<Duration>>,
        fallback: Option<Duration>,
    }
    impl InspectionClock for Clock {
        fn now(&mut self) -> Option<Duration> {
            self.ticks.next().unwrap_or(self.fallback)
        }
    }
    let tick = |n| Some(Duration::from_nanos(n));
    let run = |ticks: Vec<Option<Duration>>| {
        let mut clock = Clock {
            fallback: ticks.last().copied().flatten(),
            ticks: ticks.into_iter(),
        };
        extract_json_with_clock(b"0", &ExtractionPolicy::default(), &mut clock)
    };
    for ticks in [
        vec![None],
        vec![tick(100), None],
        vec![tick(100), tick(101), tick(100)],
        vec![
            tick(100),
            tick(100),
            tick(100),
            tick(100),
            tick(100),
            tick(2_000_100),
        ],
    ] {
        let observation = run(ticks);
        assert_eq!(observation.completeness, Completeness::Partial);
        assert_eq!(observation.reasons, vec![ObservationReason::Limit]);
    }
    let observation = run(vec![
        tick(100),
        tick(100),
        tick(100),
        tick(100),
        tick(100),
        tick(2_000_099),
    ]);
    assert_eq!(observation.completeness, Completeness::Complete);
    assert!(observation.reasons.is_empty());
}
