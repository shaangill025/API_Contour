use contour_core::{CausalEvidenceBinding, CausalEvidenceObserver, CausalEvidenceReceiver};
use serde_json::Value;

fn fixtures() -> Vec<Value> {
    serde_json::from_str(include_str!(
        "../../../docs/specification/fixtures/causal-evidence-v1.json"
    ))
    .unwrap()
}
#[test]
fn shared_vectors_and_domains() {
    for f in fixtures() {
        let input = serde_json::to_vec(&f["body"]).unwrap();
        let (canonical, digest) = match f["kind"].as_str().unwrap() {
            "binding" => {
                let x = CausalEvidenceBinding::from_wire_json(&input).unwrap();
                (x.canonical_bytes().unwrap(), x.digest_bytes().unwrap())
            }
            "observer" => {
                let x = CausalEvidenceObserver::from_wire_json(&input).unwrap();
                (x.canonical_bytes().unwrap(), x.digest_bytes().unwrap())
            }
            "receiver" => {
                let x = CausalEvidenceReceiver::from_wire_json(&input).unwrap();
                (x.canonical_bytes().unwrap(), x.digest_bytes().unwrap())
            }
            _ => panic!(),
        };
        assert_eq!(canonical, f["canonical"].as_str().unwrap().as_bytes());
        assert_eq!(
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            f["sha256"].as_str().unwrap()
        );
    }
}
#[test]
fn reject_invalid_wire() {
    let fs = fixtures();
    let binding = serde_json::to_string(&fs[0]["body"]).unwrap();
    for bad in [
        binding.replace(",\"retry_of\":null", ""),
        binding.replace("\"retry_of\":null", "\"retry_of\":null,\"retry_of\":null"),
        binding.replace("\"wire_version\":1", "\"wire_version\":2"),
        binding.replace(
            "\"producer_session_epoch\":\"9007199254740993\"",
            "\"producer_session_epoch\":9007199254740993",
        ),
        binding.replace("9007199254740993", "09007199254740993"),
        binding.replace("18446744073709551615", "18446744073709551616"),
        binding.replace("123e4567", "123E4567"),
        binding.replace("\"marker_digest\":", "\"extra\":1,\"marker_digest\":"),
    ] {
        assert!(
            CausalEvidenceBinding::from_wire_json(bad.as_bytes()).is_err(),
            "{bad}"
        );
    }
    assert!(CausalEvidenceBinding::from_wire_json(&vec![b' '; 2049]).is_err());
    let observer = serde_json::to_string(&fs[1]["body"]).unwrap();
    for bad in [
        observer.replace("\"retry_of\":null", "\"retry_of\":null,\"retry_of\":null"),
        observer.replace("ac1.fixture.signature", "bad"),
        observer.replace("\"wire_version\":1", "\"wire_version\":false"),
    ] {
        assert!(
            CausalEvidenceObserver::from_wire_json(bad.as_bytes()).is_err(),
            "{bad}"
        );
    }
    let padded = observer.replacen(
        "\"binding\":{",
        &format!("\"binding\":{{{}", " ".repeat(2049)),
        1,
    );
    assert!(padded.len() < 4096);
    assert!(CausalEvidenceObserver::from_wire_json(padded.as_bytes()).is_err());
    assert!(CausalEvidenceObserver::from_wire_json(&vec![b' '; 4097]).is_err());
    let receiver = serde_json::to_string(&fs[2]["body"]).unwrap();
    for bad in [
        receiver.replace("\"wire_version\":1", "\"wire_version\":2"),
        receiver.replace("\"wire_version\":1", "\"wire_version\":true"),
        receiver.replace(
            "\"wire_version\":1",
            "\"wire_version\":1,\"wire_version\":1",
        ),
        receiver.replace("\"local_root\":", "\"extra\":1,\"local_root\":"),
        receiver.replace("18446744073709551615", "0"),
        receiver.replace("\"18446744073709551615\"", "18446744073709551615"),
        receiver.replace("\"local_root\":\"55555555555555555555555555555555\",", ""),
        receiver.replace(
            "6666666666666666666666666666666666666666666666666666666666666666",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ),
    ] {
        assert!(
            CausalEvidenceReceiver::from_wire_json(bad.as_bytes()).is_err(),
            "{bad}"
        );
    }
    assert!(CausalEvidenceReceiver::from_wire_json(&vec![b' '; 4097]).is_err());
}
