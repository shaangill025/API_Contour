use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use contour_core::{
    CausalMarkerClaim, CausalMarkerError as E, CausalMarkerScope, CausalMarkerVerifier,
    MAX_CAUSAL_MARKER_BYTES,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
const TENANT: &str = "f0000000-0000-4000-8000-000000000001";
const RUNTIME: &str = "fc000000-0000-4000-8000-000000000001";
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/signed-causal-marker-openssl.json")).unwrap()
}
fn bytes32(s: &str) -> [u8; 32] {
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}
fn scope() -> CausalMarkerScope {
    CausalMarkerScope::new(TENANT, RUNTIME, u64::MAX, &"44".repeat(32)).unwrap()
}
fn verifier() -> CausalMarkerVerifier {
    CausalMarkerVerifier::new(
        bytes32(fixture()["public_key_hex"].as_str().unwrap()),
        scope(),
    )
    .unwrap()
}
fn signed_raw(payload: &[u8], seed: u8) -> String {
    let mut msg = b"apicontour/causal-marker/1\n".to_vec();
    msg.extend_from_slice(payload);
    let sig = SigningKey::from_bytes(&[seed; 32]).sign(&msg);
    format!(
        "ac1.{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    )
}
#[test]
fn openssl_golden_sign_verify_and_digest() {
    let f = fixture();
    let seed = bytes32(f["seed_hex"].as_str().unwrap());
    let claim = CausalMarkerClaim::new(
        &scope(),
        &"11".repeat(16),
        &"22".repeat(16),
        &"33".repeat(16),
    )
    .unwrap();
    let signed = claim.sign(&seed).unwrap();
    assert_eq!(signed.header(), f["header"].as_str().unwrap());
    let verified = verifier().verify(signed.header()).unwrap();
    assert_eq!(
        (verified.root(), verified.activity(), verified.attempt()),
        (&*"11".repeat(16), &*"22".repeat(16), &*"33".repeat(16))
    );
    assert_eq!(
        verified.marker_digest(),
        bytes32(f["marker_digest"].as_str().unwrap())
    );
    assert_eq!(verified.marker_digest(), signed.marker_digest());
    for text in [
        format!("{claim:?}"),
        format!("{signed:?}"),
        format!("{verified:?}"),
        format!("{:?}", verifier()),
        format!("{:?}", scope()),
    ] {
        assert!(!text.contains(TENANT));
        assert!(!text.contains(signed.header()));
        assert!(!text.contains(f["seed_hex"].as_str().unwrap()));
    }
}
#[test]
fn keys_signature_and_scope_fail_closed() {
    let f = fixture();
    let header = f["header"].as_str().unwrap();
    let payload = f["payload"].as_str().unwrap();
    assert!(matches!(
        CausalMarkerVerifier::new([0; 32], scope()),
        Err(E::Key)
    ));
    assert!(matches!(
        CausalMarkerVerifier::new([0xff; 32], scope()),
        Err(E::Key)
    ));
    let mut tampered = header.as_bytes().to_vec();
    tampered[4] = if tampered[4] == b'A' { b'B' } else { b'A' };
    assert!(matches!(
        verifier().verify(std::str::from_utf8(&tampered).unwrap()),
        Err(E::Signature)
    ));
    let wrong = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    assert!(matches!(
        CausalMarkerVerifier::new(wrong, scope())
            .unwrap()
            .verify(header),
        Err(E::Signature)
    ));
    assert!(matches!(
        verifier().verify(&signed_raw(payload.as_bytes(), 8)),
        Err(E::Signature)
    ));
    let raw_signature = SigningKey::from_bytes(&[7; 32]).sign(payload.as_bytes());
    let wrong_domain = format!(
        "ac1.{}.{}",
        URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        URL_SAFE_NO_PAD.encode(raw_signature.to_bytes())
    );
    assert!(matches!(
        verifier().verify(&wrong_domain),
        Err(E::Signature)
    ));
    let malformed = (0u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
        .unwrap();
    assert!(matches!(
        CausalMarkerVerifier::new(malformed, scope()),
        Err(E::Key)
    ));
    for mismatch in [
        CausalMarkerScope::new(
            "f0000000-0000-4000-8000-000000000002",
            RUNTIME,
            u64::MAX,
            &"44".repeat(32),
        )
        .unwrap(),
        CausalMarkerScope::new(
            TENANT,
            "fc000000-0000-4000-8000-000000000002",
            u64::MAX,
            &"44".repeat(32),
        )
        .unwrap(),
        CausalMarkerScope::new(TENANT, RUNTIME, u64::MAX - 1, &"44".repeat(32)).unwrap(),
        CausalMarkerScope::new(TENANT, RUNTIME, u64::MAX, &"45".repeat(32)).unwrap(),
    ] {
        assert!(matches!(
            CausalMarkerVerifier::new(bytes32(f["public_key_hex"].as_str().unwrap()), mismatch)
                .unwrap()
                .verify(header),
            Err(E::Scope)
        ));
    }
    assert!(matches!(
        CausalMarkerScope::new(TENANT, RUNTIME, 0, &"44".repeat(32)),
        Err(E::Scope)
    ));
    assert!(matches!(
        CausalMarkerScope::new(TENANT, RUNTIME, 1, &"AA".repeat(32)),
        Err(E::Scope)
    ));
    assert!(matches!(
        CausalMarkerClaim::new(
            &scope(),
            "oversized-secret",
            &"22".repeat(16),
            &"33".repeat(16)
        ),
        Err(E::Invalid)
    ));
}
#[test]
fn signed_noncanonical_or_invalid_payload_is_refused() {
    let f = fixture();
    let p = f["payload"].as_str().unwrap();
    let variants = [
        format!(" {p}"),
        p.replace("\"activity\":\"22222222222222222222222222222222\",\"attempt\":\"33333333333333333333333333333333\"", "\"attempt\":\"33333333333333333333333333333333\",\"activity\":\"22222222222222222222222222222222\""),
        p.replace("fc000000-0000-4000-8000-000000000001", "FC000000-0000-4000-8000-000000000001"),
        p.replace("\"activity\":", "\"unknown\":0,\"activity\":"),
        p.replace(
            "\"activity\":",
            "\"activity\":\"22222222222222222222222222222222\",\"activity\":",
        ),
        p.replace("\"activity\":", "\"\\u0061ctivity\":"),
        p.replace("\"wire_version\":1", "\"wire_version\":1.0"),
        p.replace("18446744073709551615", "18446744073709551616"),
        p.replace("18446744073709551615", "0"),
        p.replace(
            "11111111111111111111111111111111",
            "1111111111111111111111111111111é",
        ),
        p.replace("\"wire_version\":1", "\"wire_version\":2"),
    ];
    for invalid in variants {
        assert!(matches!(
            verifier().verify(&signed_raw(invalid.as_bytes(), 7)),
            Err(E::Invalid)
        ));
    }
}
#[test]
fn malformed_header_and_base64_rejected() {
    let f = fixture();
    let h = f["header"].as_str().unwrap();
    for invalid in [
        "",
        "ac2.a.b",
        "ac1.a.b.c",
        "ac1..",
        "ac1.a.b",
        &format!("{h}="),
        &format!(" {h}"),
        &format!("{h}\n"),
        &format!("é{h}"),
    ] {
        assert!(verifier().verify(invalid).is_err());
    }
    assert!(matches!(
        verifier().verify(&"x".repeat(MAX_CAUSAL_MARKER_BYTES + 1)),
        Err(E::Size)
    ));
    // Alter only unused signature base64 bits; aliases are never accepted.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = h.as_bytes()[h.len() - 1];
    let position = alphabet.iter().position(|byte| *byte == last).unwrap();
    assert_eq!(position & 15, 0);
    let mut alias = h.as_bytes().to_vec();
    *alias.last_mut().unwrap() = alphabet[position + 1];
    assert!(matches!(
        verifier().verify(std::str::from_utf8(&alias).unwrap()),
        Err(E::Invalid)
    ));
}

#[test]
fn canonical_mixed_order_public_key_is_rejected() {
    let f = fixture();
    let prime_bytes = bytes32(f["public_key_hex"].as_str().unwrap());
    let prime = ed25519_dalek::VerifyingKey::from_bytes(&prime_bytes).unwrap();
    assert!(!prime.is_weak());
    assert!(prime.to_edwards().is_torsion_free());
    assert!(verifier().verify(f["header"].as_str().unwrap()).is_ok());

    // The compressed order-two Edwards point has y = -1 in canonical form.
    // Adding it to a nonzero prime-order key creates a point with both
    // components, rather than the weak/small-order point alone.
    let mut order_two = [0xff; 32];
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    let torsion = ed25519_dalek::VerifyingKey::from_bytes(&order_two).unwrap();
    assert!(torsion.is_weak());
    assert_eq!(torsion.to_edwards().compress().to_bytes(), order_two);
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_ne!(order_two, identity);
    assert_eq!(
        (torsion.to_edwards() + torsion.to_edwards())
            .compress()
            .to_bytes(),
        identity
    );
    let mixed_bytes = (prime.to_edwards() + torsion.to_edwards())
        .compress()
        .to_bytes();
    let mixed = ed25519_dalek::VerifyingKey::from_bytes(&mixed_bytes).unwrap();
    assert_eq!(mixed.to_edwards().compress().to_bytes(), mixed_bytes);
    assert!(!mixed.is_weak());
    assert!(!mixed.to_edwards().is_torsion_free());
    assert_eq!(
        (mixed.to_edwards() - prime.to_edwards())
            .compress()
            .to_bytes(),
        order_two
    );
    // Canonical encoding and a non-weak check alone accept this key; the
    // separate torsion-free requirement must reject it at configuration time.
    assert!(matches!(
        CausalMarkerVerifier::new(mixed_bytes, scope()),
        Err(E::Key)
    ));
}

#[test]
fn valid_signature_with_scalar_plus_group_order_is_rejected() {
    let f = fixture();
    let header = f["header"].as_str().unwrap();
    let verified = verifier().verify(header).unwrap();
    assert_eq!(
        verified.marker_digest(),
        bytes32(f["marker_digest"].as_str().unwrap())
    );
    let mut parts = header.split('.');
    assert_eq!(parts.next(), Some("ac1"));
    let payload = parts.next().unwrap();
    let encoded_signature = parts.next().unwrap();
    assert!(parts.next().is_none());
    let mut signature = URL_SAFE_NO_PAD.decode(encoded_signature).unwrap();
    assert_eq!(signature.len(), 64);
    let original = signature.clone();
    // Ed25519 subgroup order L, in little-endian form. S + L is the same
    // residue modulo L, but is not a canonical encoded signature scalar.
    let order = bytes32("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut carry = 0u16;
    for (byte, modulus) in signature[32..].iter_mut().zip(order) {
        let sum = u16::from(*byte) + u16::from(modulus) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(&signature[..32], &original[..32]);
    assert_ne!(&signature[32..], &original[32..]);
    // Signature parsing accepts the 64-byte shape; strict verification must
    // reject the noncanonical S value instead of reducing it modulo L.
    assert!(ed25519_dalek::Signature::from_slice(&signature).is_ok());
    let malleable = format!("ac1.{payload}.{}", URL_SAFE_NO_PAD.encode(signature));
    assert!(matches!(verifier().verify(&malleable), Err(E::Signature)));
}
