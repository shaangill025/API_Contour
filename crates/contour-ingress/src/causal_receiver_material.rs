//! Local 504 material checks only; no deployment, workload, or TLS peer proof.
//! The supplied CA is a trust anchor: this module does not verify its own CA role,
//! key usage, validity interval, or self-signature. The caller must check those
//! properties independently against the same captured CA bytes before deployment.
//! Leaf X.509 KeyUsage is also not enforced here; a deployment must separately
//! require TLS-signing key usage against the same captured leaf bytes.
use crate::causal_launch_material::{MaterialError, certificate, certified, digest};
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::{
    pki_types::{ServerName, UnixTime, alg_id},
    sign::{CertifiedKey, public_key_to_spki},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Borrowed snapshots. The caller must separately authenticate and bind their origin.
pub struct ReceiverMaterialInputs<'a> {
    pub marker_seed: &'a [u8; 32],
    pub product_cert: &'a [u8],
    pub product_key: &'a [u8],
    pub export_cert: &'a [u8],
    pub export_key: &'a [u8],
    pub server_cert: &'a [u8],
    pub server_key: &'a [u8],
    pub evidence_cert: &'a [u8],
    pub evidence_key: &'a [u8],
    pub ca: &'a [u8],
    pub server_name: &'a str,
}

/// Fingerprints of local bytes only. This is not an authorization or receipt.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalReceiverMaterialIdentity {
    marker_public: [u8; 32],
    product_leaf: [u8; 32],
    export_leaf: [u8; 32],
    server_leaf: [u8; 32],
    evidence_leaf: [u8; 32],
    ca_sha256: [u8; 32],
}
impl LocalReceiverMaterialIdentity {
    pub fn marker_public(&self) -> [u8; 32] {
        self.marker_public
    }
    pub fn product_leaf(&self) -> [u8; 32] {
        self.product_leaf
    }
    pub fn export_leaf(&self) -> [u8; 32] {
        self.export_leaf
    }
    pub fn server_leaf(&self) -> [u8; 32] {
        self.server_leaf
    }
    pub fn evidence_leaf(&self) -> [u8; 32] {
        self.evidence_leaf
    }
    pub fn ca_sha256(&self) -> [u8; 32] {
        self.ca_sha256
    }
}
impl std::fmt::Debug for LocalReceiverMaterialIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalReceiverMaterialIdentity")
    }
}

/// Checks five distinct purpose keys and four leaf certificates at the local clock.
/// A successful result does not authenticate a peer or inspect a container.
/// It also does not establish the supplied trust anchor's own role or validity,
/// or enforce the leaf certificates' X.509 KeyUsage extension.
pub fn check_local_receiver_material(
    input: &ReceiverMaterialInputs<'_>,
) -> Result<LocalReceiverMaterialIdentity, MaterialError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MaterialError::Invalid)?;
    check_at(
        input,
        UnixTime::since_unix_epoch(Duration::from_secs(now.as_secs())),
    )
}

fn check_at(
    input: &ReceiverMaterialInputs<'_>,
    now: UnixTime,
) -> Result<LocalReceiverMaterialIdentity, MaterialError> {
    let marker = Ed25519KeyPair::from_seed_unchecked(input.marker_seed)
        .map_err(|_| MaterialError::Invalid)?;
    let marker_public: [u8; 32] = marker
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| MaterialError::Invalid)?;
    let marker_spki = public_key_to_spki(&alg_id::ED25519, marker_public);
    let product = certified(input.product_cert, input.product_key)?;
    let export = certified(input.export_cert, input.export_key)?;
    let server = certified(input.server_cert, input.server_key)?;
    let evidence = certified(input.evidence_cert, input.evidence_key)?;
    let pairs: [&CertifiedKey; 4] = [&product, &export, &server, &evidence];
    let mut keys = vec![marker_spki.as_ref().to_vec()];
    let mut leaves = Vec::with_capacity(4);
    let ca_der = certificate(input.ca)?;
    let anchor = webpki::anchor_from_trusted_cert(&ca_der).map_err(|_| MaterialError::Invalid)?;
    let provider = rustls::crypto::ring::default_provider();
    let server_name =
        ServerName::try_from(input.server_name).map_err(|_| MaterialError::Invalid)?;
    if !matches!(&server_name, ServerName::DnsName(_)) {
        return Err(MaterialError::Invalid);
    }
    for (index, pair) in pairs.iter().enumerate() {
        let spki = pair.key.public_key().ok_or(MaterialError::Mismatch)?;
        if keys.iter().any(|key| key.as_slice() == spki.as_ref()) {
            return Err(MaterialError::Mismatch);
        }
        keys.push(spki.as_ref().to_vec());
        let der = pair.end_entity_cert().map_err(|_| MaterialError::Invalid)?;
        let fingerprint = digest(der.as_ref());
        if leaves.contains(&fingerprint) {
            return Err(MaterialError::Mismatch);
        }
        leaves.push(fingerprint);
        let cert = webpki::EndEntityCert::try_from(der).map_err(|_| MaterialError::Invalid)?;
        let usage = if index == 2 {
            webpki::KeyUsage::required(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])
        } else {
            webpki::KeyUsage::required(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02])
        };
        cert.verify_for_usage(
            provider.signature_verification_algorithms.all,
            &[anchor.clone()],
            &[],
            now,
            usage,
            None,
            None,
        )
        .map_err(|_| MaterialError::Mismatch)?;
        if index == 2 {
            cert.verify_is_valid_for_subject_name(&server_name)
                .map_err(|_| MaterialError::Mismatch)?;
        }
    }
    Ok(LocalReceiverMaterialIdentity {
        marker_public,
        product_leaf: leaves[0],
        export_leaf: leaves[1],
        server_leaf: leaves[2],
        evidence_leaf: leaves[3],
        ca_sha256: digest(input.ca),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const DIR_CA: &[u8] = include_bytes!("../../../tests/fixtures/causal-receiver-material/ca.pem");
    const PRODUCT: &[u8] =
        include_bytes!("../../../tests/fixtures/causal-receiver-material/product.pem");
    const PRODUCT_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/causal-receiver-material/product.key");
    const EXPORT: &[u8] =
        include_bytes!("../../../tests/fixtures/causal-receiver-material/export.pem");
    const EXPORT_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/causal-receiver-material/export.key");
    const SERVER: &[u8] =
        include_bytes!("../../../tests/fixtures/causal-receiver-material/server.pem");
    const SERVER_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/causal-receiver-material/server.key");
    const EVIDENCE: &[u8] =
        include_bytes!("../../../tests/fixtures/causal-receiver-material/evidence.pem");
    const EVIDENCE_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/causal-receiver-material/evidence.key");
    const MARKER: [u8; 32] = [7; 32];

    fn input() -> ReceiverMaterialInputs<'static> {
        ReceiverMaterialInputs {
            marker_seed: &MARKER,
            product_cert: PRODUCT,
            product_key: PRODUCT_KEY,
            export_cert: EXPORT,
            export_key: EXPORT_KEY,
            server_cert: SERVER,
            server_key: SERVER_KEY,
            evidence_cert: EVIDENCE,
            evidence_key: EVIDENCE_KEY,
            ca: DIR_CA,
            server_name: "receiver.example.test",
        }
    }
    fn validate(
        input: &ReceiverMaterialInputs<'_>,
    ) -> Result<LocalReceiverMaterialIdentity, MaterialError> {
        check_at(
            input,
            UnixTime::since_unix_epoch(Duration::from_secs(1_830_297_600)),
        )
    }

    #[test]
    fn valid_distinct_material_and_server_name() {
        let a = validate(&input()).expect("valid synthetic material");
        assert_eq!(a, validate(&input()).unwrap());
        let mut bad = input();
        bad.server_name = "wrong.example.test";
        assert!(validate(&bad).is_err());
        bad.server_name = "127.0.0.1";
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn rejects_pair_swaps_bad_chain_usage_and_expiry() {
        let mut bad = input();
        bad.product_key = EXPORT_KEY;
        assert!(validate(&bad).is_err());
        bad = input();
        bad.ca = include_bytes!("../../../tests/fixtures/causal-receiver-material/other-ca.pem");
        assert!(validate(&bad).is_err());
        bad = input();
        bad.evidence_cert =
            include_bytes!("../../../tests/fixtures/causal-receiver-material/wrong_eku.pem");
        assert!(validate(&bad).is_err());
        bad.evidence_cert =
            include_bytes!("../../../tests/fixtures/causal-receiver-material/expired.pem");
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn rejects_reused_marker_server_and_client_keys() {
        let mut bad = input();
        bad.product_cert =
            include_bytes!("../../../tests/fixtures/causal-receiver-material/marker_as_client.pem");
        bad.product_key =
            include_bytes!("../../../tests/fixtures/causal-receiver-material/marker.key");
        assert!(validate(&bad).is_err());
        bad = input();
        bad.evidence_cert =
            include_bytes!("../../../tests/fixtures/causal-receiver-material/server_as_client.pem");
        bad.evidence_key = SERVER_KEY;
        assert!(validate(&bad).is_err());
        bad = input();
        bad.evidence_cert = PRODUCT;
        bad.evidence_key = PRODUCT_KEY;
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn requires_explicit_server_and_client_eku() {
        let mut candidate = input();
        candidate.ca =
            include_bytes!("../../../tests/fixtures/causal-receiver-material/no-eku-ca.pem");
        candidate.product_cert =
            include_bytes!("../../../tests/fixtures/causal-receiver-material/no-eku-product.pem");
        candidate.export_cert =
            include_bytes!("../../../tests/fixtures/causal-receiver-material/no-eku-export.pem");
        candidate.server_cert = include_bytes!(
            "../../../tests/fixtures/causal-receiver-material/no-eku-server-valid.pem"
        );
        candidate.evidence_cert = include_bytes!(
            "../../../tests/fixtures/causal-receiver-material/no-eku-evidence-valid.pem"
        );
        assert!(validate(&candidate).is_ok());
        candidate.server_cert =
            include_bytes!("../../../tests/fixtures/causal-receiver-material/no-eku-server.pem");
        assert!(validate(&candidate).is_err());
        candidate.server_cert = include_bytes!(
            "../../../tests/fixtures/causal-receiver-material/no-eku-server-valid.pem"
        );
        candidate.evidence_cert =
            include_bytes!("../../../tests/fixtures/causal-receiver-material/no-eku-evidence.pem");
        assert!(validate(&candidate).is_err());
    }

    #[test]
    fn rejects_multiple_pem_objects() {
        let mut concatenated = PRODUCT.to_vec();
        concatenated.extend_from_slice(PRODUCT);
        let mut bad = input();
        bad.product_cert = &concatenated;
        assert!(validate(&bad).is_err());
    }
}
