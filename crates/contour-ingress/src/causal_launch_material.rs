//! Local key material checks only. These do not authenticate an actual TLS peer
//! or establish that a caller's byte slices came from an inspected container.
use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, alg_id, pem::PemObject},
    sign::{CertifiedKey, public_key_to_spki},
};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_PEM: usize = 65536;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterialError {
    Invalid,
    Mismatch,
}

// Require exactly one recognized PEM envelope and no non-whitespace outside it.
// rustls's iterator otherwise intentionally skips unrelated/unknown sections.
fn one_pem<'a>(bytes: &'a [u8], allowed: &[&str]) -> Result<&'a [u8], MaterialError> {
    if bytes.is_empty() || bytes.len() > MAX_PEM || !bytes.is_ascii() {
        return Err(MaterialError::Invalid);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| MaterialError::Invalid)?
        .trim();
    for label in allowed {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        if let Some(body) = text.strip_prefix(&begin).and_then(|s| s.strip_suffix(&end)) {
            if body.is_empty()
                || !body.bytes().all(|x| {
                    x.is_ascii_alphanumeric() || matches!(x, b'+' | b'/' | b'=' | b'\r' | b'\n')
                })
            {
                return Err(MaterialError::Invalid);
            }
            return Ok(text.as_bytes());
        }
    }
    Err(MaterialError::Invalid)
}
fn certificate(pem: &[u8]) -> Result<CertificateDer<'static>, MaterialError> {
    let pem = one_pem(pem, &["CERTIFICATE"])?;
    let mut it = CertificateDer::pem_slice_iter(pem);
    let item = it
        .next()
        .ok_or(MaterialError::Invalid)?
        .map_err(|_| MaterialError::Invalid)?;
    if it.next().is_some() {
        return Err(MaterialError::Invalid);
    }
    Ok(item)
}
fn certified(cert: &[u8], key: &[u8]) -> Result<CertifiedKey, MaterialError> {
    let cert = certificate(cert)?;
    let pem = one_pem(key, &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"])?;
    let mut keys = PrivateKeyDer::pem_slice_iter(pem);
    let key = keys
        .next()
        .ok_or(MaterialError::Invalid)?
        .map_err(|_| MaterialError::Invalid)?;
    if keys.next().is_some() {
        return Err(MaterialError::Invalid);
    }
    certified_der(cert, key)
}
fn certified_der(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<CertifiedKey, MaterialError> {
    let pair = CertifiedKey::from_der(vec![cert], key, &rustls::crypto::ring::default_provider())
        .map_err(|_| MaterialError::Mismatch)?;
    // from_der deliberately accepts Unknown; this explicit check rejects it.
    matching_key(&pair)?;
    Ok(pair)
}
fn matching_key(pair: &CertifiedKey) -> Result<(), MaterialError> {
    pair.keys_match().map_err(|_| MaterialError::Mismatch)?;
    if pair.key.public_key().is_none() {
        return Err(MaterialError::Mismatch);
    }
    Ok(())
}
fn separate_keys(marker: &[u8], product: &[u8], export: &[u8]) -> Result<(), MaterialError> {
    if marker == product || marker == export || product == export {
        return Err(MaterialError::Mismatch);
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Public fingerprints of already captured bytes, not a possession or TLS receipt.
#[derive(Clone, PartialEq, Eq)]
pub struct MaterialIdentity {
    marker_public: [u8; 32],
    product_leaf: [u8; 32],
    export_leaf: [u8; 32],
    server_leaf: [u8; 32],
    ca_sha256: [u8; 32],
}
impl MaterialIdentity {
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
    pub fn ca_sha256(&self) -> [u8; 32] {
        self.ca_sha256
    }
}
impl std::fmt::Debug for MaterialIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MaterialIdentity")
    }
}
/// Validate four one-cert/one-key PEM snapshots and one CA snapshot. Callers
/// must independently bind these snapshots to their verified read-only mounts.
#[allow(clippy::too_many_arguments)]
pub fn check_material(
    seed: &[u8; 32],
    product_cert: &[u8],
    product_key: &[u8],
    export_cert: &[u8],
    export_key: &[u8],
    server_cert: &[u8],
    server_key: &[u8],
    ca: &[u8],
) -> Result<MaterialIdentity, MaterialError> {
    let marker = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| MaterialError::Invalid)?;
    let marker_public: [u8; 32] = marker
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| MaterialError::Invalid)?;
    let marker_spki = public_key_to_spki(&alg_id::ED25519, marker_public);
    let product = certified(product_cert, product_key)?;
    let export = certified(export_cert, export_key)?;
    let server = certified(server_cert, server_key)?;
    let product_spki = product.key.public_key().ok_or(MaterialError::Mismatch)?;
    let export_spki = export.key.public_key().ok_or(MaterialError::Mismatch)?;
    separate_keys(
        marker_spki.as_ref(),
        product_spki.as_ref(),
        export_spki.as_ref(),
    )?;
    let ca_der = certificate(ca)?;
    let anchor = webpki::anchor_from_trusted_cert(&ca_der).map_err(|_| MaterialError::Invalid)?;
    let end_entity = webpki::EndEntityCert::try_from(
        server
            .end_entity_cert()
            .map_err(|_| MaterialError::Invalid)?,
    )
    .map_err(|_| MaterialError::Invalid)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MaterialError::Invalid)?;
    let provider = rustls::crypto::ring::default_provider();
    end_entity
        .verify_for_usage(
            provider.signature_verification_algorithms.all,
            &[anchor],
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(now.as_secs())),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|_| MaterialError::Mismatch)?;
    Ok(MaterialIdentity {
        marker_public,
        product_leaf: digest(
            product
                .end_entity_cert()
                .map_err(|_| MaterialError::Invalid)?
                .as_ref(),
        ),
        export_leaf: digest(
            export
                .end_entity_cert()
                .map_err(|_| MaterialError::Invalid)?
                .as_ref(),
        ),
        server_leaf: digest(
            server
                .end_entity_cert()
                .map_err(|_| MaterialError::Invalid)?
                .as_ref(),
        ),
        ca_sha256: digest(ca),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pem_envelope_rejects_extra_wrong_and_oversized() {
        let one = b"-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n";
        assert!(one_pem(one, &["CERTIFICATE"]).is_ok());
        assert!(one_pem(&[one.as_slice(), one.as_slice()].concat(), &["CERTIFICATE"]).is_err());
        assert!(one_pem(one, &["PRIVATE KEY"]).is_err());
        assert!(one_pem(&vec![b'x'; MAX_PEM + 1], &["CERTIFICATE"]).is_err());
        assert!(
            one_pem(
                b"-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----junk",
                &["CERTIFICATE"]
            )
            .is_err()
        );
    }
    #[test]
    fn unknown_key_consistency_and_each_spki_equality_fail_closed() {
        #[derive(Debug)]
        struct Unknown;
        impl rustls::sign::SigningKey for Unknown {
            fn choose_scheme(
                &self,
                _: &[rustls::SignatureScheme],
            ) -> Option<Box<dyn rustls::sign::Signer>> {
                None
            }
            fn algorithm(&self) -> rustls::SignatureAlgorithm {
                rustls::SignatureAlgorithm::ED25519
            }
        }
        let pair = CertifiedKey::new(Vec::new(), std::sync::Arc::new(Unknown));
        assert!(matching_key(&pair).is_err());
        assert_eq!(separate_keys(b"marker", b"product", b"export"), Ok(()));
        for (a, b, c) in [
            (b"a".as_slice(), b"a".as_slice(), b"c".as_slice()),
            (b"a".as_slice(), b"b".as_slice(), b"a".as_slice()),
            (b"a".as_slice(), b"b".as_slice(), b"b".as_slice()),
        ] {
            assert_eq!(separate_keys(a, b, c), Err(MaterialError::Mismatch));
        }
    }
    #[test]
    fn tracked_synthetic_key_and_unrelated_certificate_are_rejected() {
        let cert = CertificateDer::from(
            include_bytes!("gateway_testdata/exact.der")
                .as_slice()
                .to_vec(),
        );
        let key = PrivateKeyDer::try_from(
            include_bytes!("../../contour-auth/tests/fixtures/synthetic-rsa.der")
                .as_slice()
                .to_vec(),
        )
        .unwrap();
        assert!(matches!(
            certified_der(cert, key),
            Err(MaterialError::Mismatch)
        ));
    }
    #[test]
    fn public_synthetic_certificate_keys_and_chain_are_actually_checked() {
        let pc =
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/product.pem");
        let pk =
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/product.key");
        let ec =
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/export.pem");
        let ek =
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/export.key");
        let sc =
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/server.pem");
        let sk =
            include_bytes!("../../../tests/fixtures/causal-container-launch/materials/server.key");
        let ca = include_bytes!("../../../tests/fixtures/causal-container-launch/materials/ca.pem");
        let result = check_material(&[7; 32], pc, pk, ec, ek, sc, sk, ca).unwrap();
        assert_ne!(result.product_leaf(), result.export_leaf());
        assert_eq!(
            check_material(&[7; 32], pc, ek, ec, ek, sc, sk, ca).unwrap_err(),
            MaterialError::Mismatch
        );
        assert_eq!(
            check_material(&[7; 32], pc, pk, pc, pk, sc, sk, ca).unwrap_err(),
            MaterialError::Mismatch
        );
        assert_eq!(
            check_material(&[7; 32], pc, pk, ec, ek, pc, pk, ca).unwrap_err(),
            MaterialError::Mismatch
        );
        assert!(check_material(&[7; 32], pc, pk, ec, ek, sc, sk, pc).is_err());
        assert_eq!(
            check_material(
                &[7; 32],
                &[pc.as_slice(), pc.as_slice()].concat(),
                pk,
                ec,
                ek,
                sc,
                sk,
                ca
            )
            .unwrap_err(),
            MaterialError::Invalid
        );
    }
    #[test]
    fn marker_spki_is_real_ed25519_public_key() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let spki = public_key_to_spki(&alg_id::ED25519, key.public_key().as_ref());
        assert_eq!(
            &spki.as_ref()[spki.as_ref().len() - 32..],
            key.public_key().as_ref()
        );
    }
    #[test]
    fn public_material_debug_is_redacted() {
        let i = MaterialIdentity {
            marker_public: [1; 32],
            product_leaf: [2; 32],
            export_leaf: [3; 32],
            server_leaf: [4; 32],
            ca_sha256: [5; 32],
        };
        assert_eq!(format!("{i:?}"), "MaterialIdentity");
    }
}
