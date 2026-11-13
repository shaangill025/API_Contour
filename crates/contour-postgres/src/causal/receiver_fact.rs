//! Receiver evidence transport and SQL29 writer. Enrollment remains authoritative in SQL.
use super::*;
use contour_core::CausalEvidenceReceiver;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTlsError {
    Configuration,
    Deadline,
    Handshake,
}

/// Private proof of a freshly authenticated receiver evidence TLS peer.
/// ```compile_fail
/// use contour_postgres::ReceiverEvidencePeer;
/// let _peer = ReceiverEvidencePeer { leaf: [0; 32] };
/// ```
/// ```compile_fail
/// use contour_postgres::ReceiverEvidencePeer;
/// fn duplicate(peer: &ReceiverEvidencePeer) -> ReceiverEvidencePeer { peer.clone() }
/// ```
/// ```compile_fail
/// use contour_postgres::{CausalReceiverSession504, CausalSession};
/// fn wrong_profile(_: &CausalReceiverSession504) {}
/// fn misuse(legacy: &CausalSession) { wrong_profile(legacy); }
/// ```
pub struct ReceiverEvidencePeer {
    leaf: [u8; 32],
}

/// A TLS connection and its inseparable peer proof. No underlying stream is exposed.
/// ```compile_fail
/// use contour_postgres::ReceiverEvidenceConnection;
/// fn replace(connection: &mut ReceiverEvidenceConnection) { connection.stream = todo!(); }
/// ```
pub struct ReceiverEvidenceConnection {
    stream: TlsStream<TcpStream>,
    peer: ReceiverEvidencePeer,
}
impl ReceiverEvidenceConnection {
    pub fn peer(&self) -> &ReceiverEvidencePeer {
        &self.peer
    }
}
impl AsyncRead for ReceiverEvidenceConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for ReceiverEvidenceConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Builds mandatory WebPKI client authentication from operator-supplied DER.
pub struct ReceiverEvidenceTls {
    acceptor: TlsAcceptor,
    deadline: Duration,
}
fn bounded_bundle(bundle: &[&[u8]]) -> bool {
    !bundle.is_empty()
        && bundle.len() <= 8
        && bundle.iter().all(|x| !x.is_empty())
        && bundle
            .iter()
            .try_fold(0usize, |n, x| n.checked_add(x.len()))
            .is_some_and(|n| n <= 65536)
}
impl ReceiverEvidenceTls {
    pub fn from_der(
        chain: &[&[u8]],
        key: &[u8],
        roots: &[&[u8]],
        deadline: Duration,
    ) -> Result<Self, ReceiverTlsError> {
        let invalid = ReceiverTlsError::Configuration;
        if !bounded_bundle(chain)
            || !bounded_bundle(roots)
            || key.is_empty()
            || key.len() > 16384
            || !(Duration::from_millis(1)..=Duration::from_secs(30)).contains(&deadline)
        {
            return Err(invalid);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut store = RootCertStore::empty();
        for root in roots {
            store
                .add(CertificateDer::from(root.to_vec()))
                .map_err(|_| invalid)?;
        }
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(store), provider.clone())
                .build()
                .map_err(|_| invalid)?;
        let key = PrivateKeyDer::try_from(key.to_vec()).map_err(|_| invalid)?;
        let chain = chain
            .iter()
            .map(|x| CertificateDer::from(x.to_vec()))
            .collect();
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| invalid)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .map_err(|_| invalid)?;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            deadline,
        })
    }
    pub async fn accept_until(
        &self,
        socket: TcpStream,
        deadline: Instant,
    ) -> Result<ReceiverEvidenceConnection, ReceiverTlsError> {
        let now = Instant::now();
        let deadline = handshake_deadline(now, self.deadline, deadline)?;
        let stream = timeout_at(deadline, self.acceptor.accept(socket))
            .await
            .map_err(|_| ReceiverTlsError::Deadline)?
            .map_err(|_| ReceiverTlsError::Handshake)?;
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or(ReceiverTlsError::Handshake)?;
        // Use the fixed SHA-256 provider, independent of the negotiated TLS suite.
        // The workspace exposes no general-purpose SHA-256 helper to this crate.
        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .ok_or(ReceiverTlsError::Configuration)?;
        let digest = suite.common.hash_provider.hash(leaf.as_ref());
        let leaf: [u8; 32] = digest
            .as_ref()
            .try_into()
            .map_err(|_| ReceiverTlsError::Configuration)?;
        if Instant::now() >= deadline {
            return Err(ReceiverTlsError::Deadline);
        }
        Ok(ReceiverEvidenceConnection {
            stream,
            peer: ReceiverEvidencePeer { leaf },
        })
    }
}

fn handshake_deadline(
    now: Instant,
    limit: Duration,
    requested: Instant,
) -> Result<Instant, ReceiverTlsError> {
    let deadline = requested.min(now + limit);
    if now >= deadline {
        Err(ReceiverTlsError::Deadline)
    } else {
        Ok(deadline)
    }
}

/// Candidate identifiers select an enrollment; they do not prove one.
pub struct ReceiverFactSelectors {
    generation: String,
    credential: String,
}
impl ReceiverFactSelectors {
    pub fn new(generation: &str, credential: &str) -> Result<Self, CausalError> {
        if generation.len() != 32
            || !generation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || generation.bytes().all(|b| b == b'0')
            || !uuid(credential)
        {
            return Err(CausalError::Identity);
        }
        Ok(Self {
            generation: generation.into(),
            credential: credential.into(),
        })
    }
}
/// Untrusted fact bytes and enrollment selectors; neither conveys authority.
pub struct ReceiverFactRequest<'a> {
    pub selectors: &'a ReceiverFactSelectors,
    pub canonical_fact: &'a [u8],
}

/// Exact canonical SQL29 receipt, returned only after confirmed commit.
pub struct ReceiverFactReceipt {
    bytes: Vec<u8>,
}
impl ReceiverFactReceipt {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
pub struct ReceiverFactInbox {
    connection: ConnectedDatabase,
}
impl ReceiverFactInbox {
    pub fn new(connection: ConnectedDatabase) -> Self {
        Self { connection }
    }
    pub fn into_database(self) -> ConnectedDatabase {
        self.connection
    }
    pub async fn accept_until(
        &mut self,
        session: &CausalReceiverSession504,
        peer: &ReceiverEvidencePeer,
        request: ReceiverFactRequest<'_>,
        grant_keys: &CausalGrantKeys,
        policy_keys: &PolicyKeys,
        deadline: Instant,
    ) -> Result<ReceiverFactReceipt, CausalError> {
        let deadline = deadline.min(Instant::now() + self.connection.deadline);
        let ReceiverFactRequest {
            selectors,
            canonical_fact: bytes,
        } = request;
        check_deadline(deadline)?;
        receiver_event_session(session)?;
        let session = &session.session;
        let deadline = deadline.min(session.verified_until);
        let fact =
            CausalEvidenceReceiver::from_wire_json(bytes).map_err(|_| CausalError::InvalidBatch)?;
        if fact
            .canonical_bytes()
            .map_err(|_| CausalError::InvalidBatch)?
            != bytes
        {
            return Err(CausalError::InvalidBatch);
        }
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| CausalError::InvalidBatch)?;
        let ids = &session.issue.binding.ids;
        if value["tenant_id"].as_str() != Some(ids[0].as_str())
            || value["receiver_runtime_id"].as_str() != Some(ids[1].as_str())
            || value["receiver_session_epoch"].as_str() != Some(session.epoch.to_string().as_str())
        {
            return Err(CausalError::Scope);
        }
        let digest = fact.digest_bytes().map_err(|_| CausalError::InvalidBatch)?;
        let mut guard = CancellationGuard::arm(&mut self.connection);
        let mut committing = false;
        let mut accepted = None;
        let work = async {
            let client = guard
                .connection
                .client
                .as_mut()
                .ok_or(CausalError::Database)?;
            check_role(client, "contour_causal_receiver_writer").await?;
            let tx = begin(client).await?;
            let preparation = async {
                configure_tenant(&tx, &ids[0], deadline.saturating_duration_since(Instant::now())).await?;
                let now = clock(&tx).await?;
                verify_session(session, grant_keys, policy_keys, now)?;
                let leaf = peer.leaf.as_slice();
                let row = tx.query_one("SELECT contour.accept_causal_receiver($1, ROW($2::bytea,$3::text,$4::text::uuid)::contour.verified_receiver_claim)", &[&bytes, &leaf, &selectors.generation, &selectors.credential]).await.map_err(db_error)?;
                let receipt: Vec<u8> = row.try_get(0).map_err(|_| CausalError::Database)?;
                validate_receipt(&receipt, &digest)?;
                tx.query_one("SELECT set_config('synchronous_commit','on',true)", &[]).await.map_err(nonretry_error)?;
                let final_now = clock(&tx).await?;
                if final_now < now { return Err(CausalError::Expired); }
                verify_session(session, grant_keys, policy_keys, final_now)?;
                check_deadline(deadline)?;
                Ok::<_, CausalError>(receipt)
            }.await;
            match preparation {
                Ok(receipt) => {
                    committing = true;
                    tx.commit().await.map_err(|_| CausalError::OutcomeUnknown)?;
                    accepted = Some(receipt);
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    guard.confirm();
                    Ok(())
                }
                Err(e) => {
                    tx.rollback().await.map_err(db_error)?;
                    empty_context(client).await?;
                    check_deadline(deadline)?;
                    if e != CausalError::Deadline {
                        guard.confirm();
                    }
                    Err(e)
                }
            }
        };
        match timeout_at(deadline, work).await {
            Ok(Ok(())) => Ok(ReceiverFactReceipt {
                bytes: accepted.ok_or(CausalError::Database)?,
            }),
            Ok(Err(_)) if committing => Err(CausalError::OutcomeUnknown),
            Ok(Err(e)) => Err(e),
            Err(_) if committing => Err(CausalError::OutcomeUnknown),
            Err(_) => Err(CausalError::Deadline),
        }
    }
}
fn verify_session(
    session: &CausalSession,
    grant_keys: &CausalGrantKeys,
    policy_keys: &PolicyKeys,
    now: OffsetDateTime,
) -> Result<(), CausalError> {
    let (grant, _) = verify(
        &session.issue,
        &session.issue.binding.peer,
        grant_keys,
        policy_keys,
        now,
    )?;
    if now < session.issued
        || now >= session.expires
        || grant.payload_digest() != session.digest
        || session.verified_remaining().is_zero()
    {
        return Err(CausalError::Expired);
    }
    Ok(())
}
fn validate_receipt(bytes: &[u8], digest: &[u8; 32]) -> Result<(), CausalError> {
    if bytes.len() > 1024 {
        return Err(CausalError::Corrupt);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CausalError::Corrupt)?;
    let obj = value.as_object().ok_or(CausalError::Corrupt)?;
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    if obj.len() != 5
        || value["wire_version"].as_u64() != Some(1)
        || value["kind"].as_str() != Some("receiver")
        || value["status"].as_str() != Some("stored")
        || value["fact_digest"].as_str() != Some(&hex)
        || !value["receipt_id"].as_str().is_some_and(uuid)
        || serde_json::to_vec(&value).map_err(|_| CausalError::Corrupt)? != bytes
    {
        return Err(CausalError::Corrupt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_are_data_with_closed_syntax() {
        let credential = "00000000-0000-4000-8000-000000000001";
        assert!(ReceiverFactSelectors::new("1234567890abcdef1234567890abcdef", credential).is_ok());
        assert!(
            ReceiverFactSelectors::new("00000000000000000000000000000000", credential).is_err()
        );
        assert!(
            ReceiverFactSelectors::new("1234567890ABCDEF1234567890ABCDEF", credential).is_err()
        );
        assert!(ReceiverFactSelectors::new("1234567890abcdef1234567890abcdef", "invalid").is_err());
    }

    #[test]
    fn receipt_requires_exact_canonical_five_fields_and_digest() {
        let digest = [0u8; 32];
        let bytes = br#"{"fact_digest":"0000000000000000000000000000000000000000000000000000000000000000","kind":"receiver","receipt_id":"00000000-0000-4000-8000-000000000001","status":"stored","wire_version":1}"#;
        assert!(validate_receipt(bytes, &digest).is_ok());
        assert!(validate_receipt(bytes, &[1; 32]).is_err());
        let wrong_type = String::from_utf8(bytes.to_vec())
            .unwrap()
            .replace("\"wire_version\":1", "\"wire_version\":\"1\"");
        assert!(validate_receipt(wrong_type.as_bytes(), &digest).is_err());
        let wrong_key = String::from_utf8(bytes.to_vec())
            .unwrap()
            .replace("\"status\"", "\"state\"");
        assert!(validate_receipt(wrong_key.as_bytes(), &digest).is_err());
        let mut padded = bytes.to_vec();
        padded.push(b' ');
        assert!(validate_receipt(&padded, &digest).is_err());
        let extra = String::from_utf8(bytes.to_vec())
            .unwrap()
            .replace("\"kind\":", "\"extra\":1,\"kind\":");
        assert!(validate_receipt(extra.as_bytes(), &digest).is_err());
    }

    #[test]
    fn expired_handshake_deadline_fails_before_io() {
        let now = Instant::now();
        assert_eq!(
            handshake_deadline(now, Duration::from_secs(1), now),
            Err(ReceiverTlsError::Deadline)
        );
        assert_eq!(
            handshake_deadline(now, Duration::from_secs(1), now + Duration::from_secs(2)),
            Ok(now + Duration::from_secs(1))
        );
    }

    #[test]
    fn tls_material_is_bounded() {
        assert!(!bounded_bundle(&[]));
        assert!(!bounded_bundle(&[b""]));
        assert!(!bounded_bundle(&[&[0; 65537]]));
        assert!(bounded_bundle(&[b"der"]));
        assert!(
            ReceiverEvidenceTls::from_der(&[], b"key", &[b"root"], Duration::from_secs(1)).is_err()
        );
    }
}

#[cfg(test)]
mod tls_tests;
