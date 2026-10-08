//! Operator-configured mTLS ingestion. Enrollment and credential lifecycle are separate.
mod pool;
mod service;
pub use pool::DatabaseCapacity;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};
pub use service::{HttpLimits, IngestionServer, IngressError, PrincipalRegistry};
use std::{fmt, sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsError {
    Configuration,
    Deadline,
    Handshake,
}
impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TlsError {}

/// Operator-supplied trust only. Configuration has no client-authentication bypass.
/// DER/key input bounds limit copies; key-memory erasure is not guaranteed.
pub struct CollectorTls {
    acceptor: TlsAcceptor,
    deadline: Duration,
}
impl fmt::Debug for CollectorTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CollectorTls")
    }
}
impl CollectorTls {
    /// Each chain/root bundle contains 1–8 DER certificates, together at most 64 KiB.
    /// Key is PKCS#1, PKCS#8 or SEC1 DER, 1–16 KiB; deadline is 1 ms–30 seconds.
    /// Trust roots and identity come from deployment configuration, never a request.
    pub fn from_der(
        server_chain: &[&[u8]],
        key: &[u8],
        client_roots: &[&[u8]],
        deadline: Duration,
    ) -> Result<Self, TlsError> {
        if !bounded_bundle(server_chain)
            || !bounded_bundle(client_roots)
            || key.is_empty()
            || key.len() > 16_384
            || !(Duration::from_millis(1)..=Duration::from_secs(30)).contains(&deadline)
        {
            return Err(TlsError::Configuration);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        for root in client_roots {
            roots
                .add(CertificateDer::from(root.to_vec()))
                .map_err(|_| TlsError::Configuration)?;
        }
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|_| TlsError::Configuration)?;
        let key = PrivateKeyDer::try_from(key.to_vec()).map_err(|_| TlsError::Configuration)?;
        let certificates = server_chain
            .iter()
            .map(|der| CertificateDer::from(der.to_vec()))
            .collect();
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| TlsError::Configuration)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)
            .map_err(|_| TlsError::Configuration)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Every connection must freshly verify its client certificate.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            deadline,
        })
    }
    /// Own the socket through a cooperative TLS deadline; errors/cancellation drop it.
    /// Requires a Tokio runtime with I/O and timers enabled.
    /// A successful handshake verifies client credentials, not collector enrollment.
    pub async fn accept(&self, socket: TcpStream) -> Result<TlsStream<TcpStream>, TlsError> {
        timeout(self.deadline, self.acceptor.accept(socket))
            .await
            .map_err(|_| TlsError::Deadline)?
            .map_err(|_| TlsError::Handshake)
    }
}
fn bounded_bundle(bundle: &[&[u8]]) -> bool {
    if bundle.is_empty() || bundle.len() > 8 {
        return false;
    }
    let mut total = 0usize;
    for certificate in bundle {
        if certificate.is_empty() || certificate.len() > 65_536 - total {
            return false;
        }
        total += certificate.len();
    }
    true
}
