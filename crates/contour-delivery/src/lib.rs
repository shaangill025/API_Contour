//! One owned authenticated attempt; no scheduler, enrollment or policy renewal.
use bytes::Bytes;
use contour_core::{Acknowledgement, DeliveryBinding, DeliveryReservation, QueueError, Timestamp};
use http_body_util::{BodyExt, Full};
use hyper::{Request, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use serde::Deserialize;
use std::{
    fmt,
    future::{Future, poll_fn},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use time::OffsetDateTime;
use tokio::{
    net::TcpStream,
    time::{Instant, timeout_at},
};
use tokio_rustls::TlsConnector;
mod retry;
pub use retry::{RetryController, RetryDirective, RetryError, WaitOutcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryError {
    Configuration,
    Deadline,
    Transport,
    Receipt,
    ResponseLimit,
    Rejected {
        status: u16,
        retry_after: Option<Duration>,
    },
}
impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DeliveryError {}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Accepted,
    Duplicate,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReceipt {
    batch_id: String,
    status: ReceiptStatus,
    receipt_id: String,
    accepted_at: Timestamp,
}
/// Created only from a complete checked 200 on the configured verified TLS session.
/// Local routing fields originate from the attempt, never receipt JSON.
pub struct CheckedReceipt {
    receipt: WireReceipt,
    identity: [String; 2],
    binding: DeliveryBinding,
    digest: [u8; 32],
}
impl fmt::Debug for CheckedReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckedReceipt")
    }
}
impl CheckedReceipt {
    pub fn status(&self) -> ReceiptStatus {
        self.receipt.status
    }
    pub fn receipt_id(&self) -> &str {
        &self.receipt.receipt_id
    }
    pub fn accepted_at(&self) -> &Timestamp {
        &self.receipt.accepted_at
    }
    /// Network/body owners have been dropped before this value is returned.
    pub fn acknowledge(self, attempt: DeliveryReservation<'_>) -> Result<(), QueueError> {
        attempt.acknowledge(Acknowledgement::from_transport(
            self.binding,
            [&self.identity[0], &self.identity[1]],
            &self.receipt.batch_id,
            &self.digest,
            &self.receipt.receipt_id,
            &self.receipt.accepted_at,
        )?)
    }
}
/// Immutable operator endpoint and credentials; not request supplied enrollment.
pub struct DeliveryClient {
    host: String,
    address: SocketAddr,
    identity: [String; 2],
    tls: TlsConnector,
    deadline: Duration,
}
impl fmt::Debug for DeliveryClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeliveryClient")
    }
}
impl DeliveryClient {
    /// Fixed operator-resolved socket and verified TLS name, no URI/options; each DER bundle 1–8 certs/64KiB,
    /// DER key 1–16KiB; cooperative attempt deadline 1ms–30s. No system roots.
    pub fn from_der(
        host: &str,
        address: SocketAddr,
        identity: [&str; 2],
        roots: &[&[u8]],
        chain: &[&[u8]],
        key: &[u8],
        deadline: Duration,
    ) -> Result<Self, DeliveryError> {
        if !host_valid(host)
            || address.port() == 0
            || identity.iter().any(|id| !uuid(id))
            || !bundle(roots)
            || !bundle(chain)
            || key.is_empty()
            || key.len() > 16384
            || !(Duration::from_millis(1)..=Duration::from_secs(30)).contains(&deadline)
        {
            return Err(DeliveryError::Configuration);
        }
        let mut trust = RootCertStore::empty();
        for root in roots {
            trust
                .add(CertificateDer::from(root.to_vec()))
                .map_err(|_| DeliveryError::Configuration)?;
        }
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|_| DeliveryError::Configuration)?
                .with_root_certificates(trust)
                .with_client_auth_cert(
                    chain
                        .iter()
                        .map(|c| CertificateDer::from(c.to_vec()))
                        .collect(),
                    PrivateKeyDer::try_from(key.to_vec())
                        .map_err(|_| DeliveryError::Configuration)?,
                )
                .map_err(|_| DeliveryError::Configuration)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        Ok(Self {
            host: host.to_owned(),
            address,
            identity: identity.map(str::to_owned),
            tls: TlsConnector::from(Arc::new(config)),
            deadline,
        })
    }
    /// Exclusive attempt borrow prevents concurrent request copies. Every body,
    /// socket and HTTP driver stays local; dropping this future drops all owners.
    /// Lease conversion depends on the operator-trusted wall clock sampled here.
    /// Caller must cancel I/O on a trusted policy update before reconciling queue.
    pub async fn send_once(
        &mut self,
        attempt: &mut DeliveryReservation<'_>,
    ) -> Result<CheckedReceipt, DeliveryError> {
        let started = Instant::now();
        let now = OffsetDateTime::now_utc();
        if attempt.identity() != self.identity.each_ref().map(String::as_str) {
            return Err(DeliveryError::Configuration);
        }
        let valid_until = attempt.valid_until();
        let view = attempt.view();
        let remaining = valid_until - now;
        if remaining <= time::Duration::ZERO {
            return Err(DeliveryError::Deadline);
        }
        let limit = Duration::try_from(remaining)
            .map_err(|_| DeliveryError::Deadline)?
            .min(self.deadline);
        let deadline = started + limit;
        let work = async {
            let socket = TcpStream::connect(self.address)
                .await
                .map_err(|_| DeliveryError::Transport)?;
            let stream = self
                .tls
                .connect(
                    ServerName::try_from(self.host.clone())
                        .map_err(|_| DeliveryError::Configuration)?,
                    socket,
                )
                .await
                .map_err(|_| DeliveryError::Transport)?;
            if stream.get_ref().1.alpn_protocol() != Some(b"http/1.1".as_slice()) {
                return Err(DeliveryError::Transport);
            }
            let mut builder = http1::Builder::new();
            builder
                .max_headers(32)
                .max_header_size(16384)
                .max_buf_size(16384);
            let (mut sender, connection) = builder
                .handshake(TokioIo::new(stream))
                .await
                .map_err(|_| DeliveryError::Transport)?;
            let authority = if self.host.contains(':') {
                format!("[{}]:{}", self.host, self.address.port())
            } else {
                format!("{}:{}", self.host, self.address.port())
            };
            // Exactly one bounded transport copy; immutable frozen source stays charged.
            let request = Request::post("/v1/batches")
                .header("Host", authority)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Connection", "close")
                .body(Full::new(Bytes::copy_from_slice(view.wire())))
                .map_err(|_| DeliveryError::Configuration)?;
            let mut driver = Driver {
                future: Box::pin(connection),
                done: false,
            };
            let response = driver
                .step(sender.send_request(request))
                .await?
                .map_err(|_| DeliveryError::Transport)?;
            let status = response.status().as_u16();
            let headers = response.headers();
            if status != 200 {
                return Err(DeliveryError::Rejected {
                    status,
                    retry_after: retry_after(headers),
                });
            }
            if headers.get("content-type").and_then(|v| v.to_str().ok()) != Some("application/json")
                || headers.contains_key("content-encoding")
            {
                return Err(DeliveryError::Receipt);
            }
            let mut body = response.into_body();
            let mut bytes = Vec::with_capacity(4096);
            while let Some(frame) = driver.step(body.frame()).await? {
                let frame = frame.map_err(|_| DeliveryError::Transport)?;
                let data = frame.into_data().map_err(|_| DeliveryError::Receipt)?;
                if data.len() > 4096 - bytes.len() {
                    return Err(DeliveryError::ResponseLimit);
                }
                bytes.extend_from_slice(&data);
            }
            let receipt: WireReceipt =
                serde_json::from_slice(&bytes).map_err(|_| DeliveryError::Receipt)?;
            if receipt.batch_id != view.batch_id()
                || !uuid(&receipt.batch_id)
                || !uuid(&receipt.receipt_id)
            {
                return Err(DeliveryError::Receipt);
            }
            Ok(CheckedReceipt {
                receipt,
                identity: self.identity.clone(),
                binding: view.binding(),
                digest: *view.digest(),
            })
        };
        let result = timeout_at(deadline, work)
            .await
            .map_err(|_| DeliveryError::Deadline)?;
        // A ready inner future can win timeout polling after descheduling.
        if Instant::now() >= deadline {
            return Err(DeliveryError::Deadline);
        }
        result
    }
}
struct Driver<F> {
    future: Pin<Box<F>>,
    done: bool,
}
impl<F: Future<Output = Result<(), hyper::Error>>> Driver<F> {
    async fn step<T>(&mut self, next: impl Future<Output = T>) -> Result<T, DeliveryError> {
        let mut next = std::pin::pin!(next);
        poll_fn(|cx| {
            if let Poll::Ready(value) = next.as_mut().poll(cx) {
                return Poll::Ready(Ok(value));
            }
            if !self.done {
                if let Poll::Ready(result) = self.future.as_mut().poll(cx) {
                    self.done = true;
                    if result.is_err() {
                        return Poll::Ready(Err(DeliveryError::Transport));
                    }
                }
            }
            next.as_mut().poll(cx).map(Ok)
        })
        .await
    }
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn bundle(items: &[&[u8]]) -> bool {
    !items.is_empty()
        && items.len() <= 8
        && items
            .iter()
            .try_fold(0usize, |n, c| {
                if c.is_empty() {
                    None
                } else {
                    n.checked_add(c.len()).filter(|n| *n <= 65536)
                }
            })
            .is_some()
}
fn host_valid(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
        && (host.parse::<IpAddr>().is_ok()
            || host.split('.').all(|s| {
                !s.is_empty()
                    && s.len() <= 63
                    && s.as_bytes()[0].is_ascii_alphanumeric()
                    && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
}

// Status decisions never depend on error body, content type or attacker-supplied logs.
fn retry_after(headers: &hyper::HeaderMap) -> Option<Duration> {
    let mut values = headers.get_all("retry-after").iter();
    let value = values.next()?;
    if values.next().is_some() || value.as_bytes().len() > 128 {
        return None;
    }
    let text = value.to_str().ok()?.trim_matches([' ', '\t']);
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        let seconds = text
            .bytes()
            .fold(0u64, |n, b| (n * 10 + u64::from(b - b'0')).min(300));
        return Some(Duration::from_secs(seconds));
    }
    let date = httpdate::parse_http_date(text).ok()?;
    Some(
        date.duration_since(std::time::SystemTime::now())
            .unwrap_or(Duration::ZERO)
            .min(Duration::from_secs(300)),
    )
}
