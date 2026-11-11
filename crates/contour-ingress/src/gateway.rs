//! Fixed-target HTTP/1 application-stream observer.
use crate::CollectorTls;
mod upstream;
use bytes::Bytes;
use contour_core::{CaptureScope, OriginWitness, RecordMetadata, Timestamp};
use contour_delivery::{AdapterCapture, CollectorPool, StructuralAdapter};
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response,
    body::{Body, Frame, Incoming},
    header::{self, HeaderMap, HeaderName, HeaderValue},
    server::conn::http1 as server_http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use std::{
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinHandle, time::timeout};
use tokio_rustls::TlsConnector;
use upstream::Upstream;

type ForwardBody = UnsyncBoxBody<Bytes, hyper::Error>;

#[derive(Clone, Copy)]
enum Rejection {
    UpstreamCertificate,
    ForwarderMissingCertificate,
    ForwarderLeaf,
}
fn report_rejection(event: Rejection) {
    static SEEN: [AtomicBool; 3] = [const { AtomicBool::new(false) }; 3];
    let (slot, name) = match event {
        Rejection::UpstreamCertificate => (0, "upstream_certificate_rejected"),
        Rejection::ForwarderMissingCertificate => (1, "forwarder_certificate_missing"),
        Rejection::ForwarderLeaf => (2, "forwarder_leaf_rejected"),
    };
    // Bounded to three closed, data-free events per process; no error objects,
    // addresses, names, identifiers, headers or payloads enter diagnostics.
    if !SEEN[slot].swap(true, Ordering::Relaxed) {
        eprintln!("apicontour_native_gateway: {name}");
    }
}
fn certificate_failure(error: &std::io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::InvalidCertificate(_))
    )
}

#[derive(Clone)]
pub struct CapturePoint {
    pub source: String,
    pub workload: [String; 4],
    pub profile: String,
    pub method: String,
    pub path: String,
    pub route: String,
}
impl CapturePoint {
    fn scope(&self) -> CaptureScope<'_> {
        CaptureScope {
            source_id: &self.source,
            workload: self.workload.each_ref().map(String::as_str),
            parser_profile: &self.profile,
            operation: &self.method,
            route_template: &self.route,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        }
    }
}

pub struct Gateway {
    tls: CollectorTls,
    peer_leaf: Vec<u8>,
    upstream: Upstream,
    authority: HeaderValue,
    point: Arc<CapturePoint>,
    adapter: Arc<StructuralAdapter>,
    connections: Arc<Semaphore>,
}
/// Operator-provided transport configuration. Peer and upstream identities are
/// independently authenticated and never derived from request headers.
pub struct GatewayTransport<'a> {
    pub tls: CollectorTls,
    pub peer_leaf: &'a [u8],
    pub upstream: SocketAddr,
    pub upstream_name: &'a str,
    pub upstream_ca: &'a [u8],
    pub client_chain: &'a [u8],
    pub client_key: &'a [u8],
}
impl Gateway {
    pub fn new(
        transport: GatewayTransport<'_>,
        point: CapturePoint,
        pool: Arc<CollectorPool>,
    ) -> Result<Arc<Self>, &'static str> {
        let GatewayTransport {
            tls,
            peer_leaf,
            upstream,
            upstream_name,
            upstream_ca,
            client_chain,
            client_key,
        } = transport;
        if peer_leaf.is_empty()
            || peer_leaf.len() > 65536
            || upstream.port() == 0
            || upstream_ca.is_empty()
            || upstream_ca.len() > 65536
            || !valid_point(&point)
        {
            return Err("invalid gateway configuration");
        }
        let name =
            ServerName::try_from(upstream_name.to_owned()).map_err(|_| "invalid upstream name")?;
        if !matches!(name, ServerName::DnsName(_)) {
            return Err("upstream must use a DNS SAN");
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(upstream_ca.to_vec()))
            .map_err(|_| "invalid upstream CA")?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| "TLS configuration")?
            .with_root_certificates(roots);
        let mut config = if client_chain.is_empty() && client_key.is_empty() {
            builder.with_no_client_auth()
        } else {
            if client_chain.is_empty()
                || client_chain.len() > 65536
                || client_key.is_empty()
                || client_key.len() > 16384
            {
                return Err("invalid upstream identity");
            }
            builder
                .with_client_auth_cert(
                    vec![CertificateDer::from(client_chain.to_vec())],
                    PrivateKeyDer::try_from(client_key.to_vec())
                        .map_err(|_| "invalid upstream key")?,
                )
                .map_err(|_| "invalid upstream identity")?
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        let authority = HeaderValue::from_str(&format!("{}:{}", upstream_name, upstream.port()))
            .map_err(|_| "invalid upstream authority")?;
        Ok(Arc::new(Self {
            tls,
            peer_leaf: peer_leaf.to_vec(),
            upstream: Upstream::new(
                upstream,
                upstream_name.to_owned(),
                TlsConnector::from(Arc::new(config)),
            ),
            authority,
            point: Arc::new(point),
            adapter: StructuralAdapter::attach(pool).map_err(|_| "adapter unavailable")?,
            connections: Arc::new(Semaphore::new(64)),
        }))
    }
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<(), &'static str> {
        loop {
            let (socket, _) = listener.accept().await.map_err(|_| "accept failed")?;
            if socket.set_nodelay(true).is_err() {
                continue;
            }
            let Ok(permit) = self.connections.clone().try_acquire_owned() else {
                drop(socket);
                continue;
            };
            let gateway = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(stream) = gateway
                    .tls
                    .accept_observed(socket, || {
                        report_rejection(Rejection::ForwarderMissingCertificate);
                    })
                    .await
                else {
                    return;
                };
                if !peer_matches(stream.get_ref().1.peer_certificates(), &gateway.peer_leaf) {
                    report_rejection(Rejection::ForwarderLeaf);
                    return;
                }
                if stream
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .is_some_and(|a| a != b"http/1.1")
                {
                    return;
                }
                let service = service_fn(move |request| {
                    let g = gateway.clone();
                    async move { Ok::<_, Infallible>(g.forward(request).await) }
                });
                let mut builder = server_http1::Builder::new();
                builder.max_headers(64).max_buf_size(32768);
                // This whole-connection deadline includes all request and
                // response body reads, not only the upstream response headers.
                // Dropping the connection also drops body capture guards and
                // the owned upstream driver.
                let _ = connection_deadline(
                    builder.serve_connection(TokioIo::new(stream), service),
                    Duration::from_secs(30),
                )
                .await;
            });
        }
    }
    async fn forward(self: Arc<Self>, request: Request<Incoming>) -> Response<ForwardBody> {
        match self.try_forward(request).await {
            Ok(response) => response,
            Err(()) => Response::builder()
                .status(502)
                .body(
                    Empty::<Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .expect("static response"),
        }
    }
    async fn try_forward(
        self: Arc<Self>,
        request: Request<Incoming>,
    ) -> Result<Response<ForwardBody>, ()> {
        let (mut parts, incoming) = request.into_parts();
        // The trusted pinned forwarder owns this header. Remove it before any
        // forwarding decisions, even for unmatched and malformed requests.
        let witness = take_origin_witness(&mut parts.headers);
        // Fixed path matching is used only for observation; all request targets go
        // to the configured socket and never select the upstream destination.
        let eligible = parts.method.as_str() == self.point.method
            && parts.uri.path() == self.point.path
            && parts.uri.query().is_none();
        if parts.method == hyper::Method::CONNECT || parts.uri.path().is_empty() {
            return Err(());
        }
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        parts.uri = format!(
            "http://{}{}",
            self.authority.to_str().map_err(|_| ())?,
            path
        )
        .parse()
        .map_err(|_| ())?;
        let trailer_nominated = strict_connection_nominated(&parts.headers);
        let eligible = prepare_request_capture(&mut parts.headers) && eligible;
        parts.headers.insert(header::HOST, self.authority.clone());
        let req_capture = if eligible {
            Capture::begin(
                self.adapter.clone(),
                self.point.clone(),
                "request",
                None,
                &witness,
            )
        } else {
            None
        };
        let body =
            ObservedBody::new_request(incoming, req_capture, trailer_nominated).boxed_unsync();
        let request = Request::from_parts(parts, body);
        let response = timeout(Duration::from_secs(15), self.upstream.request(request))
            .await
            .map_err(|_| ())??;
        let (mut parts, incoming) = response.into_parts();
        let response_eligible = prepare_response_capture(&mut parts.headers);
        let capture = if eligible && response_eligible {
            Capture::begin(
                self.adapter.clone(),
                self.point.clone(),
                "response",
                Some(parts.status.as_u16()),
                &witness,
            )
        } else {
            None
        };
        Ok(Response::from_parts(
            parts,
            ObservedBody::new(incoming, capture, None).boxed_unsync(),
        ))
    }
}
async fn connection_deadline<F: Future>(
    future: F,
    limit: Duration,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    timeout(limit, future).await
}
fn peer_matches(certs: Option<&[CertificateDer<'_>]>, expected: &[u8]) -> bool {
    certs
        .and_then(|c| c.first())
        .is_some_and(|leaf| leaf.as_ref() == expected)
}
fn valid_point(point: &CapturePoint) -> bool {
    if point.method.len() > 32
        || point.path.len() > 256
        || point.path != point.route
        || point.path.contains(['?', '#', '{', '}'])
        || !point.path.starts_with('/')
    {
        return false;
    }
    let Ok(method) = hyper::Method::from_bytes(point.method.as_bytes()) else {
        return false;
    };
    if method == hyper::Method::CONNECT {
        return false;
    }
    let Ok(uri) = point.path.parse::<hyper::Uri>() else {
        return false;
    };
    uri.scheme().is_none()
        && uri.authority().is_none()
        && uri.query().is_none()
        && uri
            .path_and_query()
            .is_some_and(|p| p.as_str() == point.path)
}
// This is an additional restriction after rustls has verified the chain and
// hostname. It never substitutes for standard certificate verification.
fn exact_dns_san(cert: &CertificateDer<'_>, expected: &str) -> bool {
    webpki::EndEntityCert::try_from(cert)
        .ok()
        .is_some_and(|cert| {
            cert.valid_dns_names()
                .any(|name| literal_dns_match(name, expected))
        })
}
fn literal_dns_match(name: &str, expected: &str) -> bool {
    !name.contains('*') && !expected.contains('*') && name.eq_ignore_ascii_case(expected)
}
const ORIGIN_WITNESS: &str = "x-contour-origin-witness";

fn take_origin_witness(headers: &mut HeaderMap) -> OriginWitness {
    // A Connection-nominated field is hop-scoped and cannot carry provenance.
    let malformed_connection = headers
        .get_all(header::CONNECTION)
        .iter()
        .any(|v| v.to_str().is_err());
    let nominated = malformed_connection
        || headers
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|v| v.trim().eq_ignore_ascii_case(ORIGIN_WITNESS));
    let mut values = headers.get_all(ORIGIN_WITNESS).iter();
    let candidate = values
        .next()
        .filter(|_| !nominated)
        .filter(|_| values.next().is_none())
        .and_then(|v| {
            let bytes = v.as_bytes();
            (bytes.len() == 64
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)))
            .then(|| String::from_utf8(bytes.to_vec()).expect("ASCII hex"))
        });
    headers.remove(ORIGIN_WITNESS);
    match candidate {
        Some(leaf_sha256) => OriginWitness::DownstreamMtlsLeafSha256V1 { leaf_sha256 },
        None => OriginWitness::Unattributed,
    }
}
fn capture_headers(headers: &HeaderMap) -> bool {
    let encoding_ok = headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .all(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"));
    let mut content_types = headers.get_all(header::CONTENT_TYPE).iter();
    let json = content_types
        .next()
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
        })
        && content_types.next().is_none();
    encoding_ok
        && json
        && !headers.contains_key(header::TRAILER)
        && !headers.contains_key(header::UPGRADE)
}
fn connection_nominated(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| HeaderName::from_bytes(v.trim().as_bytes()).ok())
        .collect()
}
// Request trailer forwarding fails closed if any original or trailer-frame
// Connection field cannot be parsed as a complete list of HTTP field names.
fn strict_connection_nominated(headers: &HeaderMap) -> Option<Vec<HeaderName>> {
    let mut nominated = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        for token in value.to_str().ok()?.split(',') {
            let token = token.trim_matches([' ', '\t']);
            nominated.push(HeaderName::from_bytes(token.as_bytes()).ok()?);
        }
    }
    Some(nominated)
}
fn strip_hop(headers: &mut HeaderMap) {
    for name in connection_nominated(headers) {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}
fn sanitize_request_trailers(trailers: &mut HeaderMap, original: Option<&[HeaderName]>) {
    if let (Some(original), Some(frame)) = (original, strict_connection_nominated(trailers)) {
        for name in original.iter().chain(&frame) {
            trailers.remove(name);
        }
        strip_hop(trailers);
        trailers.remove(ORIGIN_WITNESS);
        trailers.remove("x-forwarded-client-cert");
    } else {
        trailers.clear();
    }
}
// TE is hop-scoped. Recreate only the downstream's trailers capability for the
// new upstream hop so Hyper can relay declared response trailers.
fn prepare_request_headers(headers: &mut HeaderMap) {
    let trailers = headers
        .get_all(header::TE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case("trailers"));
    strip_hop(headers);
    if trailers {
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("TE"));
    }
}
fn prepare_request_capture(headers: &mut HeaderMap) -> bool {
    let original = capture_headers(headers);
    let had_encoding = headers.contains_key(header::CONTENT_ENCODING);
    prepare_request_headers(headers);
    original
        && capture_headers(headers)
        && (!had_encoding || headers.contains_key(header::CONTENT_ENCODING))
}
fn prepare_response_capture(headers: &mut HeaderMap) -> bool {
    let original = capture_headers(headers);
    let had_encoding = headers.contains_key(header::CONTENT_ENCODING);
    strip_hop(headers);
    original
        && capture_headers(headers)
        && (!had_encoding || headers.contains_key(header::CONTENT_ENCODING))
}
struct Capture {
    adapter: Arc<StructuralAdapter>,
    point: Arc<CapturePoint>,
    token: Option<AdapterCapture>,
    id: String,
    first: Timestamp,
    direction: &'static str,
    status: Option<u16>,
}
impl Capture {
    fn begin(
        adapter: Arc<StructuralAdapter>,
        point: Arc<CapturePoint>,
        direction: &'static str,
        status: Option<u16>,
        witness: &OriginWitness,
    ) -> Option<Self> {
        let first = stamp()?;
        let id = uuid()?;
        let token = if adapter.descriptor().origin_v2 {
            adapter.try_begin(&point.scope(), Some(witness))
        } else {
            adapter.try_begin(&point.scope(), None)
        }
        .ok()?;
        Some(Self {
            adapter,
            point,
            token: Some(token),
            id,
            first,
            direction,
            status,
        })
    }
    fn finish(&mut self) {
        let Some(token) = self.token.take() else {
            return;
        };
        let Some(last) = stamp() else {
            self.adapter.try_cancel(token);
            return;
        };
        let p = &self.point;
        let metadata = RecordMetadata {
            record_id: &self.id,
            source_id: &p.source,
            workload: p.workload.each_ref().map(String::as_str),
            protocol: "http",
            direction: self.direction,
            visibility: "structure",
            operation: &p.method,
            route_template: &p.route,
            route_uncertain: false,
            parser_profile: &p.profile,
            policy_revision: 0,
            count: 1,
            first_seen: self.first.clone(),
            last_seen: last,
            sample_numerator: 1,
            sample_denominator: 1,
            status_code: self.status,
            request_header_names: &[],
            response_header_names: &[],
            query_parameter_names: &[],
        };
        let _ = self.adapter.try_finish(token, metadata);
    }
    fn cancel(&mut self) {
        if let Some(token) = self.token.take() {
            self.adapter.try_cancel(token);
        }
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn stamp() -> Option<Timestamp> {
    let s = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .ok()?;
    Timestamp::parse(&s).ok()
}
fn uuid() -> Option<String> {
    let mut b = [0u8; 16];
    SystemRandom::new().fill(&mut b).ok()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}
struct AbortTask(JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct ObservedBody<B> {
    inner: B,
    capture: Option<Capture>,
    driver: Option<AbortTask>,
    strip_request_trailers: bool,
    trailer_nominated: Option<Vec<HeaderName>>,
}
impl<B> ObservedBody<B> {
    fn new(inner: B, capture: Option<Capture>, driver: Option<AbortTask>) -> Self {
        Self {
            inner,
            capture,
            driver,
            strip_request_trailers: false,
            trailer_nominated: Some(Vec::new()),
        }
    }
    fn new_request(inner: B, capture: Option<Capture>, nominated: Option<Vec<HeaderName>>) -> Self {
        let mut body = Self::new(inner, capture, None);
        body.strip_request_trailers = true;
        body.trailer_nominated = nominated;
        body
    }
}
impl<B> Drop for ObservedBody<B> {
    fn drop(&mut self) {
        self.driver.take();
    }
}
impl<B: Body<Data = Bytes, Error = hyper::Error> + Unpin> Body for ObservedBody<B> {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let mut result = Pin::new(&mut self.inner).poll_frame(cx);
        if self.strip_request_trailers {
            if let Poll::Ready(Some(Ok(frame))) = &mut result {
                if let Some(trailers) = frame.trailers_mut() {
                    sanitize_request_trailers(trailers, self.trailer_nominated.as_deref());
                }
            }
        }
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(capture) = self.capture.as_mut() {
                    if let Some(data) = frame.data_ref() {
                        if capture
                            .token
                            .is_some_and(|token| capture.adapter.try_fragment(token, data).is_err())
                        {
                            capture.cancel();
                        }
                    } else {
                        capture.cancel();
                    }
                }
            }
            Poll::Ready(None) => {
                if let Some(capture) = self.capture.as_mut() {
                    capture.finish();
                }
            }
            Poll::Ready(Some(Err(_))) => {
                if let Some(capture) = self.capture.as_mut() {
                    capture.cancel();
                }
            }
            Poll::Pending => {}
        }
        if matches!(&result, Poll::Ready(Some(Ok(frame))) if frame.data_ref().is_some())
            && self.inner.is_end_stream()
        {
            if let Some(capture) = self.capture.as_mut() {
                capture.finish();
            }
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hyper::client::conn::http1;
    #[test]
    fn witness_is_strict_and_always_removed() {
        let canonical = "0123456789abcdef".repeat(4);
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN_WITNESS, HeaderValue::from_str(&canonical).unwrap());
        assert_eq!(
            take_origin_witness(&mut headers),
            OriginWitness::DownstreamMtlsLeafSha256V1 {
                leaf_sha256: canonical.clone()
            }
        );
        assert!(!headers.contains_key(ORIGIN_WITNESS));
        for value in [
            "",
            "-",
            "a",
            &"A".repeat(64),
            &"g".repeat(64),
            &"a".repeat(63),
            &"a".repeat(65),
            &format!("{canonical}, {canonical}"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(ORIGIN_WITNESS, HeaderValue::from_str(value).unwrap());
            assert_eq!(
                take_origin_witness(&mut headers),
                OriginWitness::Unattributed
            );
            assert!(!headers.contains_key(ORIGIN_WITNESS));
        }
        let mut missing = HeaderMap::new();
        assert_eq!(
            take_origin_witness(&mut missing),
            OriginWitness::Unattributed
        );
        let mut duplicate = HeaderMap::new();
        duplicate.append(ORIGIN_WITNESS, HeaderValue::from_str(&canonical).unwrap());
        duplicate.append(ORIGIN_WITNESS, HeaderValue::from_str(&canonical).unwrap());
        assert_eq!(
            take_origin_witness(&mut duplicate),
            OriginWitness::Unattributed
        );
        assert!(!duplicate.contains_key(ORIGIN_WITNESS));
        let mut malformed = HeaderMap::new();
        malformed.insert(ORIGIN_WITNESS, HeaderValue::from_str(&canonical).unwrap());
        malformed.insert(
            header::CONNECTION,
            HeaderValue::from_bytes(b"x-contour-origin-witness,\x80").unwrap(),
        );
        assert_eq!(
            take_origin_witness(&mut malformed),
            OriginWitness::Unattributed
        );
        assert!(!malformed.contains_key(ORIGIN_WITNESS));
        let mut nominated = HeaderMap::new();
        nominated.insert(ORIGIN_WITNESS, HeaderValue::from_str(&canonical).unwrap());
        nominated.append(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        nominated.append(
            header::CONNECTION,
            HeaderValue::from_static("X-Contour-Origin-Witness"),
        );
        assert_eq!(
            take_origin_witness(&mut nominated),
            OriginWitness::Unattributed
        );
        prepare_request_headers(&mut nominated);
        assert!(!nominated.contains_key(ORIGIN_WITNESS));
    }
    #[test]
    fn witness_removal_preserves_application_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN_WITNESS, HeaderValue::from_static("invalid"));
        headers.insert("x-application", HeaderValue::from_static("kept"));
        assert_eq!(
            take_origin_witness(&mut headers),
            OriginWitness::Unattributed
        );
        prepare_request_capture(&mut headers);
        assert!(!headers.contains_key(ORIGIN_WITNESS));
        assert_eq!(headers["x-application"], "kept");
    }
    #[test]
    fn configured_scope_is_one_literal_method_and_path() {
        let mut point = CapturePoint {
            source: String::new(),
            workload: Default::default(),
            profile: String::new(),
            method: "POST".into(),
            path: "/pilot".into(),
            route: "/pilot".into(),
        };
        assert!(valid_point(&point));
        point.route = "/another".into();
        assert!(!valid_point(&point));
        point.path = "/orders/{id}".into();
        point.route = point.path.clone();
        assert!(!valid_point(&point));
        point.path = "/pilot?x=1".into();
        point.route = point.path.clone();
        assert!(!valid_point(&point));
        point.path = "/pilot".into();
        point.route = point.path.clone();
        point.method = "CONNECT".into();
        assert!(!valid_point(&point));
        point.method = "bad method".into();
        assert!(!valid_point(&point));
    }
    #[test]
    fn connection_deadline_drops_stalled_body_owner() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Held(Arc<AtomicBool>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let owned = dropped.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let work = async move {
                let _body_owner = Held(owned);
                std::future::pending::<()>().await;
            };
            assert!(
                connection_deadline(work, Duration::from_millis(5))
                    .await
                    .is_err()
            );
        });
        assert!(dropped.load(Ordering::SeqCst));
    }
    #[test]
    fn http1_forwards_chunked_body_and_declared_trailers() {
        use std::collections::VecDeque;
        struct Frames(VecDeque<Frame<Bytes>>);
        impl Body for Frames {
            type Data = Bytes;
            type Error = Infallible;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
                Poll::Ready(self.0.pop_front().map(Ok))
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            timeout(Duration::from_secs(1), async {
                let (client_io, server_io) = tokio::io::duplex(8192);
                let service = service_fn(|request: Request<Incoming>| async move {
                    let (mut parts, body) = request.into_parts();
                    prepare_request_headers(&mut parts.headers);
                    assert_eq!(parts.headers[header::TE], "trailers");
                    let trailer = parts.headers.get(header::TRAILER).cloned().unwrap();
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header(header::TRAILER, trailer)
                            .body(ObservedBody::new(body, None, None))
                            .unwrap(),
                    )
                });
                let server = tokio::spawn(async move {
                    server_http1::Builder::new()
                        .serve_connection(TokioIo::new(server_io), service)
                        .await
                        .unwrap()
                });
                let (mut sender, connection) =
                    http1::handshake(TokioIo::new(client_io)).await.unwrap();
                let driver = tokio::spawn(async move { connection.await.unwrap() });
                let mut trailers = HeaderMap::new();
                trailers.insert("x-check", HeaderValue::from_static("end"));
                let body = Frames(VecDeque::from([
                    Frame::data(Bytes::from_static(b"body")),
                    Frame::trailers(trailers),
                ]));
                let request = Request::builder()
                    .method("POST")
                    .uri("/pilot")
                    .header(header::HOST, "fixture")
                    .header(header::TE, "trailers")
                    .header(header::CONNECTION, "TE")
                    .header(header::TRAILER, "x-check")
                    .body(body)
                    .unwrap();
                let response = sender.send_request(request).await.unwrap();
                assert_eq!(response.headers()[header::TRAILER], "x-check");
                let mut body = response.into_body();
                let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
                assert_eq!(first, "body");
                let last = body
                    .frame()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_trailers()
                    .unwrap();
                assert_eq!(last["x-check"], "end");
                assert!(body.frame().await.is_none());
                drop(sender);
                driver.abort();
                server.abort();
            })
            .await
            .unwrap();
        });
    }
    #[test]
    fn certificate_diagnostic_excludes_transport_and_generic_tls_failure() {
        assert!(!certificate_failure(&std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused
        )));
        assert!(!certificate_failure(&std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::General("synthetic".into())
        )));
        assert!(certificate_failure(&std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        )));
    }
    #[test]
    fn forwards_original_data_and_trailers_when_capture_is_absent() {
        use std::collections::VecDeque;
        struct Frames(VecDeque<Frame<Bytes>>);
        impl Body for Frames {
            type Data = Bytes;
            type Error = hyper::Error;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
                Poll::Ready(self.0.pop_front().map(Ok))
            }
        }
        let bytes = Bytes::from_static(b"sentinel application body");
        let pointer = bytes.as_ptr();
        let mut trailers = HeaderMap::new();
        trailers.insert("x-check", HeaderValue::from_static("end"));
        let frames = Frames(VecDeque::from([
            Frame::data(bytes),
            Frame::trailers(trailers),
        ]));
        let mut observed = ObservedBody::new(frames, None, None);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Some(Ok(first))) = Pin::new(&mut observed).poll_frame(&mut cx) else {
            panic!("missing body")
        };
        assert_eq!(first.data_ref().unwrap().as_ptr(), pointer);
        let Poll::Ready(Some(Ok(last))) = Pin::new(&mut observed).poll_frame(&mut cx) else {
            panic!("missing trailers")
        };
        assert_eq!(last.trailers_ref().unwrap()["x-check"], "end");
        assert!(matches!(
            Pin::new(&mut observed).poll_frame(&mut cx),
            Poll::Ready(None)
        ));
    }
    #[test]
    fn request_trailers_strip_witness_without_capture() {
        use std::collections::VecDeque;
        struct Frames(VecDeque<Frame<Bytes>>);
        impl Body for Frames {
            type Data = Bytes;
            type Error = hyper::Error;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
                Poll::Ready(self.0.pop_front().map(Ok))
            }
        }
        let mut trailers = HeaderMap::new();
        trailers.append(ORIGIN_WITNESS, HeaderValue::from_static("forged"));
        trailers.append(ORIGIN_WITNESS, HeaderValue::from_static("duplicate"));
        trailers.insert(
            "x-forwarded-client-cert",
            HeaderValue::from_static("forged"),
        );
        trailers.append(
            "x-forwarded-client-cert",
            HeaderValue::from_static("duplicate"),
        );
        trailers.insert("x-hop", HeaderValue::from_static("removed"));
        trailers.insert(header::CONNECTION, HeaderValue::from_static("x-frame-hop"));
        trailers.insert("x-frame-hop", HeaderValue::from_static("removed"));
        trailers.insert("proxy-authorization", HeaderValue::from_static("removed"));
        trailers.insert("x-application", HeaderValue::from_static("kept"));
        let mut headers = HeaderMap::new();
        headers.append(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.append(header::CONNECTION, HeaderValue::from_static("X-Hop"));
        let nominated = strict_connection_nominated(&headers);
        let mut body = ObservedBody::new_request(
            Frames(VecDeque::from([Frame::trailers(trailers)])),
            None,
            nominated,
        );
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("missing trailers")
        };
        let trailers = frame.into_trailers().unwrap();
        assert!(!trailers.contains_key(ORIGIN_WITNESS));
        assert!(!trailers.contains_key("x-forwarded-client-cert"));
        assert!(!trailers.contains_key("x-hop"));
        assert!(!trailers.contains_key(header::CONNECTION));
        assert!(!trailers.contains_key("x-frame-hop"));
        assert!(!trailers.contains_key("proxy-authorization"));
        assert_eq!(trailers["x-application"], "kept");
    }
    #[test]
    fn malformed_connection_values_reject_request_trailers() {
        for raw in [&b"x-hop,\x80"[..], &b"x-hop, bad token"[..], &b"x-hop,"[..]] {
            let mut headers = HeaderMap::new();
            headers.append(header::CONNECTION, HeaderValue::from_static("x-valid"));
            headers.append(header::CONNECTION, HeaderValue::from_bytes(raw).unwrap());
            assert!(strict_connection_nominated(&headers).is_none());
        }
        let mut frame = HeaderMap::new();
        frame.insert(
            header::CONNECTION,
            HeaderValue::from_bytes(b"x-hop,\x80").unwrap(),
        );
        frame.insert("x-hop", HeaderValue::from_static("private"));
        assert!(strict_connection_nominated(&frame).is_none());
        sanitize_request_trailers(&mut frame, Some(&[]));
        assert!(frame.is_empty());
        let mut frame = HeaderMap::new();
        frame.insert("x-hop", HeaderValue::from_static("private"));
        sanitize_request_trailers(&mut frame, None);
        assert!(frame.is_empty());
    }
    #[test]
    fn hop_headers_remove_nominated_fields() {
        let mut h = HeaderMap::new();
        h.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        h.insert("x-secret", HeaderValue::from_static("x"));
        h.insert("keep-alive", HeaderValue::from_static("x"));
        h.insert("x-end", HeaderValue::from_static("y"));
        strip_hop(&mut h);
        assert!(!h.contains_key("x-secret"));
        assert!(!h.contains_key("keep-alive"));
        assert_eq!(h["x-end"], "y");
    }
    #[test]
    fn capture_rejects_encodings_and_trailers() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(capture_headers(&h));
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(!capture_headers(&h));
        h.remove(header::CONTENT_ENCODING);
        h.insert(header::TRAILER, HeaderValue::from_static("x-test"));
        assert!(!capture_headers(&h));
    }
    #[test]
    fn capture_rejects_original_or_stripped_unsafe_header_cases() {
        for request in [true, false] {
            let mut valid = HeaderMap::new();
            valid.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            assert!(if request {
                prepare_request_capture(&mut valid)
            } else {
                prepare_response_capture(&mut valid)
            });
            for (name, value) in [
                ("content-type", "application/json"),
                ("content-encoding", "gzip"),
                ("content-encoding", "identity"),
                ("trailer", "x-check"),
                ("upgrade", "websocket"),
            ] {
                let mut h = HeaderMap::new();
                h.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                h.insert(
                    HeaderName::from_static(name),
                    HeaderValue::from_str(value).unwrap(),
                );
                h.append(header::CONNECTION, HeaderValue::from_static("keep-alive"));
                h.append(
                    header::CONNECTION,
                    HeaderValue::from_str(&format!("x-unused, {name}")).unwrap(),
                );
                let eligible = if request {
                    prepare_request_capture(&mut h)
                } else {
                    prepare_response_capture(&mut h)
                };
                assert!(!eligible, "{name} must not permit capture on either hop");
            }
        }
    }
    #[test]
    fn pin_matches_only_leaf() {
        let a = CertificateDer::from(vec![1]);
        let b = CertificateDer::from(vec![2]);
        assert!(peer_matches(Some(&[a.clone(), b.clone()]), &[1]));
        assert!(!peer_matches(Some(&[a, b]), &[2]));
        assert!(!peer_matches(None, &[1]));
    }
    #[test]
    fn exact_san_rejects_wildcards_and_wrong_names() {
        assert!(literal_dns_match(
            "fixture.example.test",
            "FIXTURE.EXAMPLE.TEST"
        ));
        assert!(!literal_dns_match("*.example.test", "fixture.example.test"));
        assert!(!literal_dns_match(
            "other.example.test",
            "fixture.example.test"
        ));
        assert!(!exact_dns_san(
            &CertificateDer::from(vec![1, 2, 3]),
            "fixture.example.test"
        ));
        let exact = CertificateDer::from(include_bytes!("gateway_testdata/exact.der").as_slice());
        let wildcard =
            CertificateDer::from(include_bytes!("gateway_testdata/wildcard.der").as_slice());
        assert!(exact_dns_san(&exact, "FIXTURE.EXAMPLE.TEST"));
        assert!(!exact_dns_san(&exact, "other.example.test"));
        assert!(!exact_dns_san(&wildcard, "fixture.example.test"));
    }
}
