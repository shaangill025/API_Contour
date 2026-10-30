//! Fixed-target HTTP/1 application-stream observer.
use crate::CollectorTls;
use bytes::Bytes;
use contour_core::{CaptureScope, RecordMetadata, Timestamp};
use contour_delivery::{CollectorPool, PoolCapture};
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response,
    body::{Body, Frame, Incoming},
    client::conn::http1,
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
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsConnector;

type ForwardBody = UnsyncBoxBody<Bytes, hyper::Error>;

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
    upstream: SocketAddr,
    upstream_name: String,
    upstream_tls: TlsConnector,
    authority: HeaderValue,
    point: Arc<CapturePoint>,
    pool: Arc<CollectorPool>,
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
            upstream,
            upstream_name: upstream_name.to_owned(),
            upstream_tls: TlsConnector::from(Arc::new(config)),
            authority,
            point: Arc::new(point),
            pool,
            connections: Arc::new(Semaphore::new(64)),
        }))
    }
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<(), &'static str> {
        loop {
            let (socket, _) = listener.accept().await.map_err(|_| "accept failed")?;
            let Ok(permit) = self.connections.clone().try_acquire_owned() else {
                drop(socket);
                continue;
            };
            let gateway = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(stream) = gateway.tls.accept(socket).await else {
                    return;
                };
                if !peer_matches(stream.get_ref().1.peer_certificates(), &gateway.peer_leaf)
                    || stream
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
        parts.uri = path.parse().map_err(|_| ())?;
        let eligible = prepare_request_capture(&mut parts.headers) && eligible;
        parts.headers.insert(header::HOST, self.authority.clone());
        let req_capture = if eligible {
            Capture::begin(self.pool.clone(), self.point.clone(), "request", None)
        } else {
            None
        };
        let body = ObservedBody::new(incoming, req_capture, None).boxed_unsync();
        let request = Request::from_parts(parts, body);
        let work = async {
            let socket = TcpStream::connect(self.upstream).await.map_err(|_| ())?;
            let stream = self
                .upstream_tls
                .connect(
                    ServerName::try_from(self.upstream_name.clone()).map_err(|_| ())?,
                    socket,
                )
                .await
                .map_err(|_| ())?;
            let cert = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .ok_or(())?;
            if !exact_dns_san(cert, &self.upstream_name) {
                return Err(());
            }
            if stream
                .get_ref()
                .1
                .alpn_protocol()
                .is_some_and(|a| a != b"http/1.1")
            {
                return Err(());
            }
            let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|_| ())?;
            let driver = AbortTask(tokio::spawn(async move {
                let _ = connection.await;
            }));
            match sender.send_request(request).await {
                Ok(response) => Ok((response, driver)),
                Err(_) => Err(()),
            }
        };
        let (response, driver) = timeout(Duration::from_secs(15), work)
            .await
            .map_err(|_| ())??;
        let (mut parts, incoming) = response.into_parts();
        let response_eligible = prepare_response_capture(&mut parts.headers);
        let capture = if eligible && response_eligible {
            Capture::begin(
                self.pool.clone(),
                self.point.clone(),
                "response",
                Some(parts.status.as_u16()),
            )
        } else {
            None
        };
        Ok(Response::from_parts(
            parts,
            ObservedBody::new(incoming, capture, Some(driver)).boxed_unsync(),
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
fn strip_hop(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| HeaderName::from_bytes(v.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
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
    pool: Arc<CollectorPool>,
    point: Arc<CapturePoint>,
    token: Option<PoolCapture>,
    id: String,
    first: Timestamp,
    direction: &'static str,
    status: Option<u16>,
}
impl Capture {
    fn begin(
        pool: Arc<CollectorPool>,
        point: Arc<CapturePoint>,
        direction: &'static str,
        status: Option<u16>,
    ) -> Option<Self> {
        let first = stamp()?;
        let id = uuid()?;
        let token = pool.try_begin(&point.scope()).ok()?;
        Some(Self {
            pool,
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
            self.pool.try_cancel(token);
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
        let _ = self.pool.try_finish(token, metadata);
    }
    fn cancel(&mut self) {
        if let Some(token) = self.token.take() {
            self.pool.try_cancel(token);
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
}
impl<B> ObservedBody<B> {
    fn new(inner: B, capture: Option<Capture>, driver: Option<AbortTask>) -> Self {
        Self {
            inner,
            capture,
            driver,
        }
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
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(capture) = self.capture.as_mut() {
                    if let Some(data) = frame.data_ref() {
                        if capture
                            .token
                            .is_some_and(|token| capture.pool.try_fragment(token, data).is_err())
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
