//! Separate, operator-selected causal ingestion. An mTLS leaf and a committed
//! session are enrollment inputs; neither attests which producer code ran.
use crate::{
    CollectorTls,
    pool::{DatabaseCapacity, DatabasePool},
    service::{HttpLimits, IngressError, Reply, error, reply, request_id},
};
use bytes::Bytes;
use contour_core::{CausalEventBatch, CausalGrantKeys, MAX_CAUSAL_EVENT_BATCH_BYTES, PolicyKeys};
use contour_postgres::{CausalError, CausalSession, DatabaseSettings, TrustedCa};
use http_body_util::BodyExt;
use hyper::{Request, StatusCode, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    future::{Future, poll_fn},
    sync::Arc,
    task::Poll,
    time::Duration,
};
use time::format_description::well_known::Rfc3339;
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{Instant, timeout_at},
};

/// Trusted configuration mapping a verified TLS leaf pin to a committed session.
/// It does not attest the executable, flow, or artifact that used the key.
pub struct CausalRegistry(Vec<([u8; 32], Arc<CausalSession>)>);
impl fmt::Debug for CausalRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalRegistry")
    }
}
impl CausalRegistry {
    pub fn new(bindings: Vec<([u8; 32], CausalSession)>) -> Result<Self, IngressError> {
        if bindings.is_empty()
            || bindings.len() > 128
            || bindings.iter().enumerate().any(|(i, (pin, session))| {
                !session.matches_peer(pin) || bindings[..i].iter().any(|(prior, _)| prior == pin)
            })
        {
            return Err(IngressError::Configuration);
        }
        Ok(Self(
            bindings
                .into_iter()
                .map(|(pin, session)| (pin, Arc::new(session)))
                .collect(),
        ))
    }
    fn lookup(&self, leaf: &[u8]) -> Option<([u8; 32], Arc<CausalSession>)> {
        let pin: [u8; 32] = Sha256::digest(leaf).into();
        self.0
            .iter()
            .find(|(p, _)| *p == pin)
            .map(|(_, s)| (pin, s.clone()))
    }
}
struct State {
    tls: CollectorTls,
    registry: CausalRegistry,
    database: DatabasePool,
    grant_keys: Arc<CausalGrantKeys>,
}
/// Owns bounded mTLS/HTTP tasks and causal-only role-checked database jobs.
pub struct CausalServer {
    state: Arc<State>,
    limits: HttpLimits,
}
impl fmt::Debug for CausalServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CausalServer")
    }
}
impl CausalServer {
    pub fn new(
        tls: CollectorTls,
        registry: CausalRegistry,
        database: DatabaseSettings,
        trust: TrustedCa,
        grant_keys: CausalGrantKeys,
        policy_keys: PolicyKeys,
        limits: HttpLimits,
    ) -> Self {
        Self {
            state: Arc::new(State {
                tls,
                registry,
                database: DatabasePool::new(database, trust, policy_keys, limits.database_sessions),
                grant_keys: Arc::new(grant_keys),
            }),
            limits,
        }
    }
    pub fn database_capacity(&self) -> DatabaseCapacity {
        self.state.database.capacity()
    }
    pub async fn serve(
        &self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), IngressError> {
        let _serving = self
            .state
            .database
            .serving()
            .map_err(|_| IngressError::Configuration)?;
        tokio::pin!(shutdown);
        let mut tasks = JoinSet::new();
        let result = loop {
            let accepted = poll_fn(|cx| {
                if shutdown.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Ok(None));
                }
                while let Poll::Ready(Some(done)) = tasks.poll_join_next(cx) {
                    if done.is_err() {
                        return Poll::Ready(Err(IngressError::Connection));
                    }
                }
                match listener.poll_accept(cx) {
                    Poll::Ready(Ok((socket, _))) => Poll::Ready(Ok(Some(socket))),
                    Poll::Ready(Err(_)) => Poll::Ready(Err(IngressError::Listener)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            let socket = match accepted {
                Ok(Some(s)) => s,
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            };
            if tasks.len() >= self.limits.connections {
                drop(socket);
                continue;
            }
            let state = self.state.clone();
            let deadline = Instant::now() + self.limits.deadline;
            let duration = self.limits.deadline;
            tasks.spawn(async move {
                let _ = timeout_at(deadline, connection(state, socket, duration, deadline)).await;
            });
        };
        tasks.shutdown().await;
        self.state.database.shutdown().await;
        result
    }
}
async fn connection(state: Arc<State>, socket: TcpStream, duration: Duration, deadline: Instant) {
    let Ok(stream) = state.tls.accept(socket).await else {
        return;
    };
    let principal = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .and_then(|leaf| state.registry.lookup(leaf.as_ref()));
    let service =
        service_fn(move |request| handle(state.clone(), principal.clone(), request, deadline));
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(64)
        .max_header_size(16384)
        .max_buf_size(16384)
        .timer(TokioTimer::new())
        .header_read_timeout(duration);
    let _ = builder
        .serve_connection(TokioIo::new(stream), service)
        .await;
}
fn check_request<B>(request: &Request<B>) -> Result<(), (StatusCode, &'static str)> {
    if request.uri().path_and_query().map(|p| p.as_str()) != Some("/v1/causal-events")
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
    {
        return Err((StatusCode::NOT_FOUND, "not_found"));
    }
    if request.method() != hyper::Method::POST {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"));
    }
    if request.headers().contains_key("upgrade")
        || request.headers().contains_key("content-encoding")
        || request.headers().contains_key("trailer")
        || request.headers().get_all("connection").iter().any(|value| {
            value.to_str().map_or(true, |text| {
                text.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
    {
        return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_encoding"));
    }
    if request.headers().get_all("content-type").iter().count() != 1
        || !request.headers().get("content-type").is_some_and(|v| {
            matches!(
                v.to_str(),
                Ok("application/json" | "application/json; charset=utf-8")
            )
        })
    {
        return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type"));
    }
    if request.headers().get_all("content-length").iter().count() > 1 {
        return Err((StatusCode::BAD_REQUEST, "invalid_length"));
    }
    if let Some(length) = request.headers().get("content-length") {
        let Some(length) = length
            .to_str()
            .ok()
            .filter(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|x| x.parse::<u64>().ok())
        else {
            return Err((StatusCode::BAD_REQUEST, "invalid_length"));
        };
        if length > MAX_CAUSAL_EVENT_BATCH_BYTES as u64 {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "batch_too_large"));
        }
    }
    Ok(())
}
fn preflight<B, P>(
    principal: Option<P>,
    request: &Request<B>,
) -> Result<P, (StatusCode, &'static str)> {
    let principal = principal.ok_or((StatusCode::FORBIDDEN, "not_authorized"))?;
    check_request(request)?;
    Ok(principal)
}
async fn read_body<B>(mut body: B) -> Result<Vec<u8>, (StatusCode, &'static str, bool)>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| (StatusCode::BAD_REQUEST, "invalid_body", false))?;
        let data = frame
            .into_data()
            .map_err(|_| (StatusCode::BAD_REQUEST, "unsupported_trailers", false))?;
        if bytes
            .len()
            .checked_add(data.len())
            .is_none_or(|n| n > MAX_CAUSAL_EVENT_BATCH_BYTES)
        {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "batch_too_large", false));
        }
        bytes.try_reserve_exact(data.len()).map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "capacity_unavailable",
                true,
            )
        })?;
        bytes.extend_from_slice(&data);
    }
    Ok(bytes)
}
async fn handle(
    state: Arc<State>,
    principal: Option<([u8; 32], Arc<CausalSession>)>,
    request: Request<Incoming>,
    deadline: Instant,
) -> Result<Reply, IngressError> {
    let id = request_id()?;
    let fail = |status, code, retryable| error(status, code, retryable, &id);
    let (peer, session) = match preflight(principal, &request) {
        Ok(principal) => principal,
        Err((status, code)) => return fail(status, code, false),
    };
    let bytes = match read_body(request.into_body()).await {
        Ok(bytes) => bytes,
        Err((status, code, retryable)) => return fail(status, code, retryable),
    };
    // Inbox checks signed authority and live session before parsing. Do not parse
    // body here before that boundary, even to populate response correlation.
    let copy = bytes.clone();
    let Ok(receive) =
        state
            .database
            .submit_causal(session, peer, bytes, state.grant_keys.clone(), deadline)
    else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_capacity_unavailable",
            true,
        );
    };
    let result = match receive.await {
        Ok(result) => result,
        Err(_) => return fail(StatusCode::SERVICE_UNAVAILABLE, "outcome_unknown", true),
    };
    match result {
        Ok(receipt) => {
            let batch =
                CausalEventBatch::from_wire_json(&copy).map_err(|_| IngressError::Connection)?;
            let digest = batch.digest_bytes().map_err(|_| IngressError::Connection)?;
            let digest = digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let accepted = receipt
                .accepted_at()
                .format(&Rfc3339)
                .map_err(|_| IngressError::Connection)?;
            reply(
                StatusCode::OK,
                json!({"batch_id":batch.batch_id(),"runtime_id":batch.runtime_id(),"session_epoch":batch.session_epoch(),"batch_digest":digest,"receipt_id":receipt.id(),"accepted_at":accepted,"status":if receipt.duplicate(){"duplicate"}else{"accepted"}}),
            )
        }
        Err(
            CausalError::Identity
            | CausalError::Signature
            | CausalError::Scope
            | CausalError::Expired,
        ) => fail(StatusCode::FORBIDDEN, "not_authorized", false),
        Err(CausalError::InvalidBatch) => {
            fail(StatusCode::UNPROCESSABLE_ENTITY, "invalid_batch", false)
        }
        Err(CausalError::Conflict) => fail(StatusCode::CONFLICT, "batch_conflict", false),
        Err(CausalError::LogicalQuota) => fail(StatusCode::LOCKED, "logical_quota", false),
        Err(CausalError::HistoryLimit) => {
            fail(StatusCode::SERVICE_UNAVAILABLE, "history_limit", false)
        }
        Err(CausalError::OutcomeUnknown) => {
            fail(StatusCode::SERVICE_UNAVAILABLE, "outcome_unknown", true)
        }
        Err(_) => fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            true,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn req(method: &str, uri: &str, content_type: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", content_type)
            .body(())
            .unwrap()
    }
    #[test]
    fn request_profile_is_closed_and_bounded() {
        assert!(check_request(&req("POST", "/v1/causal-events", "application/json")).is_ok());
        for path in [
            "/v1/causal-events?x=1",
            "http://example/v1/causal-events",
            "/v1/causal-events/",
            "/V1/causal-events",
        ] {
            assert_eq!(
                check_request(&req("POST", path, "application/json"))
                    .unwrap_err()
                    .0,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            check_request(&req("GET", "/v1/causal-events", "application/json"))
                .unwrap_err()
                .0,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            check_request(&req("POST", "/v1/causal-events", "text/plain"))
                .unwrap_err()
                .0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        for (name, value) in [
            ("upgrade", "websocket"),
            ("content-encoding", "gzip"),
            ("trailer", "x-extra"),
            ("connection", "keep-alive, Upgrade"),
        ] {
            let r = Request::builder()
                .method("POST")
                .uri("/v1/causal-events")
                .header("content-type", "application/json")
                .header(name, value)
                .body(())
                .unwrap();
            assert_eq!(
                check_request(&r).unwrap_err().0,
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            );
        }
        let r = Request::builder()
            .method("POST")
            .uri("/v1/causal-events")
            .header("content-type", "application/json")
            .header("content-length", "1048577")
            .body(())
            .unwrap();
        assert_eq!(
            check_request(&r).unwrap_err().0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let r = Request::builder()
            .method("POST")
            .uri("/v1/causal-events")
            .header("content-type", "application/json")
            .header("content-length", "bad")
            .body(())
            .unwrap();
        assert_eq!(check_request(&r).unwrap_err().0, StatusCode::BAD_REQUEST);
    }
    #[test]
    fn missing_principal_precedes_request_validation() {
        let invalid = req("GET", "/not-a-route", "text/plain");
        assert_eq!(
            preflight::<_, ()>(None, &invalid).unwrap_err().0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            preflight(Some(()), &invalid).unwrap_err().0,
            StatusCode::NOT_FOUND
        );
    }
    #[test]
    fn body_limits_and_trailers_are_checked_without_listener() {
        use hyper::body::{Body, Frame};
        use std::{
            collections::VecDeque,
            convert::Infallible,
            pin::Pin,
            task::{Context, Poll},
        };
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
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            assert_eq!(
                read_body(Frames(VecDeque::from([Frame::data(Bytes::from_static(
                    b"abc"
                ))])))
                .await
                .unwrap(),
                b"abc"
            );
            let oversized = Frames(VecDeque::from([
                Frame::data(Bytes::from(vec![0; MAX_CAUSAL_EVENT_BATCH_BYTES])),
                Frame::data(Bytes::from_static(b"x")),
            ]));
            assert_eq!(
                read_body(oversized).await.unwrap_err().0,
                StatusCode::PAYLOAD_TOO_LARGE
            );
            let trailers = Frames(VecDeque::from([Frame::trailers(hyper::HeaderMap::new())]));
            assert_eq!(
                read_body(trailers).await.unwrap_err().0,
                StatusCode::BAD_REQUEST
            );
        });
    }
    #[test]
    fn empty_registry_rejected_without_session_forgery() {
        assert!(matches!(
            CausalRegistry::new(Vec::new()),
            Err(IngressError::Configuration)
        ));
    }
}
