//! One-request 504 mTLS ingestion, with distinct export and evidence identities.
use crate::{
    receiver_causal_pool504::{Job, Pool},
    receiver_preauth504::ReceiverPreauth504,
    service::{HttpLimits, IngressError, Reply, error, reply, request_id},
};
use bytes::Bytes;
use contour_core::{
    CausalEventBatch, CausalGrantKeys, MAX_CAUSAL_EVENT_BATCH_BYTES, MAX_CAUSAL_EVIDENCE_BYTES,
    PolicyKeys,
};
use contour_postgres::{
    CausalError, CausalReceiverSession504, DatabaseSettings, ReceiverEvidencePeer,
    ReceiverEvidenceTls, ReceiverFactSelectors, TrustedCa,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use std::{
    future::{Future, poll_fn},
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};
use time::format_description::well_known::Rfc3339;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
    time::{Instant, timeout_at},
};

/// Operator-selected identifiers and pins are data; the TLS peer proves possession.
pub struct ReceiverBinding504 {
    pub session: CausalReceiverSession504,
    pub export_pin: [u8; 32],
    pub evidence_pin: [u8; 32],
    pub selectors: ReceiverFactSelectors,
}
struct Entry {
    session: Arc<CausalReceiverSession504>,
    export: [u8; 32],
    evidence: [u8; 32],
    selectors: Arc<ReceiverFactSelectors>,
}
pub struct ReceiverRegistry504(Vec<Arc<Entry>>);
impl ReceiverRegistry504 {
    pub fn new(bindings: Vec<ReceiverBinding504>) -> Result<Self, IngressError> {
        if bindings.is_empty()
            || bindings.len() > 128
            || bindings.iter().enumerate().any(|(i, b)| {
                !b.session.matches_export_pin(&b.export_pin)
                    || !pins_unique(
                        b.export_pin,
                        b.evidence_pin,
                        bindings[..i].iter().map(|p| (p.export_pin, p.evidence_pin)),
                    )
            })
        {
            return Err(IngressError::Configuration);
        }
        Ok(Self(
            bindings
                .into_iter()
                .map(|b| {
                    Arc::new(Entry {
                        session: Arc::new(b.session),
                        export: b.export_pin,
                        evidence: b.evidence_pin,
                        selectors: Arc::new(b.selectors),
                    })
                })
                .collect(),
        ))
    }
    /// No business route is authorized until an issued binding is installed.
    pub fn pending_only() -> Self {
        Self(Vec::new())
    }
    fn lookup(&self, peer: &ReceiverEvidencePeer) -> Option<(Arc<Entry>, Route)> {
        self.0.iter().find_map(|e| {
            if peer.matches_pin(&e.export) {
                Some((e.clone(), Route::Event))
            } else if peer.matches_pin(&e.evidence) {
                Some((e.clone(), Route::Fact))
            } else {
                None
            }
        })
    }
}
fn pins_unique(
    export: [u8; 32],
    evidence: [u8; 32],
    prior: impl Iterator<Item = ([u8; 32], [u8; 32])>,
) -> bool {
    export != evidence
        && prior
            .into_iter()
            .all(|(a, b)| a != export && a != evidence && b != export && b != evidence)
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Route {
    Event,
    Fact,
}
fn route_allowed(role: Route, route: Route) -> bool {
    role == route
}
struct State {
    tls: ReceiverEvidenceTls,
    registry: ReceiverRegistry504,
    preauth: Option<ReceiverPreauth504>,
    events: Pool,
    facts: Pool,
    grants: Arc<CausalGrantKeys>,
}
/// Explicit role-isolated receiver ingestion configuration.
pub struct ReceiverCausalConfig504 {
    pub tls: ReceiverEvidenceTls,
    pub registry: ReceiverRegistry504,
    pub event_database: DatabaseSettings,
    pub event_trust: TrustedCa,
    pub fact_database: DatabaseSettings,
    pub fact_trust: TrustedCa,
    pub grant_keys: CausalGrantKeys,
    pub policy_keys: PolicyKeys,
    pub limits: HttpLimits,
    pub event_slots: usize,
}
pub struct ReceiverCausalServer504 {
    state: Arc<State>,
    limits: HttpLimits,
}
struct ServingGuard(Arc<State>);
impl Drop for ServingGuard {
    fn drop(&mut self) {
        if let Some(broker) = &self.0.preauth {
            broker.seal();
        }
        self.0.events.seal();
        self.0.facts.seal();
    }
}
impl ReceiverCausalServer504 {
    /// Both pools have dedicated database credentials and at least one slot each.
    pub fn new(config: ReceiverCausalConfig504) -> Result<Self, IngressError> {
        Self::new_inner(config, None)
    }
    /// Enable the internal, one-use preauthentication route on this listener.
    pub fn new_with_preauth(
        config: ReceiverCausalConfig504,
    ) -> Result<(Self, ReceiverPreauth504), IngressError> {
        let broker = ReceiverPreauth504::new();
        let server = Self::new_inner(config, Some(broker.clone()))?;
        Ok((server, broker))
    }
    fn new_inner(
        config: ReceiverCausalConfig504,
        preauth: Option<ReceiverPreauth504>,
    ) -> Result<Self, IngressError> {
        let ReceiverCausalConfig504 {
            tls,
            registry,
            event_database,
            event_trust,
            fact_database,
            fact_trust,
            grant_keys,
            policy_keys,
            limits,
            event_slots,
        } = config;
        if event_slots == 0 || event_slots >= limits.database_sessions {
            return Err(IngressError::Configuration);
        }
        let keys = Arc::new(policy_keys);
        let events = Pool::new(event_database, event_trust, keys.clone(), event_slots);
        let facts = Pool::new(
            fact_database,
            fact_trust,
            keys,
            limits.database_sessions - event_slots,
        );
        Ok(Self {
            state: Arc::new(State {
                tls,
                registry,
                preauth,
                events,
                facts,
                grants: Arc::new(grant_keys),
            }),
            limits,
        })
    }
    pub async fn serve(
        &self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), IngressError> {
        self.state
            .events
            .begin()
            .map_err(|_| IngressError::Configuration)?;
        if self.state.facts.begin().is_err() {
            self.state.events.shutdown().await;
            return Err(IngressError::Configuration);
        }
        if let Some(broker) = &self.state.preauth {
            if broker.activate().is_err() {
                self.state.events.shutdown().await;
                self.state.facts.shutdown().await;
                return Err(IngressError::Configuration);
            }
        }
        let _serving = ServingGuard(self.state.clone());
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
            let duration = self.limits.deadline;
            let deadline = Instant::now() + duration;
            tasks.spawn(async move {
                let _ = timeout_at(deadline, connection(state, socket, duration, deadline)).await;
            });
        };
        tasks.shutdown().await;
        self.state.events.shutdown().await;
        self.state.facts.shutdown().await;
        result
    }
}
async fn connection(state: Arc<State>, socket: TcpStream, duration: Duration, deadline: Instant) {
    let Ok(connection) = state.tls.accept_until(socket, deadline).await else {
        return;
    };
    let (io, peer) = connection.into_parts();
    let principal = state.registry.lookup(&peer);
    let peer = Arc::new(Mutex::new(Some(peer)));
    let service = service_fn(move |request| {
        let peer = peer.lock().ok().and_then(|mut p| p.take());
        handle(state.clone(), principal.clone(), peer, request, deadline)
    });
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(64)
        .max_header_size(16384)
        .max_buf_size(16384)
        .timer(TokioTimer::new())
        .header_read_timeout(duration);
    let _ = builder.serve_connection(TokioIo::new(io), service).await;
}
fn check_request<B>(request: &Request<B>) -> Result<(), (StatusCode, &'static str)> {
    if !matches!(
        request.uri().path_and_query().map(|p| p.as_str()),
        Some("/v1/causal-events" | "/v1/causal-evidence/receiver" | "/v1/receiver-preauth")
    ) || request.uri().scheme().is_some()
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
    let preauth = request.uri().path() == "/v1/receiver-preauth";
    if request.headers().get_all("content-type").iter().count() != 1
        || !request.headers().get("content-type").is_some_and(|v| {
            if preauth {
                matches!(v.to_str(), Ok("application/octet-stream"))
            } else {
                matches!(
                    v.to_str(),
                    Ok("application/json" | "application/json; charset=utf-8")
                )
            }
        })
    {
        return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type"));
    }
    if request.headers().get_all("content-length").iter().count() > 1 {
        return Err((StatusCode::BAD_REQUEST, "invalid_length"));
    }
    let limit = if request.uri().path() == "/v1/causal-events" {
        MAX_CAUSAL_EVENT_BATCH_BYTES
    } else if request.uri().path() == "/v1/receiver-preauth" {
        64
    } else {
        MAX_CAUSAL_EVIDENCE_BYTES
    };
    if let Some(length) = request.headers().get("content-length") {
        let Some(length) = length
            .to_str()
            .ok()
            .filter(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|x| x.parse::<u64>().ok())
        else {
            return Err((StatusCode::BAD_REQUEST, "invalid_length"));
        };
        if length > limit as u64 {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "batch_too_large"));
        }
    }
    Ok(())
}
async fn read_body<B>(
    mut body: B,
    limit: usize,
) -> Result<Vec<u8>, (StatusCode, &'static str, bool)>
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
            .is_none_or(|n| n > limit)
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
    principal: Option<(Arc<Entry>, Route)>,
    peer: Option<ReceiverEvidencePeer>,
    request: Request<Incoming>,
    deadline: Instant,
) -> Result<Reply, IngressError> {
    let id = request_id()?;
    let fail = |s, c, r| error(s, c, r, &id);
    if request.uri().path_and_query().map(|p| p.as_str()) == Some("/v1/receiver-preauth") {
        let Some(broker) = &state.preauth else {
            return fail(StatusCode::FORBIDDEN, "not_authorized", false);
        };
        let Some(peer) = peer else {
            return fail(StatusCode::FORBIDDEN, "not_authorized", false);
        };
        if let Err((status, code)) = check_request(&request) {
            return fail(status, code, false);
        }
        let body = match read_body(request.into_body(), 64).await {
            Ok(body) => body,
            Err((s, c, r)) => return fail(s, c, r),
        };
        if !broker.accept(&body, &peer) {
            return fail(StatusCode::FORBIDDEN, "not_authorized", false);
        }
        return reply(StatusCode::OK, json!({"status":"accepted"}));
    }
    let Some((entry, role)) = principal else {
        return fail(StatusCode::FORBIDDEN, "not_authorized", false);
    };
    let Some(peer) = peer else {
        return fail(StatusCode::FORBIDDEN, "not_authorized", false);
    };
    if let Err((status, code)) = check_request(&request) {
        return fail(status, code, false);
    }
    let route = if request.uri().path() == "/v1/causal-events" {
        Route::Event
    } else {
        Route::Fact
    };
    if !route_allowed(role, route) {
        return fail(StatusCode::FORBIDDEN, "not_authorized", false);
    }
    let bytes = match read_body(
        request.into_body(),
        if route == Route::Event {
            MAX_CAUSAL_EVENT_BATCH_BYTES
        } else {
            MAX_CAUSAL_EVIDENCE_BYTES
        },
    )
    .await
    {
        Ok(b) => b,
        Err((s, c, r)) => return fail(s, c, r),
    };
    let (tx, rx) = oneshot::channel();
    match route {
        Route::Event => {
            let copy = bytes.clone();
            if state
                .events
                .start(
                    Job::Event(entry.session.clone(), peer, bytes, state.grants.clone(), tx),
                    deadline,
                )
                .is_err()
            {
                return fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "database_capacity_unavailable",
                    true,
                );
            }
            match rx.await {
                Ok(Ok(receipt)) => {
                    let batch = CausalEventBatch::from_wire_json(&copy)
                        .map_err(|_| IngressError::Connection)?;
                    let digest = batch
                        .digest_bytes()
                        .map_err(|_| IngressError::Connection)?
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
                Ok(Err(e)) => map_error(e, &id),
                Err(_) => fail(StatusCode::SERVICE_UNAVAILABLE, "outcome_unknown", true),
            }
        }
        Route::Fact => {
            // Separate channel type follows the fact inbox's exact receipt type.
            drop(tx);
            drop(rx);
            let (tx, rx) = oneshot::channel();
            if state
                .facts
                .start(
                    Job::Fact(
                        entry.session.clone(),
                        peer,
                        entry.selectors.clone(),
                        bytes,
                        state.grants.clone(),
                        tx,
                    ),
                    deadline,
                )
                .is_err()
            {
                return fail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "database_capacity_unavailable",
                    true,
                );
            }
            match rx.await {
                Ok(Ok(receipt)) => Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .header("connection", "close")
                    .body(Full::new(Bytes::copy_from_slice(receipt.as_bytes())))
                    .map_err(|_| IngressError::Connection),
                Ok(Err(e)) => map_error(e, &id),
                Err(_) => fail(StatusCode::SERVICE_UNAVAILABLE, "outcome_unknown", true),
            }
        }
    }
}
fn map_error(e: CausalError, id: &str) -> Result<Reply, IngressError> {
    let (status, code, retryable) = match e {
        CausalError::Identity
        | CausalError::Signature
        | CausalError::Scope
        | CausalError::Expired => (StatusCode::FORBIDDEN, "not_authorized", false),
        CausalError::InvalidBatch => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_batch", false),
        CausalError::Conflict => (StatusCode::CONFLICT, "batch_conflict", false),
        CausalError::LogicalQuota => (StatusCode::LOCKED, "logical_quota", false),
        CausalError::HistoryLimit => (StatusCode::SERVICE_UNAVAILABLE, "history_limit", false),
        CausalError::OutcomeUnknown => (StatusCode::SERVICE_UNAVAILABLE, "outcome_unknown", true),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            true,
        ),
    };
    error(status, code, retryable, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_rejects_ambiguous_pins() {
        assert!(!pins_unique([1; 32], [1; 32], [].into_iter()));
        for (a, b) in [
            ([1; 32], [3; 32]),
            ([3; 32], [1; 32]),
            ([2; 32], [3; 32]),
            ([3; 32], [2; 32]),
        ] {
            assert!(!pins_unique([1; 32], [2; 32], [(a, b)].into_iter()));
        }
        assert!(pins_unique(
            [1; 32],
            [2; 32],
            [([3; 32], [4; 32])].into_iter()
        ));
        assert!(ReceiverRegistry504::new(vec![]).is_err());
    }
    #[test]
    fn pending_registry_is_empty_and_preauth_request_is_bounded() {
        let registry = ReceiverRegistry504::pending_only();
        assert!(registry.0.is_empty());
        let request = |method: &str, path: &str, length: &str| {
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/octet-stream")
                .header("content-length", length)
                .body(())
                .unwrap()
        };
        assert!(check_request(&request("POST", "/v1/receiver-preauth", "64")).is_ok());
        let json_request = Request::builder()
            .method("POST")
            .uri("/v1/receiver-preauth")
            .header("content-type", "application/json")
            .header("content-length", "64")
            .body(())
            .unwrap();
        assert_eq!(
            check_request(&json_request).unwrap_err().0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            check_request(&request("POST", "/v1/receiver-preauth", "65"))
                .unwrap_err()
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            check_request(&request("POST", "/v1/receiver-preauth?x=1", "64"))
                .unwrap_err()
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            check_request(&request("GET", "/v1/receiver-preauth", "64"))
                .unwrap_err()
                .0,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    #[test]
    fn cross_route_credentials_are_rejected() {
        assert!(route_allowed(Route::Event, Route::Event));
        assert!(route_allowed(Route::Fact, Route::Fact));
        assert!(!route_allowed(Route::Fact, Route::Event));
        assert!(!route_allowed(Route::Event, Route::Fact));
    }
    #[test]
    fn streamed_body_enforces_limit_and_rejects_trailers() {
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
            let body = Frames(VecDeque::from([
                Frame::data(Bytes::from(vec![0; MAX_CAUSAL_EVIDENCE_BYTES])),
                Frame::data(Bytes::from_static(b"x")),
            ]));
            assert_eq!(
                read_body(body, MAX_CAUSAL_EVIDENCE_BYTES)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::PAYLOAD_TOO_LARGE
            );
            let body = Frames(VecDeque::from([Frame::trailers(hyper::HeaderMap::new())]));
            assert_eq!(
                read_body(body, MAX_CAUSAL_EVIDENCE_BYTES)
                    .await
                    .unwrap_err()
                    .0,
                StatusCode::BAD_REQUEST
            );
        });
    }
    #[test]
    fn framing_and_route_limits_are_closed() {
        let req = |path: &str, length: &str| {
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("content-length", length)
                .body(())
                .unwrap()
        };
        assert!(check_request(&req("/v1/causal-evidence/receiver", "4096")).is_ok());
        assert_eq!(
            check_request(&req("/v1/causal-evidence/receiver", "4097"))
                .unwrap_err()
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            check_request(&req("/v1/causal-events?x=1", "1"))
                .unwrap_err()
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            check_request(&req("/v1/causal-events", "bad"))
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
    }
}
