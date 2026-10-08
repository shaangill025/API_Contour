use crate::CollectorTls;
use crate::pool::{DatabaseCapacity, DatabasePool};
use bytes::Bytes;
use contour_core::{Batch, PolicyKeys};
use contour_postgres::{AuthorityError, DatabaseSettings, SubmitError, TrustedCa};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use ring::rand::{SecureRandom, SystemRandom};
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
type Reply = Response<Full<Bytes>>;
const BODY_LIMIT: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressError {
    Configuration,
    Listener,
    RequestId,
    Connection,
}
impl fmt::Display for IngressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for IngressError {}
/// Operator configuration, not request-supplied enrollment or certificate subjects.
pub struct PrincipalRegistry(Vec<([u8; 32], [String; 2])>);
impl fmt::Debug for PrincipalRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrincipalRegistry")
    }
}
impl PrincipalRegistry {
    pub fn new(bindings: &[([u8; 32], [&str; 2])]) -> Result<Self, IngressError> {
        if bindings.is_empty()
            || bindings.len() > 128
            || bindings.iter().enumerate().any(|(index, (pin, identity))| {
                identity.iter().any(|id| !uuid(id))
                    || bindings[..index].iter().any(|(other, _)| other == pin)
            })
        {
            return Err(IngressError::Configuration);
        }
        Ok(Self(
            bindings
                .iter()
                .map(|(pin, identity)| (*pin, identity.map(str::to_owned)))
                .collect(),
        ))
    }
    fn lookup(&self, leaf: &[u8]) -> Option<[String; 2]> {
        let pin: [u8; 32] = Sha256::digest(leaf).into();
        self.0
            .iter()
            .find(|(installed, _)| *installed == pin)
            .map(|(_, identity)| identity.clone())
    }
}
#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    connections: usize,
    database_sessions: usize,
    deadline: Duration,
}
impl HttpLimits {
    pub fn new(connections: usize, deadline: Duration) -> Result<Self, IngressError> {
        if !(1..=64).contains(&connections)
            || !(Duration::from_millis(1)..=Duration::from_secs(30)).contains(&deadline)
        {
            return Err(IngressError::Configuration);
        }
        Ok(Self {
            connections,
            database_sessions: connections,
            deadline,
        })
    }
    pub fn with_database_sessions(mut self, capacity: usize) -> Result<Self, IngressError> {
        if !(1..=64).contains(&capacity) {
            return Err(IngressError::Configuration);
        }
        self.database_sessions = capacity;
        Ok(self)
    }
}
struct State {
    tls: CollectorTls,
    registry: PrincipalRegistry,
    database: DatabasePool,
}
/// Owns TLS authentication and HTTP dispatch. No public principal/SQL bypass.
pub struct IngestionServer {
    state: Arc<State>,
    limits: HttpLimits,
}
impl fmt::Debug for IngestionServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IngestionServer")
    }
}
impl IngestionServer {
    pub fn new(
        tls: CollectorTls,
        registry: PrincipalRegistry,
        database: DatabaseSettings,
        trust: TrustedCa,
        keys: PolicyKeys,
        limits: HttpLimits,
    ) -> Self {
        Self {
            state: Arc::new(State {
                tls,
                registry,
                database: DatabasePool::new(database, trust, keys, limits.database_sessions),
            }),
            limits,
        }
    }
    pub fn database_capacity(&self) -> DatabaseCapacity {
        self.state.database.capacity()
    }
    /// One HTTP request per owned connection. Explicit shutdown aborts and joins
    /// every task; dropping this future also aborts the owned JoinSet.
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
                while let Poll::Ready(Some(completed)) = tasks.poll_join_next(cx) {
                    if completed.is_err() {
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
                Ok(Some(socket)) => socket,
                Ok(None) => break Ok(()),
                Err(error) => break Err(error),
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
    // Only certificates on this successfully verified mandatory-mTLS session count.
    let principal = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .and_then(|leaf| state.registry.lookup(leaf.as_ref()));
    let service =
        service_fn(move |request| handle(state.clone(), principal.clone(), request, deadline));
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(64)
        .max_header_size(16_384)
        .max_buf_size(16_384)
        .timer(TokioTimer::new())
        .header_read_timeout(duration);
    let _ = builder
        .serve_connection(TokioIo::new(stream), service)
        .await;
}
async fn handle(
    state: Arc<State>,
    principal: Option<[String; 2]>,
    request: Request<Incoming>,
    deadline: Instant,
) -> Result<Reply, IngressError> {
    let id = request_id()?;
    let fail = |status, code, retryable| error(status, code, retryable, &id);
    let Some(principal) = principal else {
        return fail(StatusCode::FORBIDDEN, "not_authorized", false);
    };
    if request.uri().path_and_query().map(|target| target.as_str()) != Some("/v1/batches")
        || request.uri().scheme().is_some()
    {
        return fail(StatusCode::NOT_FOUND, "not_found", false);
    }
    if request.method() != hyper::Method::POST {
        return fail(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", false);
    }
    if request.headers().contains_key("upgrade")
        || request.headers().contains_key("content-encoding")
    {
        return fail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_encoding",
            false,
        );
    }
    if request.headers().get_all("content-type").iter().count() != 1
        || !request.headers().get("content-type").is_some_and(|value| {
            matches!(
                value.to_str(),
                Ok("application/json" | "application/json; charset=utf-8")
            )
        })
    {
        return fail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            false,
        );
    }
    if request
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > BODY_LIMIT as u64)
    {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "batch_too_large", false);
    }
    let mut body = request.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return fail(StatusCode::BAD_REQUEST, "invalid_body", false);
        };
        let Ok(data) = frame.into_data() else {
            return fail(StatusCode::BAD_REQUEST, "unsupported_trailers", false);
        };
        if bytes
            .len()
            .checked_add(data.len())
            .is_none_or(|length| length > BODY_LIMIT)
        {
            return fail(StatusCode::PAYLOAD_TOO_LARGE, "batch_too_large", false);
        }
        if bytes.try_reserve_exact(data.len()).is_err() {
            return fail(
                StatusCode::SERVICE_UNAVAILABLE,
                "capacity_unavailable",
                true,
            );
        }
        bytes.extend_from_slice(&data);
    }
    let Ok(batch) = Batch::from_wire_json(&bytes) else {
        return fail(StatusCode::BAD_REQUEST, "invalid_batch", false);
    };
    if batch.tenant_id() != principal[0] || batch.collector_id() != principal[1] {
        return fail(StatusCode::FORBIDDEN, "not_authorized", false);
    }
    // Do not precheck validate_at: committed expired-record retries are legitimate.
    drop(bytes);
    let batch_id = batch.batch_id().to_owned();
    let Ok(receive) = state.database.submit(batch, principal, deadline) else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_capacity_unavailable",
            true,
        );
    };
    let result = receive.await.map_err(|_| IngressError::Connection)?;
    match result {
        Ok(receipt) => {
            let accepted = receipt
                .accepted_at()
                .format(&Rfc3339)
                .map_err(|_| IngressError::Connection)?;
            reply(
                StatusCode::OK,
                json!({"batch_id":batch_id,"status":receipt.status().as_str(),"receipt_id":receipt.id(),"accepted_at":accepted}),
            )
        }
        Err(SubmitError::Conflict) => fail(StatusCode::CONFLICT, "batch_conflict", false),
        Err(SubmitError::OutcomeUnknown) => {
            fail(StatusCode::SERVICE_UNAVAILABLE, "outcome_unknown", true)
        }
        Err(SubmitError::Batch) => fail(StatusCode::UNPROCESSABLE_ENTITY, "invalid_batch", false),
        Err(SubmitError::Authority(AuthorityError::AuthorityTooLarge)) => {
            fail(StatusCode::PAYLOAD_TOO_LARGE, "authority_too_large", false)
        }
        Err(SubmitError::Authority(
            AuthorityError::Identity
            | AuthorityError::Missing
            | AuthorityError::Disabled
            | AuthorityError::Revoked
            | AuthorityError::Policy
            | AuthorityError::Source,
        )) => fail(StatusCode::FORBIDDEN, "not_authorized", false),
        Err(SubmitError::Authority(AuthorityError::Admission)) => {
            fail(StatusCode::UNPROCESSABLE_ENTITY, "not_admissible", false)
        }
        Err(_) => fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            true,
        ),
    }
}
fn reply(status: StatusCode, value: serde_json::Value) -> Result<Reply, IngressError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| IngressError::Connection)?;
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("connection", "close")
        .body(Full::new(Bytes::from(bytes)))
        .map_err(|_| IngressError::Connection)
}
fn error(status: StatusCode, code: &str, retryable: bool, id: &str) -> Result<Reply, IngressError> {
    reply(
        status,
        json!({"code":code,"message":"Request could not be completed","request_id":id,"retryable":retryable}),
    )
}
fn request_id() -> Result<String, IngressError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| IngressError::RequestId)?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
