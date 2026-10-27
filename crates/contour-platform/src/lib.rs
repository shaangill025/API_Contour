//! Local-only HTTPS session boundary. OIDC identities are not business authorization.
//! The business handler must check current database membership for every operation.
pub mod business;
mod state;
mod wire;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use contour_auth::{IdTokenVerifier, VerifiedIdentity};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use state::{Login, Memory, Session};
use std::{
    convert::Infallible,
    future::Future,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub type PlatformResponse = Response<Full<Bytes>>;
pub type BusinessRequest = Request<Bytes>;
const ORIGIN: &str = "https://localhost:9443";
const AUTHORITY: &str = "localhost:9443";
const PROVIDER: &str = "https://localhost:8444";
const MAX_BODY: usize = 5 * 1024 * 1024;
const LOGIN_COOKIE: &str = "__Host-contour-login";
const SESSION_COOKIE: &str = "__Host-contour-session";
const LOGIN_LIFETIME: Duration = Duration::from_secs(300);
const SESSION_LIFETIME: Duration = Duration::from_secs(1800);

/// Closed errors deliberately omit URLs, credentials and provider error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformError {
    Configuration,
    InvalidRequest,
    Unauthenticated,
    Capacity,
    Unavailable,
}
impl std::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PlatformError {}

/// Operator-owned local configuration; request data cannot select trust or destinations.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub callback: String,
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
    pub provider_ca: PathBuf,
    pub jwks: PathBuf,
}
impl Config {
    fn validate(&self) -> Result<(), PlatformError> {
        // This profile intentionally has no general remote/network destination support.
        if self.issuer != format!("{PROVIDER}/realms/apicontour-local")
            || self.authorization_endpoint
                != format!("{}/protocol/openid-connect/auth", self.issuer)
            || self.token_endpoint != format!("{}/protocol/openid-connect/token", self.issuer)
            || self.client_id != "apicontour-local"
            || self.callback != format!("{ORIGIN}/auth/callback")
        {
            return Err(PlatformError::Configuration);
        }
        Ok(())
    }
}

pub struct Platform {
    config: Config,
    verifier: IdTokenVerifier,
    memory: Mutex<Memory>,
    acceptor: TlsAcceptor,
    provider: TlsConnector,
    application: Option<Arc<business::Business>>,
    assets: Vec<(&'static str, &'static str, Vec<u8>)>,
}
impl std::fmt::Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Platform")
    }
}

impl Platform {
    pub fn from_file(path: &Path) -> Result<Self, PlatformError> {
        let config = serde_json::from_slice(&read_file(path, 16384)?)
            .map_err(|_| PlatformError::Configuration)?;
        Self::from_config(config)
    }
    pub fn from_config(config: Config) -> Result<Self, PlatformError> {
        config.validate()?;
        let verifier = IdTokenVerifier::new(
            &config.issuer,
            &config.client_id,
            &read_file(&config.jwks, 65536)?,
        )
        .map_err(|_| PlatformError::Configuration)?;
        let certificate = read_file(&config.tls_certificate, 65536)?;
        let certificates = CertificateDer::pem_slice_iter(&certificate)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PlatformError::Configuration)?;
        if certificates.is_empty() || certificates.len() > 8 {
            return Err(PlatformError::Configuration);
        }
        let private_key =
            PrivateKeyDer::from_pem_slice(&read_file(&config.tls_private_key, 16384)?)
                .map_err(|_| PlatformError::Configuration)?;
        let mut server =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|_| PlatformError::Configuration)?
                .with_no_client_auth()
                .with_single_cert(certificates, private_key)
                .map_err(|_| PlatformError::Configuration)?;
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        server.max_early_data_size = 0;
        let mut roots = RootCertStore::empty();
        let ca = read_file(&config.provider_ca, 65536)?;
        let cas = CertificateDer::pem_slice_iter(&ca)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PlatformError::Configuration)?;
        if cas.is_empty() || cas.len() > 8 {
            return Err(PlatformError::Configuration);
        }
        for ca in cas {
            roots.add(ca).map_err(|_| PlatformError::Configuration)?;
        }
        let mut client =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|_| PlatformError::Configuration)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        client.enable_early_data = false;
        client.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            config,
            application: None,
            assets: Vec::new(),
            verifier,
            memory: Mutex::new(Memory::default()),
            acceptor: TlsAcceptor::from(Arc::new(server)),
            provider: TlsConnector::from(Arc::new(client)),
        })
    }

    /// Starts the local business host with a fixed, bounded static asset manifest.
    /// Assets are loaded before binding; request paths can never select filesystem paths.
    pub async fn serve_application(
        mut self,
        application: Arc<business::Business>,
        dist: &Path,
    ) -> Result<(), PlatformError> {
        for (url, file, content_type, max) in [
            ("/", "index.html", "text/html; charset=utf-8", 131072),
            (
                "/assets/main.js",
                "assets/main.js",
                "text/javascript; charset=utf-8",
                2097152,
            ),
            (
                "/assets/main.css",
                "assets/main.css",
                "text/css; charset=utf-8",
                262144,
            ),
            (
                "/assets/main.js.LEGAL.txt",
                "assets/main.js.LEGAL.txt",
                "text/plain; charset=utf-8",
                1048576,
            ),
        ] {
            self.assets
                .push((url, content_type, read_file(&dist.join(file), max)?));
        }
        self.application = Some(application.clone());
        self.serve_with(move |request, identity| {
            let application = application.clone();
            async move { application.handle(request, identity).await }
        })
        .await
    }

    /// Starts the login host only. Business readiness is deliberately false.
    pub async fn serve(self) -> Result<(), PlatformError> {
        self.serve_with(|_, _| async {
            response(
                503,
                "application/json",
                r#"{"error":"business_unavailable"}"#,
            )
        })
        .await
    }

    /// Requests reaching this callback have a freshly verified identity, bounded body,
    /// exact local Host and (for mutations) exact Origin plus JSON content type.
    /// The callback MUST apply current database authorization, never token role claims.
    /// `/readyz` stays 503 until a complete application supplies its own readiness host.
    pub async fn serve_with<H, F>(self, business: H) -> Result<(), PlatformError>
    where
        H: Fn(BusinessRequest, VerifiedIdentity) -> F + Send + Sync + 'static,
        F: Future<Output = PlatformResponse> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:9443")
            .await
            .map_err(|_| PlatformError::Unavailable)?;
        let platform = Arc::new(self);
        let handler = Arc::new(business);
        accept_connections(listener, move |socket| {
            let platform = platform.clone();
            let handler = handler.clone();
            async move {
                // Includes TLS handshake, headers, body, provider and business work.
                let _ =
                    tokio::time::timeout(Duration::from_secs(20), async {
                        let tls = platform.acceptor.accept(socket).await.map_err(|_| ())?;
                        let service = service_fn(move |request| {
                            let platform = platform.clone();
                            let handler = handler.clone();
                            async move {
                                Ok::<_, Infallible>(platform.dispatch(request, &*handler).await)
                            }
                        });
                        hyper::server::conn::http1::Builder::new()
                            .keep_alive(false)
                            .max_headers(32)
                            .max_buf_size(16384)
                            .serve_connection(TokioIo::new(tls), service)
                            .await
                            .map_err(|_| ())
                    })
                    .await;
            }
        })
        .await
    }

    async fn dispatch<H, F>(&self, request: Request<Incoming>, business: &H) -> PlatformResponse
    where
        H: Fn(BusinessRequest, VerifiedIdentity) -> F,
        F: Future<Output = PlatformResponse>,
    {
        let request = match bounded_request(request).await {
            Ok(request) => request,
            Err(error) => return error_response(error),
        };
        if request.method() == hyper::Method::GET {
            if let Some((_, content_type, bytes)) = self
                .assets
                .iter()
                .find(|(path, _, _)| *path == request.uri().path())
            {
                return response(200, content_type, bytes.clone());
            }
            if request.uri().path() == "/readyz" {
                if let Some(application) = &self.application {
                    let ready = application.ready().await;
                    return response(
                        if ready { 200 } else { 503 },
                        "application/json",
                        if ready {
                            r#"{"ready":true}"#
                        } else {
                            r#"{"ready":false}"#
                        },
                    );
                }
            }
        }
        let result = match (request.method().as_str(), request.uri().path()) {
            ("GET", "/livez") => Ok(response(200, "application/json", r#"{"live":true}"#)),
            ("GET", "/readyz") => Ok(response(
                503,
                "application/json",
                r#"{"ready":false,"reason":"business_integration_pending"}"#,
            )),
            ("GET", "/") => Ok(response(200, "text/html; charset=utf-8", LANDING)),
            ("GET", "/app.js") => Ok(response(200, "text/javascript; charset=utf-8", SCRIPT)),
            ("GET", "/auth/login") => self.login(),
            ("GET", "/auth/callback") => self.callback(&request).await,
            ("GET", "/auth/session") => self
                .identity(request.headers())
                .map(|_| response(200, "application/json", r#"{"authenticated":true}"#)),
            ("POST", "/auth/logout") => self.logout(&request),
            (_, path) if path.starts_with("/v1/") => match self.identity(request.headers()) {
                Ok(identity) => Ok(business(request, identity).await),
                Err(error) => Err(error),
            },
            _ => Ok(response(
                404,
                "application/json",
                r#"{"error":"not_found"}"#,
            )),
        };
        result.unwrap_or_else(error_response)
    }

    fn login(&self) -> Result<PlatformResponse, PlatformError> {
        let now = Instant::now();
        let state = random()?;
        let login = Login {
            nonce: random()?,
            verifier: random()?,
            binding: random()?,
            expires: now + LOGIN_LIFETIME,
        };
        let location = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            self.config.authorization_endpoint,
            wire::encode(&self.config.client_id),
            wire::encode(&self.config.callback),
            state,
            login.nonce,
            challenge(&login.verifier)
        );
        let cookie = cookie(LOGIN_COOKIE, &login.binding, 300);
        self.memory
            .lock()
            .map_err(|_| PlatformError::Unavailable)?
            .insert_login(state, login, now)?;
        let mut result = response(303, "text/plain", "Continue to local identity provider");
        result.headers_mut().insert(
            "location",
            location.parse().map_err(|_| PlatformError::Configuration)?,
        );
        result.headers_mut().append(
            "set-cookie",
            cookie.parse().map_err(|_| PlatformError::Configuration)?,
        );
        Ok(result)
    }

    async fn callback(&self, request: &BusinessRequest) -> Result<PlatformResponse, PlatformError> {
        let query = wire::query(request.uri().query().ok_or(PlatformError::InvalidRequest)?)?;
        if query.keys().any(|key| {
            ![
                "state",
                "code",
                "iss",
                "session_state",
                "error",
                "error_description",
            ]
            .contains(&key.as_str())
        }) {
            return Err(PlatformError::InvalidRequest);
        }
        let state = query
            .get("state")
            .filter(|value| wire::opaque(value))
            .ok_or(PlatformError::InvalidRequest)?;
        let cookies = wire::cookies(request.headers())?;
        let binding = cookies
            .get(LOGIN_COOKIE)
            .ok_or(PlatformError::Unauthenticated)?;
        let login = self
            .memory
            .lock()
            .map_err(|_| PlatformError::Unavailable)?
            .consume_login(state, binding, Instant::now())?;
        // Consumption precedes provider exchange, including denied/error callbacks.
        if query.contains_key("error")
            || query
                .get("iss")
                .is_some_and(|issuer| issuer != &self.config.issuer)
        {
            return Err(PlatformError::Unauthenticated);
        }
        let code = query
            .get("code")
            .filter(|code| !code.is_empty() && code.len() <= 2048)
            .ok_or(PlatformError::InvalidRequest)?;
        let token = self.exchange(code, &login.verifier).await?;
        self.verifier
            .verify(&token, &login.nonce, unix_now()?)
            .map_err(|_| PlatformError::Unauthenticated)?;
        let session_id = random()?;
        let now = Instant::now();
        let mut memory = self.memory.lock().map_err(|_| PlatformError::Unavailable)?;
        memory.insert_session(
            session_id.clone(),
            Session {
                token,
                nonce: login.nonce,
                expires: now + SESSION_LIFETIME,
            },
            now,
        )?;
        if let Some(old) = cookies.get(SESSION_COOKIE) {
            memory.remove_session(old);
        }
        let mut result = response(303, "text/plain", "Login complete");
        result.headers_mut().insert(
            "location",
            "/".parse().map_err(|_| PlatformError::Configuration)?,
        );
        for value in [
            cookie(SESSION_COOKIE, &session_id, 1800),
            cookie(LOGIN_COOKIE, "", 0),
        ] {
            result.headers_mut().append(
                "set-cookie",
                value.parse().map_err(|_| PlatformError::Configuration)?,
            );
        }
        Ok(result)
    }

    /// Re-verifies retained ID token against this immutable approved trust configuration
    /// and current UTC. Application actor/membership must still be checked in its DB transaction.
    pub fn identity(&self, headers: &hyper::HeaderMap) -> Result<VerifiedIdentity, PlatformError> {
        let cookies = wire::cookies(headers)?;
        let session_id = cookies
            .get(SESSION_COOKIE)
            .filter(|id| wire::opaque(id))
            .ok_or(PlatformError::Unauthenticated)?;
        let mut memory = self.memory.lock().map_err(|_| PlatformError::Unavailable)?;
        memory.verified_session(session_id, &self.verifier, unix_now()?, Instant::now())
    }

    fn logout(&self, request: &BusinessRequest) -> Result<PlatformResponse, PlatformError> {
        if request.body().as_ref() != b"{}" {
            return Err(PlatformError::InvalidRequest);
        }
        let cookies = wire::cookies(request.headers())?;
        if let Some(id) = cookies.get(SESSION_COOKIE) {
            self.memory
                .lock()
                .map_err(|_| PlatformError::Unavailable)?
                .remove_session(id);
        }
        let mut result = response(200, "application/json", r#"{"authenticated":false}"#);
        result.headers_mut().append(
            "set-cookie",
            cookie(SESSION_COOKIE, "", 0)
                .parse()
                .map_err(|_| PlatformError::Configuration)?,
        );
        Ok(result)
    }

    async fn exchange(&self, code: &str, verifier: &str) -> Result<String, PlatformError> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let socket = TcpStream::connect("127.0.0.1:8444").await.map_err(|_| PlatformError::Unavailable)?;
            let tls = self.provider.connect(ServerName::try_from("localhost").map_err(|_| PlatformError::Configuration)?, socket).await.map_err(|_| PlatformError::Unavailable)?;
            let (mut sender, connection) = hyper::client::conn::http1::Builder::new().max_headers(32).max_header_size(16384).max_buf_size(16384)
                .handshake(TokioIo::new(tls)).await.map_err(|_| PlatformError::Unavailable)?;
            let _driver = AbortDriver(tokio::spawn(async move { let _ = connection.await; }));
            let form = format!("grant_type=authorization_code&client_id={}&redirect_uri={}&code={}&code_verifier={}", wire::encode(&self.config.client_id), wire::encode(&self.config.callback), wire::encode(code), wire::encode(verifier));
            let path = self.config.token_endpoint.strip_prefix(PROVIDER).ok_or(PlatformError::Configuration)?;
            let request = Request::post(path).header("host", "localhost:8444").header("content-type", "application/x-www-form-urlencoded").header("connection", "close")
                .body(Full::new(Bytes::from(form))).map_err(|_| PlatformError::Configuration)?;
            let response = sender.send_request(request).await.map_err(|_| PlatformError::Unavailable)?;
            if response.status() != 200 || response.headers().contains_key("content-encoding")
                || response.headers().get_all("content-type").iter().count() != 1
                || !response.headers().get("content-type").and_then(|v| v.to_str().ok()).is_some_and(|v| v == "application/json" || v == "application/json;charset=UTF-8" || v == "application/json; charset=utf-8") {
                return Err(PlatformError::Unauthenticated);
            }
            let bytes = read_body(response.into_body(), 65536).await?;
            wire::token(&bytes)
        }).await.map_err(|_| PlatformError::Unavailable)?
    }
}

async fn accept_connections<H, F>(listener: TcpListener, connection: H) -> Result<(), PlatformError>
where
    H: Fn(TcpStream) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    // The set belongs to the listener future: dropping/cancelling the host aborts
    // every accepted TLS, provider and business future, even if the runtime lives.
    let mut connections = JoinSet::new();
    loop {
        let (socket, _) = std::future::poll_fn(|cx| {
            // Reap promptly, including while no new connection is arriving.
            while let std::task::Poll::Ready(Some(_)) = connections.poll_join_next(cx) {}
            listener.poll_accept(cx)
        })
        .await
        .map_err(|_| PlatformError::Unavailable)?;
        if connections.len() >= 32 {
            drop(socket);
            continue;
        }
        connections.spawn(connection(socket));
    }
}

struct AbortDriver(tokio::task::JoinHandle<()>);
impl Drop for AbortDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn read_file(path: &Path, max: usize) -> Result<Vec<u8>, PlatformError> {
    let file = std::fs::File::open(path).map_err(|_| PlatformError::Configuration)?;
    if !file
        .metadata()
        .map_err(|_| PlatformError::Configuration)?
        .is_file()
    {
        return Err(PlatformError::Configuration);
    }
    let mut data = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| PlatformError::Configuration)?;
    if data.is_empty() || data.len() > max {
        return Err(PlatformError::Configuration);
    }
    Ok(data)
}
fn unix_now() -> Result<u64, PlatformError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| PlatformError::Unavailable)
}
fn random() -> Result<String, PlatformError> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| PlatformError::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
fn cookie(name: &str, value: &str, age: u32) -> String {
    format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={age}")
}

async fn bounded_request(request: Request<Incoming>) -> Result<BusinessRequest, PlatformError> {
    wire::validate_request(&request)?;
    let limit = if matches!(request.method().as_str(), "GET" | "HEAD") {
        0
    } else {
        MAX_BODY
    };
    let (parts, body) = request.into_parts();
    Ok(Request::from_parts(
        parts,
        Bytes::from(read_body(body, limit).await?),
    ))
}
async fn read_body<B: hyper::body::Body<Data = Bytes> + Unpin>(
    mut body: B,
    limit: usize,
) -> Result<Vec<u8>, PlatformError> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let data = frame
            .map_err(|_| PlatformError::InvalidRequest)?
            .into_data()
            .map_err(|_| PlatformError::InvalidRequest)?;
        if data.len() > limit - bytes.len() {
            return Err(PlatformError::InvalidRequest);
        }
        bytes.extend_from_slice(&data);
    }
    Ok(bytes)
}
pub fn response(
    status: u16,
    content_type: &'static str,
    body: impl Into<Bytes>,
) -> PlatformResponse {
    let mut response = Response::new(Full::new(body.into()));
    *response.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    let headers = response.headers_mut();
    headers.insert(
        "content-type",
        hyper::header::HeaderValue::from_static(content_type),
    );
    headers.insert(
        "cache-control",
        hyper::header::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        "pragma",
        hyper::header::HeaderValue::from_static("no-cache"),
    );
    headers.insert(
        "referrer-policy",
        hyper::header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "x-content-type-options",
        hyper::header::HeaderValue::from_static("nosniff"),
    );
    headers.insert("content-security-policy", hyper::header::HeaderValue::from_static("default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"));
    response
}
fn error_response(error: PlatformError) -> PlatformResponse {
    let (status, body) = match error {
        PlatformError::InvalidRequest => (400, r#"{"error":"invalid_request"}"#),
        PlatformError::Unauthenticated => (401, r#"{"error":"authentication_required"}"#),
        PlatformError::Capacity => (503, r#"{"error":"capacity"}"#),
        _ => (503, r#"{"error":"unavailable"}"#),
    };
    response(status, "application/json", body)
}
const LANDING: &str = r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>API Contour local login</title><h1>API Contour</h1><p>Local authentication workspace. Contract import and review are not connected yet.</p><p id="status" role="status">Checking session…</p><a href="/auth/login">Sign in with local identity provider</a><button id="logout" type="button">Sign out of API Contour</button><p>Signing out ends this application session. The local identity provider may retain its own login.</p><script src="/app.js" defer></script></html>"#;
const SCRIPT: &str = r#"async function check(){const r=await fetch('/auth/session',{cache:'no-store'});document.getElementById('status').textContent=r.ok?'Signed in':'Signed out';}document.getElementById('logout').onclick=async()=>{await fetch('/auth/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});await check();};check().catch(()=>{document.getElementById('status').textContent='Session unavailable';});"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelling_host_drops_pending_request_and_socket_while_runtime_lives() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let dropped = Arc::new(AtomicBool::new(false));
            let completed = Arc::new(AtomicBool::new(false));
            let started = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let server = tokio::spawn(accept_connections(listener, {
                let (dropped, completed, started, release) = (
                    dropped.clone(),
                    completed.clone(),
                    started.clone(),
                    release.clone(),
                );
                move |mut socket| {
                    let (dropped, completed, started, release) = (
                        dropped.clone(),
                        completed.clone(),
                        started.clone(),
                        release.clone(),
                    );
                    async move {
                        let _dropped = Dropped(dropped);
                        let mut byte = [0];
                        socket.read_exact(&mut byte).await.unwrap();
                        started.notify_one();
                        release.notified().await;
                        completed.store(true, Ordering::SeqCst);
                        let _ = socket.write_all(b"completed").await;
                    }
                }
            }));
            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(b"r").await.unwrap();
            tokio::time::timeout(Duration::from_secs(1), started.notified())
                .await
                .unwrap();
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
            let mut byte = [0];
            let closed = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte)).await;
            assert!(
                closed.is_ok(),
                "accepted request socket must close when host is cancelled"
            );
            assert!(matches!(closed.unwrap(), Ok(0)));
            assert!(
                dropped.load(Ordering::SeqCst),
                "pending request must be dropped"
            );
            release.notify_one();
            tokio::task::yield_now().await;
            assert!(
                !completed.load(Ordering::SeqCst),
                "request must not complete after host cancellation"
            );
        });
    }
    #[test]
    fn actual_body_limit_including_bodyless_requests() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert_eq!(
                read_body(Full::new(Bytes::from_static(b"1234")), 4)
                    .await
                    .unwrap(),
                b"1234"
            );
            assert_eq!(
                read_body(Full::new(Bytes::from_static(b"12345")), 4).await,
                Err(PlatformError::InvalidRequest)
            );
            assert_eq!(
                read_body(Full::new(Bytes::from_static(b"x")), 0).await,
                Err(PlatformError::InvalidRequest)
            );
            assert!(
                read_body(Full::new(Bytes::new()), 0)
                    .await
                    .unwrap()
                    .is_empty()
            );
        });
    }
    #[test]
    fn operator_urls_cannot_expand_local_trust() {
        let mut config = Config {
            issuer: format!("{PROVIDER}/realms/apicontour-local"),
            authorization_endpoint: format!(
                "{PROVIDER}/realms/apicontour-local/protocol/openid-connect/auth"
            ),
            token_endpoint: format!(
                "{PROVIDER}/realms/apicontour-local/protocol/openid-connect/token"
            ),
            client_id: "apicontour-local".into(),
            callback: format!("{ORIGIN}/auth/callback"),
            tls_certificate: PathBuf::new(),
            tls_private_key: PathBuf::new(),
            provider_ca: PathBuf::new(),
            jwks: PathBuf::new(),
        };
        assert!(config.validate().is_ok());
        config.token_endpoint = "https://elsewhere.invalid/token".into();
        assert_eq!(config.validate(), Err(PlatformError::Configuration));
    }
    #[test]
    fn pkce_rfc7636_vector_and_unpredictable_identifiers() {
        // Public octet vectors from RFC 7636 Appendix B, not credentials:
        // https://www.rfc-editor.org/rfc/rfc7636#appendix-B
        let verifier_octets = [
            116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212,
            37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
        ];
        let expected_digest = [
            19, 211, 30, 150, 26, 26, 216, 236, 47, 22, 177, 12, 76, 152, 46, 8, 118, 168, 120,
            173, 109, 241, 68, 86, 110, 225, 137, 74, 203, 112, 249, 195,
        ];
        let verifier = URL_SAFE_NO_PAD.encode(verifier_octets);
        let encoded = challenge(&verifier);
        assert!(wire::opaque(&encoded));
        assert_eq!(URL_SAFE_NO_PAD.decode(encoded).unwrap(), expected_digest);
        let values = (0..100)
            .map(|_| random().unwrap())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(values.len(), 100);
        assert!(values.iter().all(|value| wire::opaque(value)));
    }
    #[test]
    fn host_cookie_attributes_and_explicit_deletion() {
        assert_eq!(
            cookie(SESSION_COOKIE, "opaque", 1800),
            "__Host-contour-session=opaque; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=1800"
        );
        assert_eq!(
            cookie(LOGIN_COOKIE, "", 0),
            "__Host-contour-login=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
        );
    }
}
