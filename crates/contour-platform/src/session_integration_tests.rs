//! Synthetic HTTP/1 fixture. It uses the checked-in test CA and a loopback
//! ephemeral port, never an IDP, database, or production credential.
use super::*;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use tokio::sync::Notify;

fn config() -> Config {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let materials = root.join("tests/fixtures/causal-container-launch/materials");
    let issuer = "https://localhost:8444/realms/apicontour-local".to_string();
    Config {
        transport: TransportProfile::Host,
        authorization_endpoint: format!("{issuer}/protocol/openid-connect/auth"),
        token_endpoint: format!("{issuer}/protocol/openid-connect/token"),
        issuer,
        client_id: "apicontour-local".into(),
        callback: "https://localhost:9443/auth/callback".into(),
        tls_certificate: materials.join("server.pem"),
        tls_private_key: materials.join("server.key"),
        provider_ca: materials.join("ca.pem"),
        jwks: root.join("crates/contour-auth/tests/fixtures/public-jwks.json"),
    }
}
fn token(subject: &str, exp: u64) -> String {
    let now = unix_now().unwrap();
    let claims = serde_json::json!({"iss":"https://localhost:8444/realms/apicontour-local","sub":subject,"aud":"apicontour-local","iat":now-10,"exp":exp,"nonce":"synthetic-nonce"});
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"synthetic-rsa","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let bytes = include_bytes!("../../contour-auth/tests/fixtures/synthetic-rsa.der");
    let key = RsaKeyPair::from_der(bytes)
        .or_else(|_| RsaKeyPair::from_pkcs8(bytes))
        .unwrap();
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        message.as_bytes(),
        &mut signature,
    )
    .unwrap();
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))
}
fn insert(platform: &Platform, id: &str, view: &str, subject: &str, exp: u64) {
    let now = Instant::now();
    platform
        .memory
        .lock()
        .unwrap()
        .insert_session(
            id.into(),
            Session {
                token: token(subject, exp),
                nonce: "synthetic-nonce".into(),
                view: view.into(),
                expires: now + Duration::from_secs(60),
            },
            now,
        )
        .unwrap();
}
async fn call(
    address: std::net::SocketAddr,
    connector: TlsConnector,
    path: &str,
    cookie_id: Option<&str>,
    supplied_view: Option<&str>,
) -> (u16, hyper::HeaderMap, String) {
    let stream = TcpStream::connect(address).await.unwrap();
    let tls = connector
        .connect(ServerName::try_from("causal-node").unwrap(), stream)
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let logout = path == "/auth/logout";
    let mut request = Request::builder()
        .method(if logout { "POST" } else { "GET" })
        .uri(path)
        .header("host", AUTHORITY);
    if logout {
        request = request
            .header("origin", ORIGIN)
            .header("content-type", "application/json");
    }
    if let Some(id) = cookie_id {
        request = request.header("cookie", format!("{SESSION_COOKIE}={id}"));
    }
    if let Some(view) = supplied_view {
        request = request.header("x-contour-session-view", view);
    }
    let result = sender
        .send_request(
            request
                .body(Full::new(if logout {
                    Bytes::from_static(b"{}")
                } else {
                    Bytes::new()
                }))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = result.status().as_u16();
    let headers = result.headers().clone();
    let body = result.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    task.await.unwrap();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}
fn view(headers: &hyper::HeaderMap) -> Option<&str> {
    headers
        .get("x-contour-session-view")
        .map(|v| v.to_str().unwrap())
}
#[test]
fn verified_session_view_is_bound_to_actual_http_response() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            let platform = Arc::new(Platform::from_config(config()).unwrap());
            let now = unix_now().unwrap();
            let a = "a".repeat(43);
            let b = "b".repeat(43);
            let expired = "c".repeat(43);
            let av = format!("sv1_{}", "d".repeat(43));
            let bv = format!("sv1_{}", "e".repeat(43));
            insert(&platform, &a, &av, "session-a", now + 60);
            insert(&platform, &b, &bv, "session-b", now + 60);
            insert(
                &platform,
                &expired,
                &format!("sv1_{}", "f".repeat(43)),
                "expired",
                now - 1,
            );
            let ca = std::fs::read(config().provider_ca).unwrap();
            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(&ca) {
                roots.add(cert.unwrap()).unwrap();
            }
            let client = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let started = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let server_platform = platform.clone();
            let server_started = started.clone();
            let server_release = release.clone();
            let server = tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    let platform = server_platform.clone();
                    let started = server_started.clone();
                    let release = server_release.clone();
                    tasks.spawn(async move {
                        let tls = platform.acceptor.accept(socket).await.unwrap();
                        let handler =
                            move |request: BusinessRequest, identity: VerifiedIdentity| {
                                let started = started.clone();
                                let release = release.clone();
                                async move {
                                    if request.uri().path() == "/v1/delayed" {
                                        started.notify_one();
                                        release.notified().await;
                                    }
                                    let status = match request.uri().path() {
                                        "/v1/denied" => 403,
                                        "/v1/unavailable" => 503,
                                        _ => 200,
                                    };
                                    response(status, "text/plain", identity.subject().to_owned())
                                }
                            };
                        let service = service_fn(move |request| {
                            let platform = platform.clone();
                            let handler = handler.clone();
                            async move {
                                Ok::<_, Infallible>(platform.dispatch(request, &handler).await)
                            }
                        });
                        hyper::server::conn::http1::Builder::new()
                            .keep_alive(false)
                            .serve_connection(TokioIo::new(tls), service)
                            .await
                            .unwrap();
                    });
                }
            });
            let first = call(address, connector.clone(), "/auth/session", Some(&a), None).await;
            assert_eq!(first.0, 200);
            assert_eq!(first.2, r#"{"authenticated":true}"#);
            assert_eq!(view(&first.1), Some(av.as_str()));
            assert_eq!(first.1["cache-control"], "no-store");
            assert!(!wire::opaque(&av));
            assert_ne!(av, bv);
            let other = call(address, connector.clone(), "/auth/session", Some(&b), None).await;
            assert_eq!(view(&other.1), Some(bv.as_str()));
            for id in [None, Some(expired.as_str()), Some(av.as_str())] {
                let r = call(address, connector.clone(), "/v1/x", id, None).await;
                assert_eq!(r.0, 401);
                assert_eq!(view(&r.1), None);
            }
            for (path, status) in [("/v1/denied", 403), ("/v1/unavailable", 503)] {
                let r = call(address, connector.clone(), path, Some(&b), Some(&av)).await;
                assert_eq!(r.0, status);
                assert_eq!(view(&r.1), Some(bv.as_str()));
                assert_eq!(r.2, "session-b");
            }
            for id in [None, Some(expired.as_str())] {
                let r = call(address, connector.clone(), "/auth/session", id, None).await;
                assert_eq!(r.0, 401);
                assert_eq!(view(&r.1), None);
            }
            let delayed = tokio::spawn({
                let connector = connector.clone();
                let a = a.clone();
                async move { call(address, connector, "/v1/delayed", Some(&a), None).await }
            });
            started.notified().await;
            let logout = call(address, connector.clone(), "/auth/logout", Some(&a), None).await;
            assert_eq!(logout.0, 200);
            let current = call(address, connector.clone(), "/v1/x", Some(&b), Some(&av)).await;
            assert_eq!(current.2, "session-b");
            assert_eq!(view(&current.1), Some(bv.as_str()));
            release.notify_one();
            let old = delayed.await.unwrap();
            assert_eq!(old.0, 200);
            assert_eq!(old.2, "session-a");
            assert_eq!(view(&old.1), Some(av.as_str()));
            let removed = call(address, connector, "/auth/session", Some(&a), None).await;
            assert_eq!(removed.0, 401);
            assert_eq!(view(&removed.1), None);
            server.abort();
            let _ = server.await;
        })
        .await
        .expect("fixture deadline");
    });
}
