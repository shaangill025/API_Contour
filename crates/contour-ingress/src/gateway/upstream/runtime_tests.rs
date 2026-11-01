//! Loopback TLS regressions use only independently generated synthetic certificates.
#[path = "fixture.rs"]
mod fixture;
thread_local! { static FIXTURE: fixture::Fixture = fixture::Fixture::new(); }
use super::*;
use http_body_util::{BodyExt, Full};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};
use std::convert::Infallible;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

const LIMIT: Duration = Duration::from_secs(5);
fn fixture(name: &str) -> Vec<u8> {
    let file = match name {
        "CONTOUR_POOL_TEST_CA" => "ca.der",
        "CONTOUR_POOL_TEST_OTHER_CA" => "other.der",
        "CONTOUR_POOL_TEST_SERVER_CERT" => "server.der",
        "CONTOUR_POOL_TEST_SERVER_KEY" => "server.key.der",
        "CONTOUR_POOL_TEST_CLIENT_CERT" => "client.der",
        "CONTOUR_POOL_TEST_CLIENT_KEY" => "client.key.der",
        _ => panic!("unknown synthetic fixture"),
    };
    FIXTURE.with(|fixture| fixture.read(file))
}
fn roots(name: &str) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(fixture(name))).unwrap();
    roots
}
fn key(name: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::try_from(fixture(name)).unwrap()
}
fn server_config(mtls: bool) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = if mtls {
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots("CONTOUR_POOL_TEST_CA")))
            .build()
            .unwrap();
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder
        .with_single_cert(
            vec![CertificateDer::from(fixture(
                "CONTOUR_POOL_TEST_SERVER_CERT",
            ))],
            key("CONTOUR_POOL_TEST_SERVER_KEY"),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}
fn client_config(ca: &str, client_auth: bool) -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(ca));
    let mut config = if client_auth {
        builder
            .with_client_auth_cert(
                vec![CertificateDer::from(fixture(
                    "CONTOUR_POOL_TEST_CLIENT_CERT",
                ))],
                key("CONTOUR_POOL_TEST_CLIENT_KEY"),
            )
            .unwrap()
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(config))
}
fn runtime(f: impl Future<Output = ()>) {
    FIXTURE.with(|_| ());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            timeout(Duration::from_secs(30), f)
                .await
                .expect("test exceeded deadline");
        });
}
async fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}
fn upstream(addr: SocketAddr, name: &str, ca: &str, mtls: bool) -> Upstream {
    Upstream::new(addr, name.to_owned(), client_config(ca, mtls))
}
fn request(method: &str) -> Request<ForwardBody> {
    Request::builder()
        .method(method)
        .uri("http://upstream.test/test")
        .body(
            Full::new(Bytes::new())
                .map_err(|never: Infallible| match never {})
                .boxed_unsync(),
        )
        .unwrap()
}
async fn call(pool: &Upstream, method: &str) -> Result<hyper::Response<ForwardBody>, ()> {
    timeout(LIMIT, pool.request(request(method)))
        .await
        .expect("request timeout")
}
async fn read_head(stream: &mut TlsStream<TcpStream>) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut one = [0; 1];
    loop {
        match timeout(LIMIT, stream.read(&mut one))
            .await
            .expect("timed out waiting for HTTP header or socket close")
        {
            Ok(0) => {
                assert!(result.is_empty(), "EOF in a partial request header");
                return None;
            }
            Err(error)
                if result.is_empty()
                    && matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::UnexpectedEof
                    ) =>
            {
                return None;
            }
            Err(error) => panic!("socket read failed or partial request header: {error}"),
            Ok(_) => {
                result.push(one[0]);
                if result.ends_with(b"\r\n\r\n") {
                    return Some(result);
                }
                if result.len() > 8192 {
                    panic!("request header too large");
                }
            }
        }
    }
}
async fn accepted(listener: &TcpListener, config: Arc<ServerConfig>) -> TlsStream<TcpStream> {
    let (socket, _) = timeout(LIMIT, listener.accept())
        .await
        .expect("accept timeout")
        .unwrap();
    timeout(LIMIT, TlsAcceptor::from(config).accept(socket))
        .await
        .expect("TLS timeout")
        .unwrap()
}
async fn wait_permits(permits: &Semaphore, count: usize) {
    timeout(LIMIT, async {
        while permits.available_permits() != count {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("permits not returned");
}

#[test]
fn sequential_reuse_and_idle_eof_post_no_duplicate() {
    runtime(async {
        let l = listener().await;
        let addr = l.local_addr().unwrap();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let complete = Arc::new(AtomicBool::new(false));
        let complete_server = complete.clone();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_server = count.clone();
        let server = tokio::spawn(async move {
            let mut first = accepted(&l, server_config(false)).await;
            let h = read_head(&mut first).await.unwrap();
            assert!(h.starts_with(b"GET "));
            first
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let h = read_head(&mut first).await.unwrap();
            assert!(h.starts_with(b"POST "));
            first
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            first.shutdown().await.unwrap();
            closed_tx.send(()).unwrap();
            let mut children = tokio::task::JoinSet::new();
            loop {
                match timeout(Duration::from_millis(200), l.accept()).await {
                    Ok(Ok((socket, _))) => {
                        let count = count_server.clone();
                        children.spawn(async move {
                            if let Ok(Ok(mut stream)) = timeout(
                                LIMIT,
                                TlsAcceptor::from(server_config(false)).accept(socket),
                            )
                            .await
                            {
                                while let Ok(Some(head)) =
                                    timeout(Duration::from_millis(200), read_head(&mut stream))
                                        .await
                                {
                                    assert!(head.starts_with(b"POST "));
                                    count.fetch_add(1, Ordering::SeqCst);
                                    stream
                                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                                        .await
                                        .unwrap();
                                }
                            }
                        });
                    }
                    Ok(Err(error)) => panic!("accept failed: {error}"),
                    Err(_) if complete_server.load(Ordering::SeqCst) => break,
                    Err(_) => {}
                }
            }
            while let Some(child) = children.join_next().await {
                child.unwrap();
            }
        });
        let pool = upstream(addr, "upstream.test", "CONTOUR_POOL_TEST_CA", false);
        call(&pool, "GET")
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        call(&pool, "POST")
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        closed_rx.await.unwrap();
        let succeeded = match call(&pool, "POST").await {
            Ok(response) => {
                response.into_body().collect().await.unwrap();
                true
            }
            Err(()) => false,
        };
        complete.store(true, Ordering::SeqCst);
        timeout(LIMIT, server).await.unwrap().unwrap();
        let posts = count.load(Ordering::SeqCst);
        assert!(posts <= 1, "one POST attempt was sent more than once");
        if succeeded {
            assert_eq!(posts, 1, "successful POST requires a server response");
        }
    });
}

#[test]
fn truncated_and_abandoned_bodies_discard_connection() {
    runtime(async {
        let l = listener().await;
        let addr = l.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut a = accepted(&l, server_config(false)).await;
            read_head(&mut a).await.unwrap();
            a.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx")
                .await
                .unwrap();
            a.shutdown().await.unwrap();
            let mut b = accepted(&l, server_config(false)).await;
            read_head(&mut b).await.unwrap();
            b.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
                .await
                .unwrap();
            // Dropping the downstream body must close the connection without draining.
            assert!(read_head(&mut b).await.is_none());
            let mut c = accepted(&l, server_config(false)).await;
            read_head(&mut c).await.unwrap();
            c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let pool = upstream(addr, "upstream.test", "CONTOUR_POOL_TEST_CA", false);
        assert!(
            call(&pool, "GET")
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .is_err()
        );
        drop(call(&pool, "GET").await.unwrap());
        wait_permits(&pool.connector.permits, 64).await;
        call(&pool, "GET")
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        timeout(LIMIT, server).await.unwrap().unwrap();
    });
}

struct NeverBody;
impl Body for NeverBody {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        Poll::Pending
    }
}
async fn early_response_case(nonempty: bool) {
    let l = listener().await;
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = accepted(&l, server_config(false)).await;
        read_head(&mut stream).await.unwrap();
        let response = if nonempty {
            b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 1\r\n\r\nx".as_slice()
        } else {
            b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n".as_slice()
        };
        stream.write_all(response).await.unwrap();
        assert!(read_head(&mut stream).await.is_none());
        let mut next = accepted(&l, server_config(false)).await;
        read_head(&mut next).await.unwrap();
        next.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let pool = upstream(addr, "upstream.test", "CONTOUR_POOL_TEST_CA", false);
    let req = Request::builder()
        .method("POST")
        .uri("http://upstream.test/upload")
        .body(NeverBody.boxed_unsync())
        .unwrap();
    let response = timeout(LIMIT, pool.request(req))
        .await
        .expect("early response timed out")
        .expect("early response must reach the downstream caller");
    assert_eq!(response.status(), hyper::StatusCode::PAYLOAD_TOO_LARGE);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        bytes,
        if nonempty {
            Bytes::from_static(b"x")
        } else {
            Bytes::new()
        }
    );
    wait_permits(&pool.connector.permits, 64).await;
    call(&pool, "GET")
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    timeout(LIMIT, server).await.unwrap().unwrap();
}
#[test]
fn early_response_closes_incomplete_outgoing_body() {
    runtime(async {
        early_response_case(false).await;
        early_response_case(true).await;
    });
}

#[test]
fn cancel_waiting_for_headers_closes_connection() {
    runtime(async {
        let l = listener().await;
        let addr = l.local_addr().unwrap();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut first = accepted(&l, server_config(false)).await;
            read_head(&mut first).await.unwrap();
            ready_tx.send(()).unwrap();
            assert!(read_head(&mut first).await.is_none());
            let mut second = accepted(&l, server_config(false)).await;
            read_head(&mut second).await.unwrap();
            second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let pool = Arc::new(upstream(
            addr,
            "upstream.test",
            "CONTOUR_POOL_TEST_CA",
            false,
        ));
        let request_pool = pool.clone();
        let task = tokio::spawn(async move { call(&request_pool, "POST").await });
        ready_rx.await.unwrap();
        task.abort();
        let _ = task.await;
        wait_permits(&pool.connector.permits, 64).await;
        call(&pool, "GET").await.unwrap();
        timeout(LIMIT, server).await.unwrap().unwrap();
    });
}

#[test]
fn cap_counts_stalled_bodies_and_recovers() {
    runtime(async {
        let l = listener().await;
        let addr = l.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            for index in 0..65 {
                let mut stream = accepted(&l, server_config(false)).await;
                children.spawn(async move {
                    read_head(&mut stream).await.unwrap();
                    if index < 64 {
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx")
                            .await
                            .unwrap();
                        assert!(read_head(&mut stream).await.is_none());
                    } else {
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap();
                    }
                });
            }
            while let Some(result) = children.join_next().await {
                result.unwrap();
            }
        });
        let pool = upstream(addr, "upstream.test", "CONTOUR_POOL_TEST_CA", false);
        let mut responses = Vec::new();
        for _ in 0..64 {
            responses.push(call(&pool, "GET").await.unwrap());
        }
        assert_eq!(pool.connector.permits.available_permits(), 0);
        assert!(call(&pool, "GET").await.is_err());
        drop(responses);
        wait_permits(&pool.connector.permits, 64).await;
        call(&pool, "GET")
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        timeout(LIMIT, server).await.unwrap().unwrap();
    });
}

#[test]
fn rollover_keeps_active_body_and_pool_drop_closes_idle() {
    runtime(async {
        let l = listener().await;
        let addr = l.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut old = accepted(&l, server_config(false)).await;
            read_head(&mut old).await.unwrap();
            old.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                .await
                .unwrap();
            let mut new = accepted(&l, server_config(false)).await;
            read_head(&mut new).await.unwrap();
            new.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            old.write_all(b"x").await.unwrap();
            assert!(read_head(&mut old).await.is_none());
            assert!(read_head(&mut new).await.is_none());
        });
        let pool = upstream(addr, "upstream.test", "CONTOUR_POOL_TEST_CA", false);
        let body = call(&pool, "GET").await.unwrap().into_body();
        pool.generation.lock().unwrap().0 = Instant::now() - ABSOLUTE_LIFETIME;
        call(&pool, "GET")
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        assert_eq!(
            timeout(LIMIT, body.collect())
                .await
                .unwrap()
                .unwrap()
                .to_bytes(),
            Bytes::from_static(b"x")
        );
        drop(pool);
        timeout(LIMIT, server).await.unwrap().unwrap();
    });
}

#[test]
fn tls_name_trust_client_identity_failures_and_recovery() {
    runtime(async {
        let l = listener().await;
        let addr = l.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let config = server_config(true);
            for attempt in 0..4 {
                let (socket, _) = timeout(LIMIT, l.accept()).await.unwrap().unwrap();
                if let Ok(Ok(mut stream)) =
                    timeout(LIMIT, TlsAcceptor::from(config.clone()).accept(socket)).await
                {
                    if attempt == 3 {
                        read_head(&mut stream).await.unwrap();
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap();
                    }
                }
            }
        });
        let wrong_name = upstream(addr, "wrong.test", "CONTOUR_POOL_TEST_CA", true);
        assert!(call(&wrong_name, "GET").await.is_err());
        let wrong_ca = upstream(addr, "upstream.test", "CONTOUR_POOL_TEST_OTHER_CA", true);
        assert!(call(&wrong_ca, "GET").await.is_err());
        let no_client = upstream(addr, "upstream.test", "CONTOUR_POOL_TEST_CA", false);
        assert!(call(&no_client, "GET").await.is_err());
        let correct = upstream(addr, "upstream.test", "CONTOUR_POOL_TEST_CA", true);
        call(&correct, "GET")
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        timeout(LIMIT, server).await.unwrap().unwrap();
    });
}

#[test]
fn dropping_unread_previous_body_cannot_close_next_post() {
    runtime(async {
        let l = listener().await;
        let addr = l.local_addr().unwrap();
        let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut socket = accepted(&l, server_config(false)).await;
            assert!(read_head(&mut socket).await.unwrap().starts_with(b"GET "));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
                .await
                .unwrap();
            let next = read_head(&mut socket)
                .await
                .expect("POST must reuse the same socket");
            assert!(next.starts_with(b"POST "));
            observed_tx.send(()).unwrap();
            release_rx.await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            // A duplicate POST on the same connection is forbidden.
            if let Some(extra) = read_head(&mut socket).await {
                assert!(!extra.starts_with(b"POST "));
            }
        });
        let pool = Arc::new(upstream(
            addr,
            "upstream.test",
            "CONTOUR_POOL_TEST_CA",
            false,
        ));
        let unread_a = call(&pool, "GET").await.unwrap();
        // Reserve the other 63 permits: any POST B seen by the server must
        // use A's one socket, and no replacement socket can mask the race.
        let permits = pool
            .connector
            .permits
            .clone()
            .acquire_many_owned(63)
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;
        let b_pool = pool.clone();
        let post = tokio::spawn(async move { call(&b_pool, "POST").await });
        timeout(LIMIT, observed_rx)
            .await
            .expect("POST never reached the first socket")
            .unwrap();
        drop(unread_a);
        release_tx.send(()).unwrap();
        let response = timeout(LIMIT, post)
            .await
            .unwrap()
            .unwrap()
            .expect("dropping A must not close B");
        response.into_body().collect().await.unwrap();
        drop(permits);
        drop(pool);
        timeout(LIMIT, server).await.unwrap().unwrap();
    });
}
