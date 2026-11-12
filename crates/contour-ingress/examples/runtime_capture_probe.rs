//! Fixture-only HTTP/1 application. Requires a real signed authority endpoint.
//! The controlling driver owns all endpoints and verifies delivered records.
use bytes::Bytes;
use contour_core::{PolicyKeys, QueueLimits};
use contour_delivery::{
    CollectorOwner, CollectorPool, DeliveryClient, SendOutcome, StructuralAdapter,
};
use contour_ingress::{
    CollectorTls,
    runtime_capture::{CapturePoint, RuntimeCapture},
};
use http_body_util::BodyExt;
use hyper::{
    Request, Response,
    body::{Body, Frame, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    convert::Infallible,
    env, fs,
    io::{self, BufRead},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{RwLock, Semaphore},
    time::{Instant, sleep, timeout, timeout_at},
};

struct Barrier {
    reached: Semaphore,
    release: Semaphore,
}
impl Default for Barrier {
    fn default() -> Self {
        Self {
            reached: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    server_certificate_der: String,
    server_key_der: String,
    client_ca_der: String,
    delivery_address: SocketAddr,
    delivery_name: String,
    delivery_ca_der: String,
    delivery_client_certificate_der: String,
    delivery_client_key_der: String,
    tenant: String,
    collector: String,
    source: String,
    workload: [String; 4],
    policy_key_id: String,
    policy_key_file: String,
}
fn read(path: &str, max: usize) -> Result<Vec<u8>, &'static str> {
    let bytes = fs::read(path).map_err(|_| "fixture file unavailable")?;
    if bytes.is_empty() || bytes.len() > max {
        return Err("fixture file size invalid");
    }
    Ok(bytes)
}
fn id() -> Result<String, &'static str> {
    let mut b = [0u8; 16];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "random unavailable")?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    Ok(format!(
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
struct FixtureBody(VecDeque<Frame<Bytes>>);
impl Body for FixtureBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.pop_front().map(Ok))
    }
    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }
}
async fn app(
    request: Request<Incoming>,
    capture: Arc<RwLock<RuntimeCapture>>,
    barrier: Arc<Barrier>,
) -> Result<Response<contour_ingress::runtime_capture::ObservedBody<FixtureBody>>, Infallible> {
    let observer = capture.read().await.clone();
    let (request, response_context) = observer.request(request);
    // This is test behavior only. Drop exercises cancellation; normal requests
    // consume the actual Hyper body, without logging or echoing its raw bytes.
    let drop_request = request
        .headers()
        .get("x-fixture-drop")
        .is_some_and(|v| v == "request");
    let response_trailers = request
        .headers()
        .get("x-fixture-trailers")
        .is_some_and(|v| v == "yes");
    let hold = request
        .headers()
        .get("x-fixture-hold")
        .is_some_and(|v| v == "yes");
    if drop_request {
        drop(request);
    } else {
        let mut body = request.into_body();
        if hold && matches!(body.frame().await, Some(Ok(frame)) if frame.data_ref().is_some()) {
            barrier.reached.add_permits(1);
            if let Ok(permit) = barrier.release.acquire().await {
                permit.forget();
            }
        }
        let _ = body.collect().await;
    }
    let mut frames = VecDeque::from([
        Frame::data(Bytes::from_static(b"{\"result\":")),
        Frame::data(Bytes::from_static(b"1}")),
    ]);
    if response_trailers {
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert(
            "x-fixture-proof",
            hyper::header::HeaderValue::from_static("present"),
        );
        frames.push_back(Frame::trailers(trailers));
    }
    let response = Response::builder()
        .status(201)
        .header("content-type", "application/json")
        .body(FixtureBody(frames))
        .expect("static fixture response");
    Ok(response_context.response(response))
}
async fn serve_stream<T>(stream: T, capture: Arc<RwLock<RuntimeCapture>>, barrier: Arc<Barrier>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| app(request, capture.clone(), barrier.clone()));
    let _ = http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await;
}
fn main() {
    if let Err(error) = run() {
        eprintln!("runtime capture fixture: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    let path = args.next().ok_or("config missing")?;
    if args.next().is_some() {
        return Err("unexpected argument");
    }
    let c: Config = serde_json::from_slice(&read(&path, 16384)?).map_err(|_| "config invalid")?;
    if !c.delivery_address.ip().is_loopback() {
        return Err("non-loopback fixture endpoint");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "runtime failed")?;
    runtime.block_on(async move {
        let server = read(&c.server_certificate_der, 65536)?;
        let server_key = read(&c.server_key_der, 16384)?;
        let client_ca = read(&c.client_ca_der, 65536)?;
        let tls = Arc::new(
            CollectorTls::from_der(
                &[&server],
                &server_key,
                &[&client_ca],
                Duration::from_secs(5),
            )
            .map_err(|_| "server TLS invalid")?,
        );
        let ca = read(&c.delivery_ca_der, 65536)?;
        let cert = read(&c.delivery_client_certificate_der, 65536)?;
        let key = read(&c.delivery_client_key_der, 16384)?;
        let policy_key: [u8; 32] = read(&c.policy_key_file, 32)?
            .try_into()
            .map_err(|_| "policy key invalid")?;
        let mut owners = Vec::new();
        for _ in 0..4 {
            let client = DeliveryClient::from_der_v2(
                &c.delivery_name,
                c.delivery_address,
                [&c.tenant, &c.collector],
                &[&ca],
                &[&cert],
                &key,
                Duration::from_secs(5),
            )
            .map_err(|_| "delivery TLS invalid")?;
            let keys = PolicyKeys::new(&[(&c.policy_key_id, policy_key)])
                .map_err(|_| "policy key invalid")?;
            owners.push(
                CollectorOwner::new_v2(
                    client,
                    keys,
                    &[&c.source],
                    QueueLimits::new(16, 16384).map_err(|_| "queue invalid")?,
                )
                .map_err(|_| "owner invalid")?,
            );
        }
        let pool = CollectorPool::new(owners).map_err(|_| "pool invalid")?;
        pool.synchronize()
            .await
            .map_err(|_| "authority synchronization failed")?;
        let point = CapturePoint {
            source: c.source,
            workload: c.workload,
            profile: "http_json_v1".into(),
            method: "POST".into(),
            path: "/pilot".into(),
            route: "/pilot".into(),
        };
        let mut adapter = StructuralAdapter::attach(pool.clone()).map_err(|_| "adapter invalid")?;
        let capture = Arc::new(RwLock::new(RuntimeCapture::new(
            adapter.clone(),
            point.clone(),
        )?));
        let barrier = Arc::new(Barrier::default());
        let plain = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "listener failed")?;
        let secure = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "listener failed")?;
        let plain_port = plain.local_addr().map_err(|_| "listener failed")?.port();
        let secure_port = secure.local_addr().map_err(|_| "listener failed")?.port();
        let p = capture.clone();
        let b = barrier.clone();
        let plain_task = tokio::spawn(async move {
            while let Ok((socket, _)) = plain.accept().await {
                tokio::spawn(serve_stream(socket, p.clone(), b.clone()));
            }
        });
        let p = capture.clone();
        let b = barrier.clone();
        let secure_task = tokio::spawn(async move {
            while let Ok((socket, _)) = secure.accept().await {
                let tls = tls.clone();
                let p = p.clone();
                let b = b.clone();
                tokio::spawn(async move {
                    if let Ok(stream) = tls.accept(socket).await {
                        serve_stream(stream, p, b).await;
                    }
                });
            }
        });
        let poll_pool = pool.clone();
        let maintenance = tokio::spawn(async move {
            loop {
                let _ = poll_pool.poll_authority();
                sleep(Duration::from_millis(100)).await;
            }
        });
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in io::stdin().lock().lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        println!("READY {plain_port} {secure_port}");
        while let Some(line) = receiver.recv().await {
            match line.map_err(|_| "command failed")?.as_str() {
                "STOP" => {
                    plain_task.abort();
                    secure_task.abort();
                    maintenance.abort();
                    return Ok(());
                }
                "SYNC" => {
                    pool.synchronize().await.map_err(|_| "sync failed")?;
                    println!("SYNCED");
                }
                "WAIT_HOLD" => {
                    let permit = timeout(Duration::from_secs(10), barrier.reached.acquire())
                        .await
                        .map_err(|_| "hold deadline")?
                        .map_err(|_| "hold unavailable")?;
                    permit.forget();
                    println!("HELD");
                }
                "RELEASE" => {
                    barrier.release.add_permits(1);
                    println!("RELEASED");
                }
                "DETACH" => {
                    loop {
                        if adapter.detach().is_ok() {
                            break;
                        }
                        sleep(Duration::from_millis(10)).await;
                    }
                    println!("DETACHED");
                }
                "ATTACH" => {
                    adapter =
                        StructuralAdapter::attach(pool.clone()).map_err(|_| "adapter invalid")?;
                    *capture.write().await = RuntimeCapture::new(adapter.clone(), point.clone())?;
                    println!("ATTACHED");
                }
                "DRAIN" => {
                    let mut acknowledged = 0;
                    let deadline = Instant::now() + Duration::from_secs(10);
                    for slot in 0..4 {
                        loop {
                            if Instant::now() >= deadline {
                                return Err("drain deadline");
                            }
                            let frozen = match pool.try_freeze(slot, &id()?, 100, 1_048_576) {
                                Ok(value) => value,
                                Err(_) => {
                                    sleep(Duration::from_millis(10)).await;
                                    continue;
                                }
                            };
                            if !frozen {
                                break;
                            }
                            match timeout_at(deadline, pool.send(slot)).await {
                                Ok(Ok(SendOutcome::Acknowledged { .. })) => acknowledged += 1,
                                _ => return Err("delivery failed"),
                            }
                        }
                    }
                    println!("DRAIN {} {acknowledged}", pool.losses());
                }
                _ => return Err("unexpected command"),
            }
        }
        Err("command input closed")
    })
}
