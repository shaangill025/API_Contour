//! Fixed-target HTTP/1 transport. All library errors are collapsed at the connector
//! boundary because hyper-util may emit connector errors at tracing level.
use super::{ForwardBody, Rejection, certificate_failure, exact_dns_san, report_rejection};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{
    Request, Uri,
    body::{Body, Frame},
    rt::Executor,
};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{CaptureConnection, Connected, Connection, capture_connection},
    },
    rt::{TokioIo, TokioTimer},
};
use rustls::pki_types::ServerName;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::Instant,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tower_service::Service;

const MAX_CONNECTIONS: usize = 64;
const ABSOLUTE_LIFETIME: Duration = Duration::from_secs(300);
const IDLE_LIFETIME: Duration = Duration::from_secs(15);

#[derive(Default)]
struct Tasks(Mutex<Vec<JoinHandle<()>>>);
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in self.0.get_mut().unwrap().drain(..) {
            task.abort();
        }
    }
}
#[derive(Clone)]
struct OwnedExecutor(Weak<Tasks>);
impl<F: Future<Output = ()> + Send + 'static> Executor<F> for OwnedExecutor {
    fn execute(&self, future: F) {
        let Some(tasks) = self.0.upgrade() else {
            return;
        };
        let mut handles = tasks.0.lock().unwrap();
        handles.retain(|h| !h.is_finished());
        // At most 64 connection drivers, 64 on-idle waiters, 64 speculative
        // connectors, and the pool timer can be live. Bound all owned tasks.
        if handles.len() < 256 {
            handles.push(tokio::spawn(future));
        }
    }
}

#[derive(Default)]
struct OwnerState {
    owner: Option<Arc<()>>,
    pending_close: bool,
}
#[derive(Default)]
struct Control {
    closed: AtomicBool,
    waker: Mutex<Option<Waker>>,
    owner: Mutex<OwnerState>,
}
impl Control {
    // Called while the request/IO gate is held. A pending close belongs to the
    // previous owner, so retire that IO before transferring it to a new owner.
    fn claim(&self, token: &Arc<()>) {
        let mut state = self.owner.lock().unwrap();
        if state.pending_close {
            self.closed.store(true, Ordering::Release);
        } else {
            state.owner = Some(token.clone());
        }
    }
    fn close_for(&self, token: &Arc<()>) {
        let mut state = self.owner.lock().unwrap();
        if state
            .owner
            .as_ref()
            .is_none_or(|owner| Arc::ptr_eq(owner, token))
        {
            state.pending_close = true;
            drop(state);
            if let Some(w) = self.waker.lock().unwrap().take() {
                w.wake();
            }
        }
    }
    fn check(&self, cx: &Context<'_>) -> io::Result<()> {
        *self.waker.lock().unwrap() = Some(cx.waker().clone());
        if self.owner.lock().unwrap().pending_close {
            self.closed.store(true, Ordering::Release);
        }
        if self.closed.load(Ordering::Acquire) {
            Err(io::Error::other("upstream closed"))
        } else {
            Ok(())
        }
    }
}

struct Stream {
    io: TlsStream<TcpStream>,
    _permit: OwnedSemaphorePermit,
    control: Arc<Control>,
    gate: Arc<Mutex<()>>,
}
impl Stream {
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        self.control.check(cx)
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let gate = self.gate.clone();
        let _gate = gate.lock().unwrap();
        self.check(cx)?;
        Pin::new(&mut self.io)
            .poll_read(cx, buf)
            .map(|r| r.map_err(|_| io::Error::other("upstream IO")))
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let gate = self.gate.clone();
        let _gate = gate.lock().unwrap();
        self.check(cx)?;
        Pin::new(&mut self.io)
            .poll_write(cx, buf)
            .map(|r| r.map_err(|_| io::Error::other("upstream IO")))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let gate = self.gate.clone();
        let _gate = gate.lock().unwrap();
        self.check(cx)?;
        Pin::new(&mut self.io)
            .poll_flush(cx)
            .map(|r| r.map_err(|_| io::Error::other("upstream IO")))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io)
            .poll_shutdown(cx)
            .map(|r| r.map_err(|_| io::Error::other("upstream IO")))
    }
}
struct ConnectionIo {
    io: TokioIo<Stream>,
    control: Arc<Control>,
}
impl Connection for ConnectionIo {
    fn connected(&self) -> Connected {
        Connected::new().extra(self.control.clone())
    }
}
impl hyper::rt::Read for ConnectionIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl hyper::rt::Write for ConnectionIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
#[derive(Clone)]
struct Connector {
    address: SocketAddr,
    name: String,
    tls: TlsConnector,
    permits: Arc<Semaphore>,
    gate: Arc<Mutex<()>>,
}
impl Service<Uri> for Connector {
    type Response = ConnectionIo;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let fail = || io::Error::other("upstream unavailable");
            // No pending semaphore waiters: speculative connects are bounded too.
            let permit = this.permits.try_acquire_owned().map_err(|_| fail())?;
            let stream = tokio::time::timeout(Duration::from_secs(15), async {
                let socket = TcpStream::connect(this.address).await.map_err(|_| fail())?;
                let name = ServerName::try_from(this.name.clone()).map_err(|_| fail())?;
                this.tls.connect(name, socket).await.map_err(|e| {
                    if certificate_failure(&e) {
                        report_rejection(Rejection::UpstreamCertificate);
                    }
                    fail()
                })
            })
            .await
            .map_err(|_| fail())??;
            let cert = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .ok_or_else(fail)?;
            if !exact_dns_san(cert, &this.name) {
                report_rejection(Rejection::UpstreamCertificate);
                return Err(fail());
            }
            if stream
                .get_ref()
                .1
                .alpn_protocol()
                .is_some_and(|a| a != b"http/1.1")
            {
                return Err(fail());
            }
            let control = Arc::new(Control::default());
            let io = Stream {
                io: stream,
                _permit: permit,
                control: control.clone(),
                gate: this.gate.clone(),
            };
            Ok(ConnectionIo {
                io: TokioIo::new(io),
                control,
            })
        })
    }
}

pub(super) struct Upstream {
    generation: Mutex<(Instant, Client<Connector, ForwardBody>)>,
    connector: Connector,
    tasks: Arc<Tasks>,
}
impl Upstream {
    fn client(connector: Connector, tasks: &Arc<Tasks>) -> Client<Connector, ForwardBody> {
        let mut builder = Client::builder(OwnedExecutor(Arc::downgrade(tasks)));
        builder
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(IDLE_LIFETIME)
            .pool_max_idle_per_host(MAX_CONNECTIONS)
            .retry_canceled_requests(false)
            .set_host(false);
        builder.build(connector)
    }
    pub fn new(address: SocketAddr, name: String, tls: TlsConnector) -> Self {
        let tasks = Arc::new(Tasks::default());
        let connector = Connector {
            address,
            name,
            tls,
            permits: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            gate: Arc::new(Mutex::new(())),
        };
        let client = Self::client(connector.clone(), &tasks);
        Self {
            generation: Mutex::new((Instant::now(), client)),
            connector,
            tasks,
        }
    }
    fn current_client(&self) -> Client<Connector, ForwardBody> {
        let mut generation = self.generation.lock().unwrap();
        if generation.0.elapsed() >= ABSOLUTE_LIFETIME {
            *generation = (
                Instant::now(),
                Self::client(self.connector.clone(), &self.tasks),
            );
        }
        generation.1.clone()
    }
    pub async fn request(
        &self,
        mut request: Request<ForwardBody>,
    ) -> Result<hyper::Response<ForwardBody>, ()> {
        let captured = capture_connection(&mut request);
        let token = Arc::new(());
        let head_guard = Guard::new(captured.clone(), token.clone());
        let pair = Arc::new(Pair {
            request: AtomicBool::new(false),
            response: AtomicBool::new(false),
            captured: captured.clone(),
            token: token.clone(),
        });
        let (parts, body) = request.into_parts();
        let body = GuardBody::new(body, pair.clone(), true).boxed_unsync();
        let client = self.current_client();
        let mut future = Box::pin(client.request(Request::from_parts(parts, body)));
        let response = std::future::poll_fn(|cx| {
            // Serialize assignment with socket IO. Hyper captures metadata during
            // this poll before it can send the request on its driver task.
            let _gate = self.connector.gate.lock().unwrap();
            let result = future.as_mut().poll(cx);
            with_control(&captured, |control| control.claim(&token));
            result
        })
        .await
        .map_err(|_| ())?;
        head_guard.complete();
        let (parts, body) = response.into_parts();
        Ok(hyper::Response::from_parts(
            parts,
            GuardBody::new(body, pair, false).boxed_unsync(),
        ))
    }
}

struct Pair {
    request: AtomicBool,
    response: AtomicBool,
    captured: CaptureConnection,
    token: Arc<()>,
}
impl Pair {
    fn finish(&self, request: bool) {
        if request {
            self.request.store(true, Ordering::Release);
        } else {
            self.response.store(true, Ordering::Release);
            // An upstream may respond while it is still waiting for a request
            // body. Do not leave that upload (and its IO permit) running after
            // the response is already complete.
            if !self.request.load(Ordering::Acquire) {
                close(&self.captured, &self.token);
            }
        }
    }
}
struct GuardBody<B> {
    inner: B,
    pair: Arc<Pair>,
    request: bool,
    done: bool,
}
impl<B: Body> GuardBody<B> {
    fn new(inner: B, pair: Arc<Pair>, request: bool) -> Self {
        let done = inner.is_end_stream();
        if done {
            pair.finish(request);
        }
        Self {
            inner,
            pair,
            request,
            done,
        }
    }
}
impl<B: Body<Data = Bytes, Error = hyper::Error> + Unpin> Body for GuardBody<B> {
    type Data = Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(&result, Poll::Ready(None))
            || matches!(&result, Poll::Ready(Some(Ok(frame))) if frame.is_trailers() || self.inner.is_end_stream())
        {
            self.done = true;
            self.pair.finish(self.request);
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
impl<B> Drop for GuardBody<B> {
    fn drop(&mut self) {
        if !self.done {
            close(&self.pair.captured, &self.pair.token);
        }
    }
}
fn with_control(captured: &CaptureConnection, f: impl FnOnce(&Control)) {
    if let Some(conn) = captured.connection_metadata().as_ref() {
        let mut ext = hyper::http::Extensions::new();
        conn.get_extras(&mut ext);
        if let Some(control) = ext.get::<Arc<Control>>() {
            f(control);
        }
    }
}
fn close(captured: &CaptureConnection, token: &Arc<()>) {
    with_control(captured, |control| control.close_for(token));
}

struct Guard {
    captured: CaptureConnection,
    token: Arc<()>,
    complete: bool,
}
impl Guard {
    fn new(captured: CaptureConnection, token: Arc<()>) -> Self {
        Self {
            captured,
            token,
            complete: false,
        }
    }
    fn complete(mut self) {
        self.complete = true;
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.complete {
            close(&self.captured, &self.token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::SizeHint;
    use std::{collections::VecDeque, sync::atomic::AtomicUsize, task::Wake};

    struct Frames(VecDeque<Frame<Bytes>>);
    impl Body for Frames {
        type Data = Bytes;
        type Error = hyper::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.pop_front().map(Ok))
        }
        fn is_end_stream(&self) -> bool {
            self.0.is_empty()
        }
        fn size_hint(&self) -> SizeHint {
            SizeHint::default()
        }
    }
    fn pair() -> Arc<Pair> {
        let mut request = Request::new(());
        Arc::new(Pair {
            request: AtomicBool::new(false),
            response: AtomicBool::new(false),
            captured: capture_connection(&mut request),
            token: Arc::new(()),
        })
    }
    #[test]
    fn completion_covers_empty_final_data_and_trailers() {
        let p = pair();
        let _empty = GuardBody::new(Frames(VecDeque::new()), p.clone(), true);
        assert!(p.request.load(Ordering::Acquire));
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-end", hyper::header::HeaderValue::from_static("yes"));
        let mut body = GuardBody::new(
            Frames(VecDeque::from([
                Frame::data(Bytes::from_static(b"a")),
                Frame::trailers(trailers),
            ])),
            p.clone(),
            false,
        );
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(Pin::new(&mut body).poll_frame(&mut cx).is_ready());
        assert!(!p.response.load(Ordering::Acquire));
        assert!(Pin::new(&mut body).poll_frame(&mut cx).is_ready());
        assert!(p.response.load(Ordering::Acquire));
        let p = pair();
        let mut body = GuardBody::new(
            Frames(VecDeque::from([Frame::data(Bytes::from_static(b"a"))])),
            p.clone(),
            false,
        );
        assert!(Pin::new(&mut body).poll_frame(&mut cx).is_ready());
        assert!(p.response.load(Ordering::Acquire));
    }
    #[test]
    fn terminal_trailers_complete_even_when_inner_end_stream_is_false() {
        struct IncomingLike(Option<Frame<Bytes>>);
        impl Body for IncomingLike {
            type Data = Bytes;
            type Error = hyper::Error;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
                Poll::Ready(self.0.take().map(Ok))
            }
            fn is_end_stream(&self) -> bool {
                false
            }
        }
        for request in [true, false] {
            let p = pair();
            if !request {
                p.request.store(true, Ordering::Release);
            }
            let mut trailers = hyper::HeaderMap::new();
            trailers.insert("x-end", hyper::header::HeaderValue::from_static("yes"));
            let mut body = GuardBody::new(
                IncomingLike(Some(Frame::trailers(trailers))),
                p.clone(),
                request,
            );
            let mut cx = Context::from_waker(Waker::noop());
            assert!(
                matches!(Pin::new(&mut body).poll_frame(&mut cx), Poll::Ready(Some(Ok(frame))) if frame.is_trailers())
            );
            assert!(
                body.done,
                "terminal trailers must complete before Hyper drops the body"
            );
            assert!(if request {
                p.request.load(Ordering::Acquire)
            } else {
                p.response.load(Ordering::Acquire)
            });
            drop(body);
        }
    }
    struct CountWake(AtomicUsize);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn closing_a_connection_wakes_the_io_driver() {
        let control = Control::default();
        let count = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        assert!(control.check(&Context::from_waker(&waker)).is_ok());
        let token = Arc::new(());
        control.claim(&token);
        control.close_for(&token);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(control.check(&Context::from_waker(&waker)).is_err());
    }
    #[test]
    fn rotation_keeps_the_shared_connection_cap() {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let upstream = Upstream::new(
            ([127, 0, 0, 1], 443).into(),
            "example.test".into(),
            TlsConnector::from(Arc::new(config)),
        );
        let before = upstream.connector.permits.clone();
        upstream.generation.lock().unwrap().0 = Instant::now() - ABSOLUTE_LIFETIME;
        let _client = upstream.current_client();
        assert!(upstream.generation.lock().unwrap().0.elapsed() < Duration::from_secs(1));
        assert!(Arc::ptr_eq(&before, &upstream.connector.permits));
        assert_eq!(before.available_permits(), MAX_CONNECTIONS);
    }
    #[test]
    fn dropping_task_owner_aborts_driver() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let tasks = Arc::new(Tasks::default());
                let exec = OwnedExecutor(Arc::downgrade(&tasks));
                let (tx, rx) = tokio::sync::oneshot::channel::<()>();
                exec.execute(async move {
                    let _ = rx.await;
                });
                drop(tasks);
                tokio::task::yield_now().await;
                assert!(tx.is_closed());
            });
    }
}

#[cfg(test)]
mod runtime_tests;
