//! Opt-in in-process HTTP/1 body observation. The host owns transport, routing
//! and authority maintenance; HTTPS must already be decrypted by the host.
use bytes::Bytes;
use contour_core::{CaptureScope, OriginWitness, RecordMetadata, Timestamp};
use contour_delivery::{AdapterCapture, StructuralAdapter};
use hyper::{
    Request, Response,
    body::{Body, Frame, SizeHint},
    header::{self, HeaderMap},
};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// All matching and record authority comes from operator configuration.
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
    fn valid(&self) -> bool {
        if self.method.len() > 32
            || self.path.len() > 256
            || self.path != self.route
            || !self.path.starts_with('/')
            || self.path.starts_with("//")
            || self.path.contains(['?', '#', '{', '}'])
        {
            return false;
        }
        let Ok(method) = hyper::Method::from_bytes(self.method.as_bytes()) else {
            return false;
        };
        if method == hyper::Method::CONNECT {
            return false;
        }
        self.path.parse::<hyper::Uri>().ok().is_some_and(|uri| {
            uri.scheme().is_none()
                && uri.authority().is_none()
                && uri.query().is_none()
                && uri
                    .path_and_query()
                    .is_some_and(|p| p.as_str() == self.path)
        })
    }
}

/// Keep the pool's authority maintenance running and retry adapter detachment
/// until it succeeds, as required by StructuralAdapter.
#[derive(Clone)]
pub struct RuntimeCapture {
    adapter: Arc<StructuralAdapter>,
    point: Arc<CapturePoint>,
}
impl RuntimeCapture {
    pub fn new(adapter: Arc<StructuralAdapter>, point: CapturePoint) -> Result<Self, &'static str> {
        if !point.valid() {
            return Err("invalid capture point");
        }
        Ok(Self {
            adapter,
            point: Arc::new(point),
        })
    }
    /// Wrap a request without changing its parts or frames. The opaque response
    /// context is tied to this request and its fixed operator point.
    pub fn request<B: Body<Data = Bytes> + Unpin>(
        &self,
        request: Request<B>,
    ) -> (Request<ObservedBody<B>>, ResponseContext) {
        let (parts, body) = request.into_parts();
        let eligible = request_eligible(&parts, &self.point);
        let capture = (eligible && capture_headers(&parts.headers))
            .then(|| Capture::begin(self.adapter.clone(), self.point.clone(), "request", None))
            .flatten();
        let context = ResponseContext {
            adapter: self.adapter.clone(),
            point: self.point.clone(),
            eligible,
        };
        (
            Request::from_parts(parts, ObservedBody::new(body, capture)),
            context,
        )
    }
}
fn request_eligible(parts: &hyper::http::request::Parts, point: &CapturePoint) -> bool {
    matches!(
        parts.version,
        hyper::Version::HTTP_10 | hyper::Version::HTTP_11
    ) && parts.method.as_str() == point.method
        && parts.uri.path() == point.path
        && parts.uri.query().is_none()
}
/// Single-use response pairing. No request header can modify its scope.
pub struct ResponseContext {
    adapter: Arc<StructuralAdapter>,
    point: Arc<CapturePoint>,
    eligible: bool,
}
impl ResponseContext {
    pub fn response<B: Body<Data = Bytes> + Unpin>(
        self,
        response: Response<B>,
    ) -> Response<ObservedBody<B>> {
        let (parts, body) = response.into_parts();
        let capture = (self.eligible && capture_headers(&parts.headers))
            .then(|| {
                Capture::begin(
                    self.adapter,
                    self.point,
                    "response",
                    Some(parts.status.as_u16()),
                )
            })
            .flatten();
        Response::from_parts(parts, ObservedBody::new(body, capture))
    }
}
fn capture_headers(headers: &HeaderMap) -> bool {
    let encoding_ok = headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .all(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"));
    let mut types = headers.get_all(header::CONTENT_TYPE).iter();
    let json = types.next().and_then(|v| v.to_str().ok()).is_some_and(|v| {
        v.split(';')
            .next()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
    }) && types.next().is_none();
    encoding_ok
        && json
        && !headers.contains_key(header::TRAILER)
        && !headers.contains_key(header::UPGRADE)
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
    ) -> Option<Self> {
        let first = stamp()?;
        let id = uuid()?;
        let token = if adapter.descriptor().origin_v2 {
            adapter.try_begin(&point.scope(), Some(&OriginWitness::Unattributed))
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
    fn cancel(&mut self) {
        if let Some(token) = self.token.take() {
            self.adapter.try_cancel(token);
        }
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
        if self.adapter.try_finish(token, metadata).is_err() {
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
    Timestamp::parse(
        &time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .ok()?,
    )
    .ok()
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
/// Transparent body wrapper. Capture failure never changes application frames.
pub struct ObservedBody<B> {
    inner: B,
    capture: Option<Capture>,
}
impl<B: Body<Data = Bytes> + Unpin> ObservedBody<B> {
    fn new(inner: B, capture: Option<Capture>) -> Self {
        let mut this = Self { inner, capture };
        if this.inner.is_end_stream() {
            if let Some(capture) = this.capture.as_mut() {
                capture.finish();
            }
        }
        this
    }
}
impl<B: Body<Data = Bytes> + Unpin> Body for ObservedBody<B> {
    type Data = Bytes;
    type Error = B::Error;
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
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use std::{collections::VecDeque, task::Waker};

    trait IntoReady<T> {
        fn into_ready(self) -> Option<T>;
    }
    impl<T> IntoReady<T> for Poll<T> {
        fn into_ready(self) -> Option<T> {
            match self {
                Poll::Ready(value) => Some(value),
                Poll::Pending => None,
            }
        }
    }

    fn point() -> CapturePoint {
        CapturePoint {
            source: "source".into(),
            workload: ["w".into(), "n".into(), "s".into(), "i".into()],
            profile: "http_json_v1".into(),
            method: "POST".into(),
            path: "/orders".into(),
            route: "/orders".into(),
        }
    }

    #[test]
    fn point_only_accepts_fixed_origin_form_path() {
        assert!(point().valid());
        for path in [
            "https://example.test/orders",
            "//example.test/orders",
            "/orders?q=x",
            "/orders/{id}",
            "/orders#x",
        ] {
            let mut p = point();
            p.path = path.into();
            p.route = path.into();
            assert!(!p.valid(), "{path}");
        }
        let mut p = point();
        p.route = "/other".into();
        assert!(!p.valid());
        p = point();
        p.method = "CONNECT".into();
        assert!(!p.valid());
    }

    #[test]
    fn request_match_ignores_untrusted_authority_and_rejects_other_scope() {
        let p = point();
        let request = Request::builder()
            .method("POST")
            .uri("http://untrusted.test/orders")
            .header("host", "different.test")
            .body(())
            .unwrap();
        let (mut parts, _) = request.into_parts();
        assert!(request_eligible(&parts, &p));
        parts.uri = "/orders?token=secret".parse().unwrap();
        assert!(!request_eligible(&parts, &p));
        parts.uri = "/other".parse().unwrap();
        assert!(!request_eligible(&parts, &p));
        parts.uri = "/orders".parse().unwrap();
        parts.version = hyper::Version::HTTP_2;
        assert!(!request_eligible(&parts, &p));
        parts.version = hyper::Version::HTTP_11;
        parts.method = hyper::Method::GET;
        assert!(!request_eligible(&parts, &p));
    }

    #[test]
    fn unsupported_representation_and_declared_trailers_are_ineligible() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/JSON; charset=utf-8"),
        );
        assert!(capture_headers(&headers));
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(!capture_headers(&headers));
        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        assert!(capture_headers(&headers));
        headers.insert(header::TRAILER, HeaderValue::from_static("x-extra"));
        assert!(!capture_headers(&headers));
        headers.remove(header::TRAILER);
        headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(!capture_headers(&headers));
    }

    struct Frames(VecDeque<Result<Frame<Bytes>, &'static str>>);
    impl Body for Frames {
        type Data = Bytes;
        type Error = &'static str;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.pop_front())
        }
        fn is_end_stream(&self) -> bool {
            self.0.is_empty()
        }
    }

    #[test]
    fn wrapper_preserves_fragment_trailer_and_error_frames() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-proof", HeaderValue::from_static("unchanged"));
        let inner = Frames(VecDeque::from([
            Ok(Frame::data(Bytes::from_static(b"{\"id\":"))),
            Ok(Frame::data(Bytes::from_static(b"1}"))),
            Ok(Frame::trailers(trailers.clone())),
            Err("body error"),
        ]));
        let mut body = ObservedBody::new(inner, None);
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(
            Pin::new(&mut body)
                .poll_frame(&mut cx)
                .into_ready()
                .unwrap()
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            Bytes::from_static(b"{\"id\":")
        );
        assert_eq!(
            Pin::new(&mut body)
                .poll_frame(&mut cx)
                .into_ready()
                .unwrap()
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            Bytes::from_static(b"1}")
        );
        assert_eq!(
            Pin::new(&mut body)
                .poll_frame(&mut cx)
                .into_ready()
                .unwrap()
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap(),
            trailers
        );
        assert_eq!(
            Pin::new(&mut body)
                .poll_frame(&mut cx)
                .into_ready()
                .unwrap()
                .unwrap()
                .unwrap_err(),
            "body error"
        );
        assert!(body.is_end_stream());
        assert!(
            Pin::new(&mut body)
                .poll_frame(&mut cx)
                .into_ready()
                .unwrap()
                .is_none()
        );
    }
}
