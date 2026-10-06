//! Requests in terms of the [`http`] and [`http_body`] crates: an HTTP
//! client on top of [`UrlRequest`].
//!
//! ```no_run
//! # async fn example() -> Result<(), cronet::http::Error> {
//! let client = cronet::http::Client::new()?;
//! let request = http::Request::get("https://example.com/").body(cronet::http::Body::empty()).unwrap();
//! let response = client.send(request).await?;
//! let body = response.into_body().bytes().await?;
//! # Ok(())
//! # }
//! ```
//!
//! Nothing here needs a particular async runtime: Cronet's callbacks wake
//! the futures, whichever executor polls them.

use std::{
    error, fmt, future, io,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderName, HeaderValue, Version};
use http_body::{Body as _, Frame, SizeHint};

use crate::{
    ApiError, Buffer, Engine, EngineParams, ErrorRef, Executor, UploadDataProvider, UploadRead, UploadRewind,
    UrlRequest, UrlRequestCallback, UrlRequestParams, UrlResponseInfoRef,
};

/// How much of the response body one read asks Cronet for.
const READ_SIZE: usize = 32 * 1024;

/// A boxed error, as request bodies report them.
pub type BoxError = Box<dyn error::Error + Send + Sync>;

/// Decides whether to follow a redirect to the URL it is given.
type RedirectPolicy = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Sends `http::Request`s through a Cronet engine.
///
/// Cloning is cheap: clones share the engine and the executor.
#[derive(Clone)]
pub struct Client {
    engine: Engine,
    executor: Executor,
    redirect_policy: Option<RedirectPolicy>,
}

impl Client {
    /// A client with an engine of its own, speaking HTTP/2, QUIC and Brotli,
    /// and an executor thread of its own.
    ///
    /// # Errors
    ///
    /// If the engine does not start.
    pub fn new() -> Result<Self, Error> {
        let mut params = EngineParams::new();
        params
            .set_enable_http2(true)
            .set_enable_quic(true)
            .set_enable_brotli(true)
            .set_user_agent(concat!("cronet-rs/", env!("CARGO_PKG_VERSION")));
        Ok(Self::with_engine(Engine::start(&params)?, Executor::thread()))
    }

    /// A client on `engine`, whose callbacks and uploads run on `executor`.
    /// The executor must not run tasks inline on the thread handing them
    /// over.
    pub fn with_engine(engine: Engine, executor: Executor) -> Self {
        Self {
            engine,
            executor,
            redirect_policy: None,
        }
    }

    /// Follows a redirect only when `policy` approves its URL. A refused
    /// redirect is the response: its status and headers, with an empty body.
    /// Without a policy, every redirect is followed.
    #[must_use]
    pub fn redirect_policy(mut self, policy: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        self.redirect_policy = Some(Arc::new(policy));
        self
    }

    /// The engine requests go through.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Sends `request`, and resolves once the response headers arrive; the
    /// body follows as [`ResponseBody`] reads it.
    ///
    /// The method defaults to `GET`, and every header is sent, repeated ones
    /// combined into one line (with `; ` for `Cookie`, `, ` otherwise). No
    /// header is made up: a body goes without `Content-Type` unless the
    /// request has one.
    ///
    /// Dropping the future before it resolves cancels the request.
    ///
    /// # Errors
    ///
    /// [`Error::Api`] if Cronet refuses the request, [`Error::Request`] if it
    /// fails before a response, [`Error::Canceled`] if it is canceled.
    pub async fn send(&self, request: http::Request<Body>) -> Result<http::Response<ResponseBody>, Error> {
        let (parts, body) = request.into_parts();
        let mut params = UrlRequestParams::new();
        params.set_method(parts.method.as_str());
        // Cronet keeps one value per name, the last, so repeated headers are
        // combined into one field line the way HTTP allows.
        for name in parts.headers.keys() {
            let separator = if name == http::header::COOKIE { "; " } else { ", " };
            let values: Vec<_> = parts
                .headers
                .get_all(name)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()))
                .collect();
            params.add_header(name.as_str(), &values.join(separator));
        }
        match body.kind {
            Kind::Empty => {}
            Kind::Full(bytes) if bytes.is_empty() => {}
            Kind::Full(bytes) => {
                params.set_upload(io::Cursor::new(bytes), &self.executor);
            }
            Kind::Streaming(body) => {
                params.set_upload(StreamingUpload::new(body), &self.executor);
            }
        }

        let shared = Arc::new(Shared::default());
        let handler = Handler {
            shared: shared.clone(),
            redirect_policy: self.redirect_policy.clone(),
        };
        let url = parts.uri.to_string();
        let request = UrlRequest::new(&self.engine, &url, params, handler, &self.executor)?;
        request.start()?;

        let mut pending = CancelOnDrop(Some(request));
        let head = future::poll_fn(|cx| shared.poll_head(cx)).await;
        let request = pending.0.take().expect("disarmed only here");
        let (head, empty) = head?;
        let body = if empty {
            ResponseBody::empty()
        } else {
            ResponseBody {
                inner: Inner::Streaming { request, shared },
            }
        };
        Ok(head.map(|()| body))
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("engine", &self.engine)
            .field("executor", &self.executor)
            .field("redirect_policy", &self.redirect_policy.is_some())
            .finish()
    }
}

/// Cancels the request it holds when dropped: the `send` future went away
/// before the response arrived.
struct CancelOnDrop(Option<UrlRequest>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(request) = &self.0 {
            request.cancel();
        }
    }
}

/// Why a request failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Cronet refused the request.
    Api(ApiError),
    /// The request failed.
    Request(crate::Error),
    /// The request was canceled.
    Canceled,
    /// The request body failed.
    Body(BoxError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(error) => write!(f, "cronet refused the request: {error}"),
            Self::Request(error) => write!(f, "request failed: {error}"),
            Self::Canceled => f.write_str("request canceled"),
            Self::Body(error) => write!(f, "request body failed: {error}"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Api(error) => Some(error),
            Self::Request(error) => Some(error),
            Self::Canceled => None,
            Self::Body(error) => Some(&**error),
        }
    }
}

impl From<ApiError> for Error {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}

impl From<crate::Error> for Error {
    fn from(error: crate::Error) -> Self {
        Self::Request(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Request(error) => error.into(),
            Error::Canceled => io::Error::new(io::ErrorKind::ConnectionAborted, Error::Canceled),
            other => io::Error::other(other),
        }
    }
}

/// A request body: nothing, bytes in memory, or anything that implements
/// [`http_body::Body`].
pub struct Body {
    kind: Kind,
}

enum Kind {
    Empty,
    Full(Bytes),
    Streaming(Pin<Box<dyn http_body::Body<Data = Bytes, Error = BoxError> + Send>>),
}

impl Body {
    /// No body.
    pub fn empty() -> Self {
        Self { kind: Kind::Empty }
    }

    /// A body streamed from `body`. Its length is announced when its size
    /// hint is exact, else it is sent chunked. Cronet cannot rewind it once
    /// read, so a redirect that keeps the body fails.
    pub fn wrap<B>(body: B) -> Self
    where
        B: http_body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<BoxError>,
    {
        Self {
            kind: Kind::Streaming(Box::pin(IntoBytes(Box::pin(body)))),
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Bytes> for Body {
    fn from(bytes: Bytes) -> Self {
        Self {
            kind: Kind::Full(bytes),
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Self {
        Bytes::from(bytes).into()
    }
}

impl From<String> for Body {
    fn from(text: String) -> Self {
        Bytes::from(text).into()
    }
}

impl From<&'static str> for Body {
    fn from(text: &'static str) -> Self {
        Bytes::from_static(text.as_bytes()).into()
    }
}

impl From<&'static [u8]> for Body {
    fn from(bytes: &'static [u8]) -> Self {
        Bytes::from_static(bytes).into()
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            Kind::Empty => f.write_str("Body::Empty"),
            Kind::Full(bytes) => f.debug_tuple("Body::Full").field(&bytes.len()).finish(),
            Kind::Streaming(_) => f.write_str("Body::Streaming"),
        }
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        match &mut this.kind {
            Kind::Empty => Poll::Ready(None),
            Kind::Full(_) => {
                let Kind::Full(bytes) = std::mem::replace(&mut this.kind, Kind::Empty) else {
                    unreachable!()
                };
                Poll::Ready((!bytes.is_empty()).then(|| Ok(Frame::data(bytes))))
            }
            Kind::Streaming(body) => body.as_mut().poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.kind {
            Kind::Empty => true,
            Kind::Full(bytes) => bytes.is_empty(),
            Kind::Streaming(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.kind {
            Kind::Empty => SizeHint::with_exact(0),
            Kind::Full(bytes) => SizeHint::with_exact(bytes.len() as u64),
            Kind::Streaming(body) => body.size_hint(),
        }
    }
}

/// Turns a body's data into `Bytes` and its errors into [`BoxError`].
struct IntoBytes<B>(Pin<Box<B>>);

impl<B> http_body::Body for IntoBytes<B>
where
    B: http_body::Body,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.get_mut().0.as_mut().poll_frame(cx).map(|frame| {
            frame.map(|frame| {
                frame
                    .map_err(Into::into)
                    .map(|frame| frame.map_data(|mut data| data.copy_to_bytes(data.remaining())))
            })
        })
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

/// Uploads a streaming body: each Cronet read waits for the body's next
/// data, polled with a waker that resumes it.
struct StreamingUpload {
    shared: Arc<UploadShared>,
}

struct UploadShared {
    state: Mutex<UploadState>,
    /// Someone is polling the body; others leave a note instead.
    polling: AtomicBool,
    /// The body asked to be polled again.
    notified: AtomicBool,
}

struct UploadState {
    body: Pin<Box<dyn http_body::Body<Data = Bytes, Error = BoxError> + Send>>,
    length: Option<u64>,
    /// The read Cronet waits on.
    pending: Option<UploadRead>,
    /// Data the body gave beyond what the last read took.
    leftover: Bytes,
    sent: u64,
    ended: bool,
}

impl StreamingUpload {
    fn new(body: Pin<Box<dyn http_body::Body<Data = Bytes, Error = BoxError> + Send>>) -> Self {
        let length = body.size_hint().exact();
        let state = UploadState {
            body,
            length,
            pending: None,
            leftover: Bytes::new(),
            sent: 0,
            ended: false,
        };
        Self {
            shared: Arc::new(UploadShared {
                state: Mutex::new(state),
                polling: AtomicBool::new(false),
                notified: AtomicBool::new(false),
            }),
        }
    }
}

impl UploadDataProvider for StreamingUpload {
    fn length(&mut self) -> Option<u64> {
        self.shared.state().length
    }

    fn read(&mut self, read: UploadRead) {
        self.shared.state().pending = Some(read);
        self.shared.drive();
    }

    fn rewind(&mut self, rewind: UploadRewind) {
        // Nothing was read yet, so there is nothing to start over from.
        let untouched = {
            let state = self.shared.state();
            state.sent == 0 && state.leftover.is_empty()
        };
        if untouched {
            rewind.succeed();
        } else {
            rewind.fail("unsupported");
        }
    }
}

impl UploadShared {
    fn state(&self) -> MutexGuard<'_, UploadState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Polls the body until the pending read can be answered or the body is
    /// not ready. Wakes that arrive while another call polls leave a note,
    /// which that call honours before it stops, so no wake is lost and the
    /// body is never polled re-entrantly.
    fn drive(self: &Arc<Self>) {
        self.notified.store(true, Ordering::Release);
        if self.polling.swap(true, Ordering::AcqRel) {
            return;
        }
        loop {
            self.notified.store(false, Ordering::Release);
            self.step();
            self.polling.store(false, Ordering::Release);
            if !self.notified.load(Ordering::Acquire) || self.polling.swap(true, Ordering::AcqRel) {
                return;
            }
        }
    }

    fn step(self: &Arc<Self>) {
        let waker = Waker::from(self.clone());
        let mut cx = Context::from_waker(&waker);
        let mut state = self.state();
        let state = &mut *state;
        loop {
            let Some(read) = state.pending.as_mut() else { return };
            if !state.leftover.is_empty() {
                let buffer = read.buffer();
                let n = buffer.len().min(state.leftover.len());
                buffer[..n].copy_from_slice(&state.leftover[..n]);
                state.leftover.advance(n);
                state.sent += n as u64;
                state.pending.take().expect("checked above").succeed(n, false);
                return;
            }
            if state.ended {
                let read = state.pending.take().expect("checked above");
                match state.length {
                    None => read.succeed(0, true),
                    Some(length) => read.fail(&format!("the body ended after {} of {length} bytes", state.sent)),
                }
                return;
            }
            match state.body.as_mut().poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        state.leftover = data;
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    state.pending.take().expect("checked above").fail(&error.to_string());
                    return;
                }
                Poll::Ready(None) => state.ended = true,
                Poll::Pending => return,
            }
        }
    }
}

impl Wake for UploadShared {
    fn wake(self: Arc<Self>) {
        self.drive();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.drive();
    }
}

/// A response body, read from Cronet as it is polled.
///
/// Dropping it before the end cancels the request.
pub struct ResponseBody {
    inner: Inner,
}

enum Inner {
    Empty,
    Streaming { request: UrlRequest, shared: Arc<Shared> },
}

impl ResponseBody {
    fn empty() -> Self {
        Self { inner: Inner::Empty }
    }

    /// The whole body.
    ///
    /// # Errors
    ///
    /// If the request fails or is canceled before the end.
    pub async fn bytes(mut self) -> Result<Bytes, Error> {
        let mut collected = BytesMut::new();
        while let Some(frame) = future::poll_fn(|cx| Pin::new(&mut self).poll_frame(cx)).await {
            if let Ok(data) = frame?.into_data() {
                collected.extend_from_slice(&data);
            }
        }
        Ok(collected.freeze())
    }
}

impl http_body::Body for ResponseBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let Inner::Streaming { request, shared } = &self.get_mut().inner else {
            return Poll::Ready(None);
        };
        let buffer = {
            let mut state = shared.state();
            if let Some(chunk) = state.chunk.take() {
                return Poll::Ready(Some(Ok(Frame::data(chunk))));
            }
            match &state.end {
                Some(End::Succeeded) => return Poll::Ready(None),
                Some(End::Failed(error)) => return Poll::Ready(Some(Err(Error::Request(error.clone())))),
                Some(End::Canceled) => return Poll::Ready(Some(Err(Error::Canceled))),
                None => {}
            }
            state.body_waker = Some(cx.waker().clone());
            if state.reading {
                return Poll::Pending;
            }
            state.reading = true;
            state.buffer.take().unwrap_or_else(|| Buffer::zeroed(READ_SIZE))
        };
        // Outside the lock: the read's callback takes it.
        if let Err(error) = request.read(buffer) {
            shared.state().reading = false;
            return Poll::Ready(Some(Err(error.into())));
        }
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Inner::Empty => true,
            Inner::Streaming { shared, .. } => {
                let state = shared.state();
                state.chunk.is_none() && matches!(state.end, Some(End::Succeeded))
            }
        }
    }
}

impl Drop for ResponseBody {
    fn drop(&mut self) {
        if let Inner::Streaming { request, shared } = &self.inner
            && shared.state().end.is_none()
        {
            request.cancel();
        }
    }
}

impl fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            Inner::Empty => f.write_str("ResponseBody::Empty"),
            Inner::Streaming { request, .. } => f.debug_tuple("ResponseBody").field(request).finish(),
        }
    }
}

/// What the callback and the futures share.
#[derive(Default)]
struct Shared {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// The response head, and whether its body is empty (a refused redirect).
    head: Option<(http::Response<()>, bool)>,
    head_taken: bool,
    /// Data read and not yet polled.
    chunk: Option<Bytes>,
    /// The read buffer, between reads.
    buffer: Option<Buffer>,
    reading: bool,
    end: Option<End>,
    head_waker: Option<Waker>,
    body_waker: Option<Waker>,
}

enum End {
    Succeeded,
    Failed(crate::Error),
    Canceled,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn poll_head(&self, cx: &mut Context<'_>) -> Poll<Result<(http::Response<()>, bool), Error>> {
        let mut state = self.state();
        if let Some(head) = state.head.take() {
            state.head_taken = true;
            return Poll::Ready(Ok(head));
        }
        match &state.end {
            Some(End::Failed(error)) => return Poll::Ready(Err(Error::Request(error.clone()))),
            Some(End::Canceled) => return Poll::Ready(Err(Error::Canceled)),
            Some(End::Succeeded) => return Poll::Ready(Err(Error::Canceled)),
            None => {}
        }
        state.head_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn end(&self, end: End) {
        let mut state = self.state();
        state.end.get_or_insert(end);
        state.reading = false;
        if let Some(waker) = state.head_waker.take() {
            waker.wake();
        }
        if let Some(waker) = state.body_waker.take() {
            waker.wake();
        }
    }
}

/// The request's callback: it records what happened and wakes the futures.
struct Handler {
    shared: Arc<Shared>,
    redirect_policy: Option<RedirectPolicy>,
}

impl Handler {
    fn respond(&self, info: &UrlResponseInfoRef, empty: bool) {
        let mut state = self.shared.state();
        if state.head.is_none() && !state.head_taken {
            state.head = Some((head(info), empty));
            if let Some(waker) = state.head_waker.take() {
                waker.wake();
            }
        }
    }
}

impl UrlRequestCallback for Handler {
    fn on_redirect_received(&mut self, request: &UrlRequest, info: &UrlResponseInfoRef, new_location_url: &str) {
        if self
            .redirect_policy
            .as_ref()
            .is_some_and(|policy| !policy(new_location_url))
        {
            self.respond(info, true);
            // The redirect is the response; nothing more is wanted.
            request.cancel();
        } else if let Err(error) = request.follow_redirect() {
            self.shared.end(End::Failed(api_failure(error)));
            request.cancel();
        }
    }

    fn on_response_started(&mut self, _: &UrlRequest, info: &UrlResponseInfoRef) {
        self.respond(info, false);
    }

    fn on_read_completed(&mut self, _: &UrlRequest, _: &UrlResponseInfoRef, buffer: Buffer, bytes_read: u64) {
        let mut state = self.shared.state();
        state.reading = false;
        let n = usize::try_from(bytes_read).unwrap_or(usize::MAX).min(buffer.len());
        if n > 0 {
            state.chunk = Some(Bytes::copy_from_slice(&buffer[..n]));
        }
        state.buffer = Some(buffer);
        if let Some(waker) = state.body_waker.take() {
            waker.wake();
        }
    }

    fn on_succeeded(&mut self, _: &UrlRequest, _: &UrlResponseInfoRef) {
        self.shared.end(End::Succeeded);
    }

    fn on_failed(&mut self, _: &UrlRequest, _: Option<&UrlResponseInfoRef>, error: &ErrorRef) {
        self.shared.end(End::Failed(error.to_owned()));
    }

    fn on_canceled(&mut self, _: &UrlRequest, _: Option<&UrlResponseInfoRef>) {
        self.shared.end(End::Canceled);
    }
}

/// A failure of this module's own Cronet calls, as a request error.
fn api_failure(error: ApiError) -> crate::Error {
    let mut failure = crate::Error::new();
    failure
        .set_error_code(crate::ErrorCode::Callback)
        .set_message(&error.to_string());
    failure
}

/// The response head Cronet reported: status, headers in wire order, the
/// HTTP version from the negotiated protocol, and a copy of the whole
/// [`UrlResponseInfo`](crate::UrlResponseInfo) as an extension.
fn head(info: &UrlResponseInfoRef) -> http::Response<()> {
    let mut response = http::Response::new(());
    *response.status_mut() = u16::try_from(info.status_code())
        .ok()
        .and_then(|code| http::StatusCode::from_u16(code).ok())
        .unwrap_or_default();
    *response.version_mut() = version(&info.negotiated_protocol());
    let headers = response.headers_mut();
    for header in info.headers() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(header.name().as_bytes()),
            HeaderValue::from_str(&header.value()),
        ) {
            headers.append(name, value);
        }
    }
    response.extensions_mut().insert(info.to_owned());
    response
}

fn version(protocol: &str) -> Version {
    let protocol = protocol.to_ascii_lowercase();
    if protocol == "h2" {
        Version::HTTP_2
    } else if protocol.starts_with("h3") || protocol.starts_with("quic") {
        Version::HTTP_3
    } else if protocol == "http/1.0" {
        Version::HTTP_10
    } else {
        Version::HTTP_11
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_follow_the_negotiated_protocol() {
        assert_eq!(version("h2"), Version::HTTP_2);
        assert_eq!(version("h3"), Version::HTTP_3);
        assert_eq!(version("quic/1+spdy/3"), Version::HTTP_3);
        assert_eq!(version("http/1.0"), Version::HTTP_10);
        assert_eq!(version("http/1.1"), Version::HTTP_11);
        assert_eq!(version(""), Version::HTTP_11);
    }

    #[test]
    fn in_memory_bodies_are_one_frame() {
        let mut body = Body::from("hello");
        assert_eq!(body.size_hint().exact(), Some(5));
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!()
        };
        assert_eq!(frame.into_data().unwrap(), "hello");
        assert!(matches!(Pin::new(&mut body).poll_frame(&mut cx), Poll::Ready(None)));
        assert!(body.is_end_stream());
    }
}
