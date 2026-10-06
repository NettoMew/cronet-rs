//! A bidirectional stream as a byte stream: `tokio::io::AsyncRead` and
//! `AsyncWrite` over Cronet's callbacks.

use std::{
    fmt, future, io,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll, Waker},
};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{BidirectionalStream, Engine, Headers, NetError, Stream, StreamCallback, StreamError, StreamPriority};

/// When a [`BidirectionalConn`] may read and write.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnOptions {
    /// Reads wait for the response headers, not just for the stream.
    pub read_wait_headers: bool,
    /// Writes wait for the response headers, not just for the stream.
    pub write_wait_headers: bool,
}

/// The largest piece one write hands to Cronet.
const MAX_WRITE: usize = 1 << 20;
/// The smallest buffer one read hands to Cronet.
const MIN_READ: usize = 16 * 1024;

/// A bidirectional stream as `AsyncRead + AsyncWrite`.
///
/// Reads and writes wait until the stream is ready, or with
/// [`ConnOptions`] until the response headers arrive. A write returns once
/// its bytes are copied for Cronet; one is in flight at a time, and
/// [flushing](tokio::io::AsyncWrite::poll_flush) waits for it to be sent.
/// [Shutting down](tokio::io::AsyncWrite::poll_shutdown) ends the request side
/// only; dropping the connection, or [`close`](Self::close), cancels the
/// stream.
///
/// A timeout around a read loses nothing: the read keeps going, and its data
/// waits for the next one.
pub struct BidirectionalConn {
    stream: BidirectionalStream,
    shared: Arc<Shared>,
    options: ConnOptions,
}

/// The response headers of a stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseHeaders {
    /// Every header, `:status` included, in the order received.
    pub headers: Vec<(String, String)>,
    /// The protocol negotiated, such as `h2` or `h3`.
    pub negotiated_protocol: String,
}

impl ResponseHeaders {
    /// The first value of `name`, ignoring ASCII case.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The `:status` pseudo header, as a number.
    pub fn status(&self) -> Option<u16> {
        self.get(":status")?.parse().ok()
    }
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    ready: bool,
    headers: Option<ResponseHeaders>,
    /// Data read and not yet consumed, or an emptied buffer to reuse.
    received: BytesMut,
    reading: bool,
    /// The server sent its last byte.
    eof: bool,
    writing: bool,
    shutdown: bool,
    closed: bool,
    ended: Option<Ended>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    headers_wakers: Vec<Waker>,
    on_end: Option<Box<dyn FnOnce() + Send>>,
}

#[derive(Debug, Clone, Copy)]
enum Ended {
    Succeeded,
    Failed(NetError),
    Canceled,
}

impl State {
    fn wake_all(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
        self.headers_wakers.drain(..).for_each(Waker::wake);
    }

    /// Why nothing more can happen, if so.
    fn failure(&self) -> Option<io::Error> {
        if self.closed {
            return Some(io::Error::new(io::ErrorKind::NotConnected, "the connection is closed"));
        }
        match self.ended? {
            Ended::Succeeded => None,
            Ended::Failed(error) => Some(error.into()),
            Ended::Canceled => Some(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the stream was canceled",
            )),
        }
    }

    fn may(&self, wait_headers: bool) -> bool {
        if wait_headers {
            self.headers.is_some()
        } else {
            self.ready || self.headers.is_some()
        }
    }
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn end(&self, ended: Ended) {
        let on_end = {
            let mut state = self.state();
            state.ended.get_or_insert(ended);
            state.reading = false;
            state.writing = false;
            state.wake_all();
            state.on_end.take()
        };
        if let Some(on_end) = on_end {
            on_end();
        }
    }
}

/// The stream's callback: it records what happened and wakes the waiters.
struct Events(Arc<Shared>);

impl StreamCallback for Events {
    fn on_stream_ready(&mut self, _: &Stream) {
        let mut state = self.0.state();
        state.ready = true;
        state.wake_all();
    }

    fn on_response_headers_received(&mut self, _: &Stream, headers: &Headers<'_>, negotiated_protocol: &str) {
        let headers = ResponseHeaders {
            headers: headers
                .iter()
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect(),
            negotiated_protocol: negotiated_protocol.to_owned(),
        };
        let mut state = self.0.state();
        state.headers = Some(headers);
        state.wake_all();
    }

    fn on_read_completed(&mut self, _: &Stream, buffer: BytesMut, bytes_read: usize) {
        let mut state = self.0.state();
        state.reading = false;
        if bytes_read == 0 {
            state.eof = true;
        }
        state.received = buffer;
        if let Some(waker) = state.read_waker.take() {
            waker.wake();
        }
    }

    fn on_write_completed(&mut self, _: &Stream, _: Bytes) {
        let mut state = self.0.state();
        state.writing = false;
        if let Some(waker) = state.write_waker.take() {
            waker.wake();
        }
    }

    fn on_succeeded(&mut self, _: &Stream) {
        self.0.end(Ended::Succeeded);
    }

    fn on_failed(&mut self, _: &Stream, error: NetError) {
        self.0.end(Ended::Failed(error));
    }

    fn on_canceled(&mut self, _: &Stream) {
        self.0.end(Ended::Canceled);
    }
}

impl BidirectionalConn {
    /// A connection over a new stream on `engine`; nothing is sent until
    /// [`start`](Self::start).
    pub fn new(engine: &Engine, options: ConnOptions) -> Self {
        let shared = Arc::new(Shared::default());
        let stream = BidirectionalStream::new(engine, Events(shared.clone()));
        Self {
            stream,
            shared,
            options,
        }
    }

    /// Sends the request; see [`Stream::start`].
    ///
    /// # Errors
    ///
    /// As [`Stream::start`].
    pub fn start<K: AsRef<str>, V: AsRef<str>>(
        &self,
        method: &str,
        url: &str,
        headers: &[(K, V)],
        priority: StreamPriority,
        end_of_stream: bool,
    ) -> Result<(), StreamError> {
        self.stream.start(method, url, headers, priority, end_of_stream)
    }

    /// The stream underneath, for [`flush`](Stream::flush) and the like.
    pub fn stream(&self) -> &Stream {
        &self.stream
    }

    /// Waits for the response headers.
    ///
    /// # Errors
    ///
    /// If the stream ends, or is closed, first.
    pub async fn headers(&self) -> io::Result<ResponseHeaders> {
        future::poll_fn(|cx| self.poll_headers(cx)).await
    }

    /// Polls for the response headers; see [`headers`](Self::headers).
    pub fn poll_headers(&self, cx: &mut Context<'_>) -> Poll<io::Result<ResponseHeaders>> {
        let mut state = self.shared.state();
        if let Some(headers) = &state.headers {
            return Poll::Ready(Ok(headers.clone()));
        }
        if let Some(error) = state.failure() {
            return Poll::Ready(Err(error));
        }
        if state.ended.is_some() {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        state.headers_wakers.push(cx.waker().clone());
        Poll::Pending
    }

    /// Cancels the stream. Reads and writes fail from now on.
    pub fn close(&self) {
        {
            let mut state = self.shared.state();
            state.closed = true;
            state.wake_all();
        }
        self.stream.cancel();
    }

    /// Waits until the stream has ended, however it did.
    pub async fn closed(&self) {
        future::poll_fn(|cx| {
            let mut state = self.shared.state();
            if state.ended.is_some() {
                return Poll::Ready(());
            }
            state.headers_wakers.push(cx.waker().clone());
            Poll::Pending
        })
        .await;
    }

    /// Runs `on_end` once the stream has ended, however it did; at once if it
    /// already has. A later call replaces an earlier hook not yet run.
    pub fn on_end(&self, on_end: impl FnOnce() + Send + 'static) {
        let mut state = self.shared.state();
        if state.ended.is_some() {
            drop(state);
            on_end();
        } else {
            state.on_end = Some(Box::new(on_end));
        }
    }
}

impl AsyncRead for BidirectionalConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let mut state = this.shared.state();
        if state.closed {
            return Poll::Ready(Err(state.failure().expect("closed")));
        }
        if !state.received.is_empty() {
            let n = state.received.len().min(buf.remaining());
            buf.put_slice(&state.received[..n]);
            state.received.advance(n);
            return Poll::Ready(Ok(()));
        }
        if state.eof || matches!(state.ended, Some(Ended::Succeeded)) {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = state.failure() {
            return Poll::Ready(Err(error));
        }
        if !state.reading && state.may(this.options.read_wait_headers) {
            let mut buffer = std::mem::take(&mut state.received);
            buffer.clear();
            buffer.reserve(buf.remaining().max(MIN_READ));
            state.reading = true;
            if let Err(error) = this.stream.read(buffer) {
                state.reading = false;
                return Poll::Ready(Err(io::Error::other(error)));
            }
        }
        state.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for BidirectionalConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut state = this.shared.state();
        if let Some(error) = state.failure() {
            return Poll::Ready(Err(error));
        }
        if state.ended.is_some() || state.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if state.writing || !state.may(this.options.write_wait_headers) {
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = data.len().min(MAX_WRITE);
        state.writing = true;
        if let Err(error) = this.stream.write(Bytes::copy_from_slice(&data[..n]), false) {
            state.writing = false;
            return Poll::Ready(Err(io::Error::other(error)));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared.state();
        if let Some(error) = state.failure() {
            return Poll::Ready(Err(error));
        }
        if state.writing {
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut state = this.shared.state();
        if let Some(error) = state.failure() {
            return Poll::Ready(Err(error));
        }
        if state.ended.is_some() {
            return Poll::Ready(Ok(()));
        }
        if state.writing || !state.may(this.options.write_wait_headers) {
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if !state.shutdown {
            state.shutdown = true;
            state.writing = true;
            if let Err(error) = this.stream.write(Bytes::new(), true) {
                state.writing = false;
                return Poll::Ready(Err(io::Error::other(error)));
            }
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}

impl fmt::Debug for BidirectionalConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.state();
        f.debug_struct("BidirectionalConn")
            .field("ready", &state.ready)
            .field("headers", &state.headers.is_some())
            .field("ended", &state.ended)
            .field("closed", &state.closed)
            .finish()
    }
}
