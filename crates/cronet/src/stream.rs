//! Bidirectional streams: one HTTP/2 or QUIC stream, written and read
//! concurrently. NaiveProxy's tunnels are `CONNECT` streams.

use std::{
    borrow::Cow,
    collections::VecDeque,
    error,
    ffi::{CString, c_char, c_int},
    fmt,
    ops::Deref,
    ptr::{self, NonNull},
    slice,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use bytes::{Bytes, BytesMut};
use cronet_sys as sys;

use crate::{Engine, NetError, engine::NetworkThread, ffi::string};

/// What a [`BidirectionalStream`] reports, on Cronet's network thread.
///
/// Callbacks must not block: the network thread serves every stream and
/// request of the engine. Each has a default that does nothing, and after
/// `on_succeeded`, `on_failed` or `on_canceled` none is called again.
#[allow(unused_variables)]
pub trait StreamCallback: Send + 'static {
    /// The stream can be read and written.
    fn on_stream_ready(&mut self, stream: &Stream) {}

    /// The response headers arrived; reading can start.
    fn on_response_headers_received(&mut self, stream: &Stream, headers: &Headers<'_>, negotiated_protocol: &str) {}

    /// A [`read`](Stream::read) completed: `bytes_read` bytes were appended
    /// to `buffer`, which comes back for the next read. Zero means the server
    /// will send no more; reading again then completes the stream.
    fn on_read_completed(&mut self, stream: &Stream, buffer: BytesMut, bytes_read: usize) {}

    /// A [`write`](Stream::write) was sent; its data comes back.
    fn on_write_completed(&mut self, stream: &Stream, data: Bytes) {}

    /// Trailers arrived, perhaps while read data is still buffered.
    fn on_response_trailers_received(&mut self, stream: &Stream, trailers: &Headers<'_>) {}

    /// Both sides finished cleanly.
    fn on_succeeded(&mut self, stream: &Stream) {}

    /// The stream failed; HTTP/2 errors arrive mapped to Chromium's.
    fn on_failed(&mut self, stream: &Stream, error: NetError) {}

    /// The stream was [canceled](Stream::cancel).
    fn on_canceled(&mut self, stream: &Stream) {}
}

/// `net::RequestPriority`: how the stream ranks against its connection's
/// others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(i32)]
pub enum StreamPriority {
    /// Sent only when nothing else is.
    Throttled = 0,
    /// Idle.
    Idle = 1,
    /// Lowest.
    Lowest = 2,
    /// Low.
    Low = 3,
    /// Medium, the default.
    #[default]
    Medium = 4,
    /// Highest.
    Highest = 5,
}

/// Why a stream operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StreamError {
    /// The stream has already been started.
    AlreadyStarted,
    /// The stream has not been started.
    NotStarted,
    /// The stream has ended.
    Closed,
    /// A read is already in flight.
    ReadPending,
    /// The method, URL, or the header at this index was rejected.
    InvalidArgument(Option<usize>),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyStarted => f.write_str("the stream has already started"),
            Self::NotStarted => f.write_str("the stream has not started"),
            Self::Closed => f.write_str("the stream has ended"),
            Self::ReadPending => f.write_str("a read is already in flight"),
            Self::InvalidArgument(None) => f.write_str("invalid method or URL"),
            Self::InvalidArgument(Some(index)) => write!(f, "invalid header at index {index}"),
        }
    }
}

impl error::Error for StreamError {}

/// A bidirectional stream, made with an engine and a [`StreamCallback`].
///
/// This is the stream's owner, and dereferences to the [`Stream`] that
/// callbacks see. Dropping it cancels a stream still running; the stream is
/// freed once Cronet reports how it ended.
pub struct BidirectionalStream(Arc<Stream>);

/// The operations of a bidirectional stream, for its owner and its callbacks.
pub struct Stream {
    raw: NonNull<sys::bidirectional_stream>,
    state: Mutex<State>,
    callback: Mutex<Box<dyn StreamCallback>>,
    _engine: Engine,
}

// SAFETY: the stream API posts every call to the network thread, so it may be
// called from any thread; the state is behind locks, the callback is `Send`.
unsafe impl Send for Stream {}
// SAFETY: as above.
unsafe impl Sync for Stream {}

#[derive(Default)]
struct State {
    phase: Phase,
    /// The buffer Cronet is reading into.
    read: Option<BytesMut>,
    /// The data Cronet is writing, oldest first.
    writes: VecDeque<Bytes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Phase {
    #[default]
    Created,
    /// Started: Cronet holds a strong reference until a final callback.
    Started,
    /// A final callback ran, and the C stream is destroyed.
    Done,
}

/// The callbacks every stream shares; each finds its `Stream` in the C
/// stream's annotation.
static CALLBACKS: sys::bidirectional_stream_callback = sys::bidirectional_stream_callback {
    on_stream_ready: Some(on_stream_ready),
    on_response_headers_received: Some(on_response_headers_received),
    on_read_completed: Some(on_read_completed),
    on_write_completed: Some(on_write_completed),
    on_response_trailers_received: Some(on_response_trailers_received),
    on_succeded: Some(on_succeeded),
    on_failed: Some(on_failed),
    on_canceled: Some(on_canceled),
};

/// Spare capacity a read gets when its buffer has none.
const DEFAULT_READ_SIZE: usize = 32 * 1024;

impl BidirectionalStream {
    /// A stream on `engine` reporting to `callback`; nothing is sent until
    /// [`start`](Stream::start).
    pub fn new(engine: &Engine, callback: impl StreamCallback) -> Self {
        let stream = Arc::new_cyclic(|weak: &std::sync::Weak<Stream>| {
            // SAFETY: the stream engine belongs to `engine`, which the stream
            // keeps; the annotation is the `Stream` being built, which outlives
            // the C stream; the callbacks are static.
            let raw = unsafe {
                sys::bidirectional_stream_create(engine.stream_engine(), weak.as_ptr().cast_mut().cast(), &CALLBACKS)
            };
            Stream {
                raw: NonNull::new(raw).expect("bidirectional_stream_create returned null"),
                state: Mutex::default(),
                callback: Mutex::new(Box::new(callback)),
                _engine: engine.clone(),
            }
        });
        Self(stream)
    }
}

impl Deref for BidirectionalStream {
    type Target = Stream;

    fn deref(&self) -> &Stream {
        &self.0
    }
}

impl Drop for BidirectionalStream {
    fn drop(&mut self) {
        let phase = self.0.state().phase;
        match phase {
            // No callback can come: free it now.
            Phase::Created => {
                self.0.state().phase = Phase::Done;
                // SAFETY: the stream never started, so Cronet holds no reference.
                unsafe { sys::bidirectional_stream_destroy(self.0.raw.as_ptr()) };
            }
            // The final callback frees it.
            Phase::Started => self.0.cancel(),
            Phase::Done => {}
        }
    }
}

impl fmt::Debug for BidirectionalStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl Stream {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends the request: `method` to `url` with `headers`, in order. With
    /// `end_of_stream`, nothing will be written.
    ///
    /// naiveproxy's Cronet reads a few pseudo headers: `-connect-authority`
    /// (the `CONNECT` target), `-force-quic`, and `-network-isolation-key`.
    ///
    /// # Errors
    ///
    /// [`StreamError::AlreadyStarted`] or [`StreamError::Closed`] unless the
    /// stream is new, and [`StreamError::InvalidArgument`] for a NUL byte or
    /// a header Chromium rejects.
    pub fn start<K: AsRef<str>, V: AsRef<str>>(
        &self,
        method: &str,
        url: &str,
        headers: &[(K, V)],
        priority: StreamPriority,
        end_of_stream: bool,
    ) -> Result<(), StreamError> {
        let method = CString::new(method).map_err(|_| StreamError::InvalidArgument(None))?;
        let url = CString::new(url).map_err(|_| StreamError::InvalidArgument(None))?;
        let strings = headers
            .iter()
            .enumerate()
            .map(|(index, (name, value))| {
                let invalid = |_| StreamError::InvalidArgument(Some(index));
                Ok((
                    CString::new(name.as_ref()).map_err(invalid)?,
                    CString::new(value.as_ref()).map_err(invalid)?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut entries: Vec<sys::bidirectional_stream_header> = strings
            .iter()
            .map(|(name, value)| sys::bidirectional_stream_header {
                key: name.as_ptr(),
                value: value.as_ptr(),
            })
            .collect();
        let array = sys::bidirectional_stream_header_array {
            count: entries.len(),
            capacity: entries.len(),
            headers: entries.as_mut_ptr(),
        };

        let mut state = self.state();
        match state.phase {
            Phase::Created => {}
            Phase::Started => return Err(StreamError::AlreadyStarted),
            Phase::Done => return Err(StreamError::Closed),
        }
        // SAFETY: the stream is live, and every string outlives the call, which copies them.
        let result = unsafe {
            sys::bidirectional_stream_start(
                self.raw.as_ptr(),
                url.as_ptr(),
                priority as c_int,
                method.as_ptr(),
                &array,
                end_of_stream,
            )
        };
        if result != 0 {
            let index = usize::try_from(result - 1).ok().filter(|index| *index < headers.len());
            return Err(StreamError::InvalidArgument(index));
        }
        state.phase = Phase::Started;
        // Cronet's reference, released by the final callback.
        // SAFETY: `self` lives in the `Arc` made by `BidirectionalStream::new`.
        unsafe { Arc::increment_strong_count(ptr::from_ref(self)) };
        Ok(())
    }

    /// Reads into `buffer`'s spare capacity (32 KiB is reserved if it has
    /// none); [`StreamCallback::on_read_completed`] hands it back. At most one
    /// read may be in flight.
    ///
    /// # Errors
    ///
    /// [`StreamError::ReadPending`], or the stream is not running.
    pub fn read(&self, mut buffer: BytesMut) -> Result<(), StreamError> {
        let mut state = self.state();
        Self::running(&state)?;
        if state.read.is_some() {
            return Err(StreamError::ReadPending);
        }
        if buffer.capacity() == buffer.len() {
            buffer.reserve(DEFAULT_READ_SIZE);
        }
        let spare = buffer.spare_capacity_mut();
        let (data, capacity) = (
            spare.as_mut_ptr().cast::<c_char>(),
            c_int::try_from(spare.len()).unwrap_or(c_int::MAX),
        );
        state.read = Some(buffer);
        // SAFETY: the spare capacity stays put on the heap while the buffer is
        // kept in `state.read`, until the read completes or the stream ends.
        unsafe { sys::bidirectional_stream_read(self.raw.as_ptr(), data, capacity) };
        Ok(())
    }

    /// Writes `data`, then [`StreamCallback::on_write_completed`] hands it
    /// back. With `end_of_stream`, it is the last write. Several writes may be
    /// in flight; without [auto flush](Self::disable_auto_flush) they wait for
    /// [`flush`](Self::flush).
    ///
    /// # Errors
    ///
    /// The stream is not running.
    pub fn write(&self, data: Bytes, end_of_stream: bool) -> Result<(), StreamError> {
        let mut state = self.state();
        Self::running(&state)?;
        // Never null, even when empty: Chromium drops a write without a buffer,
        // which would lose the end of the stream an empty write carries.
        let pointer = data.as_ptr().cast::<c_char>();
        let len = c_int::try_from(data.len()).expect("a write of at most 2 GiB");
        state.writes.push_back(data);
        // SAFETY: `Bytes` never moves its data, which stays in `state.writes`
        // until the write completes or the stream ends.
        unsafe { sys::bidirectional_stream_write(self.raw.as_ptr(), pointer, len, end_of_stream) };
        Ok(())
    }

    /// Sends the writes waiting for it. Not before
    /// [`on_stream_ready`](StreamCallback::on_stream_ready).
    pub fn flush(&self) {
        if Self::running(&self.state()).is_ok() {
            // SAFETY: the stream is live and started.
            unsafe { sys::bidirectional_stream_flush(self.raw.as_ptr()) }
        }
    }

    /// Whether each write is sent at once (the default) or waits for
    /// [`flush`](Self::flush).
    pub fn disable_auto_flush(&self, disable: bool) {
        if self.state().phase != Phase::Done {
            // SAFETY: the stream is live.
            unsafe { sys::bidirectional_stream_disable_auto_flush(self.raw.as_ptr(), disable) }
        }
    }

    /// Holds the request headers back until [`flush`](Self::flush), so that
    /// QUIC can send them in one packet with the first data. Only QUIC heeds
    /// it. Before [`start`](Self::start).
    pub fn delay_request_headers_until_flush(&self, delay: bool) {
        if self.state().phase != Phase::Done {
            // SAFETY: the stream is live.
            unsafe { sys::bidirectional_stream_delay_request_headers_until_flush(self.raw.as_ptr(), delay) }
        }
    }

    /// Cancels the stream: [`on_canceled`](StreamCallback::on_canceled)
    /// follows, unless it already ended. At most one other callback may still
    /// arrive first.
    pub fn cancel(&self) {
        if self.state().phase == Phase::Started {
            // SAFETY: the stream is live and started.
            unsafe { sys::bidirectional_stream_cancel(self.raw.as_ptr()) }
        }
    }

    fn running(state: &State) -> Result<(), StreamError> {
        match state.phase {
            Phase::Started => Ok(()),
            Phase::Created => Err(StreamError::NotStarted),
            Phase::Done => Err(StreamError::Closed),
        }
    }

    fn callback(&self) -> MutexGuard<'_, Box<dyn StreamCallback>> {
        self.callback.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state();
        f.debug_struct("Stream")
            .field("phase", &state.phase)
            .field("reading", &state.read.is_some())
            .field("writes_in_flight", &state.writes.len())
            .finish()
    }
}

/// Headers or trailers a stream received, in order. Borrowed for the
/// duration of the callback.
#[derive(Clone, Copy)]
pub struct Headers<'a> {
    entries: &'a [sys::bidirectional_stream_header],
}

impl<'a> Headers<'a> {
    /// # Safety
    ///
    /// `array` is null or valid, with its strings, for `'a`.
    unsafe fn from_raw(array: *const sys::bidirectional_stream_header_array) -> Self {
        // SAFETY: forwarded to the caller.
        let entries = match unsafe { array.as_ref() } {
            Some(array) if array.count > 0 && !array.headers.is_null() => {
                // SAFETY: Cronet's array holds `count` entries.
                unsafe { slice::from_raw_parts(array.headers, array.count) }
            }
            _ => &[],
        };
        Self { entries }
    }

    /// Each header's name and value.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (Cow<'a, str>, Cow<'a, str>)> + 'a {
        self.entries.iter().map(|entry| {
            // SAFETY: the strings live for `'a`.
            unsafe { (string(entry.key), string(entry.value)) }
        })
    }

    /// The first value of `name`, ignoring ASCII case.
    pub fn get(&self, name: &str) -> Option<Cow<'a, str>> {
        self.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    /// The `:status` pseudo header, as a number.
    pub fn status(&self) -> Option<u16> {
        self.get(":status")?.parse().ok()
    }

    /// How many headers there are.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Debug for Headers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

/// The `Stream` a callback is for.
///
/// # Safety
///
/// `raw` is a stream made by `BidirectionalStream::new` that has not had its
/// final callback, so Cronet's reference keeps the `Stream` alive.
unsafe fn stream<'a>(raw: *mut sys::bidirectional_stream) -> &'a Stream {
    // SAFETY: the annotation is the `Stream`, alive per the caller.
    unsafe { &*(*raw).annotation.cast::<Stream>() }
}

unsafe extern "C" fn on_stream_ready(raw: *mut sys::bidirectional_stream) {
    let _network = NetworkThread::enter();
    // SAFETY: called before the final callback.
    let stream = unsafe { stream(raw) };
    stream.callback().on_stream_ready(stream);
}

unsafe extern "C" fn on_response_headers_received(
    raw: *mut sys::bidirectional_stream,
    headers: *const sys::bidirectional_stream_header_array,
    negotiated_protocol: *const c_char,
) {
    let _network = NetworkThread::enter();
    // SAFETY: called before the final callback, with headers valid for the call.
    let (stream, headers, protocol) = unsafe { (stream(raw), Headers::from_raw(headers), string(negotiated_protocol)) };
    stream
        .callback()
        .on_response_headers_received(stream, &headers, &protocol);
}

unsafe extern "C" fn on_read_completed(raw: *mut sys::bidirectional_stream, _data: *mut c_char, bytes_read: c_int) {
    let _network = NetworkThread::enter();
    // SAFETY: called before the final callback.
    let stream = unsafe { stream(raw) };
    let Some(mut buffer) = stream.state().read.take() else {
        return;
    };
    let bytes_read = usize::try_from(bytes_read).unwrap_or(0);
    // SAFETY: Cronet wrote `bytes_read` bytes into the spare capacity.
    unsafe { buffer.set_len(buffer.len() + bytes_read) };
    stream.callback().on_read_completed(stream, buffer, bytes_read);
}

unsafe extern "C" fn on_write_completed(raw: *mut sys::bidirectional_stream, data: *const c_char) {
    let _network = NetworkThread::enter();
    // SAFETY: called before the final callback.
    let stream = unsafe { stream(raw) };
    let Some(written) = stream.state().writes.pop_front() else {
        return;
    };
    debug_assert!(
        written.is_empty() || written.as_ptr().cast() == data,
        "writes complete in order"
    );
    stream.callback().on_write_completed(stream, written);
}

unsafe extern "C" fn on_response_trailers_received(
    raw: *mut sys::bidirectional_stream,
    trailers: *const sys::bidirectional_stream_header_array,
) {
    let _network = NetworkThread::enter();
    // SAFETY: called before the final callback, with trailers valid for the call.
    let (stream, trailers) = unsafe { (stream(raw), Headers::from_raw(trailers)) };
    stream.callback().on_response_trailers_received(stream, &trailers);
}

unsafe extern "C" fn on_succeeded(raw: *mut sys::bidirectional_stream) {
    // SAFETY: this is the final callback.
    unsafe { finish(raw, |callback, stream| callback.on_succeeded(stream)) }
}

unsafe extern "C" fn on_failed(raw: *mut sys::bidirectional_stream, net_error: c_int) {
    // SAFETY: this is the final callback.
    unsafe {
        finish(raw, |callback, stream| {
            callback.on_failed(stream, NetError::from_code(net_error))
        })
    }
}

unsafe extern "C" fn on_canceled(raw: *mut sys::bidirectional_stream) {
    // SAFETY: this is the final callback.
    unsafe { finish(raw, |callback, stream| callback.on_canceled(stream)) }
}

/// Reports how the stream ended, then frees everything: no callback follows a
/// final one, so the C stream, the buffers and Cronet's reference can go.
///
/// # Safety
///
/// Called once, from the final callback of a started stream.
unsafe fn finish(raw: *mut sys::bidirectional_stream, report: impl FnOnce(&mut dyn StreamCallback, &Stream)) {
    let _network = NetworkThread::enter();
    // SAFETY: the stream started, and this is its final callback.
    let stream = unsafe { stream(raw) };
    report(&mut **stream.callback(), stream);
    let buffers = {
        let mut state = stream.state();
        state.phase = Phase::Done;
        (state.read.take(), std::mem::take(&mut state.writes))
    };
    // SAFETY: no callback follows; destruction is posted, so the C stream
    // stays valid until this callback returns.
    unsafe { sys::bidirectional_stream_destroy(raw) };
    drop(buffers);
    // SAFETY: releases the reference `start` took for Cronet.
    unsafe { Arc::decrement_strong_count(ptr::from_ref(stream)) };
}
