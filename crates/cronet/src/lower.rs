//! Adapting a Tokio byte stream (`AsyncRead + AsyncWrite`) into a non-blocking
//! `Cronet_LowerStream` driven on Cronet's network thread.

use std::{
    ffi::c_void,
    future::Future,
    io,
    pin::Pin,
    ptr::NonNull,
    slice,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use cronet_sys as sys;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{NetError, engine::NetworkThread};

/// A byte stream handed to Cronet, which reads, writes and closes it without
/// touching an OS socket.
///
/// Implemented for every `AsyncRead + AsyncWrite + Send + Unpin + 'static`,
/// including `Box<dyn Lower>`.
pub trait Lower: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Lower for T {}

struct LowerHandle(NonNull<sys::Cronet_LowerStreamHandle>);

// SAFETY: `Cronet_LowerStreamHandle_Notify` and `Destroy` are thread-safe.
unsafe impl Send for LowerHandle {}
// SAFETY: as above.
unsafe impl Sync for LowerHandle {}

impl LowerHandle {
    fn notify(&self, flags: u32) {
        // SAFETY: the handle stays valid until `Drop` destroys it.
        unsafe { sys::Cronet_LowerStreamHandle_Notify(self.0.as_ptr(), flags) };
    }
}

impl Drop for LowerHandle {
    fn drop(&mut self) {
        // SAFETY: wrapped in a single `Arc<LowerHandle>`, so destroyed once
        // after both the context and every cloned `Waker` have dropped.
        unsafe { sys::Cronet_LowerStreamHandle_Destroy(self.0.as_ptr()) };
    }
}

/// Shared readiness coordinator between Tokio wakers and Cronet's bridge.
struct NotifyGate {
    handle: LowerHandle,
    in_poll: AtomicBool,
    sync_woke: AtomicU32,
}

impl NotifyGate {
    fn signal(self: &Arc<Self>, flags: u32) {
        if self.in_poll.load(Ordering::Acquire) && NetworkThread::is_current() {
            self.sync_woke.fetch_or(flags, Ordering::AcqRel);
        } else {
            self.handle.notify(flags);
        }
    }

    fn signal_async(self: &Arc<Self>, flags: u32) {
        let gate = self.clone();
        std::thread::spawn(move || gate.handle.notify(flags));
    }
}

struct ReadyWaker {
    gate: Arc<NotifyGate>,
    flags: u32,
}

impl Wake for ReadyWaker {
    fn wake(self: Arc<Self>) {
        self.gate.signal(self.flags);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.gate.signal(self.flags);
    }
}

struct LowerContext {
    stream: Mutex<Option<Box<dyn Lower>>>,
    runtime: Option<tokio::runtime::Handle>,
    gate: Arc<NotifyGate>,
    read_waker: Waker,
    write_waker: Waker,
}

const READABLE: u32 = sys::Cronet_LowerReady_READABLE as u32;
const WRITABLE: u32 = sys::Cronet_LowerReady_WRITABLE as u32;
const IO_PENDING: isize = -1;
const MAX_SYNC_REPOLLS: usize = 8;

/// Packages `stream` and `handle` into a `Cronet_LowerStream` whose `close`
/// callback frees the boxed state.
///
/// # Safety
///
/// `handle` must be a newly created `Cronet_LowerStreamHandle` whose ownership
/// transfers to this stream.
pub(crate) unsafe fn into_raw_stream(
    stream: Box<dyn Lower>,
    handle: *mut sys::Cronet_LowerStreamHandle,
    runtime: Option<tokio::runtime::Handle>,
) -> sys::Cronet_LowerStream {
    let handle = LowerHandle(NonNull::new(handle).expect("Cronet_LowerStreamHandle is non-null"));
    let gate = Arc::new(NotifyGate {
        handle,
        in_poll: AtomicBool::new(false),
        sync_woke: AtomicU32::new(0),
    });
    let read_waker = Waker::from(Arc::new(ReadyWaker {
        gate: gate.clone(),
        flags: READABLE,
    }));
    let write_waker = Waker::from(Arc::new(ReadyWaker {
        gate: gate.clone(),
        flags: WRITABLE,
    }));
    let context = Box::new(LowerContext {
        stream: Mutex::new(Some(stream)),
        runtime,
        gate,
        read_waker,
        write_waker,
    });
    sys::Cronet_LowerStream {
        context: Box::into_raw(context).cast::<c_void>(),
        read: Some(lower_read),
        write: Some(lower_write),
        close: Some(lower_close),
    }
}

struct PollGuard<'a>(&'a NotifyGate);

impl<'a> PollGuard<'a> {
    fn enter(gate: &'a NotifyGate) -> Self {
        gate.sync_woke.store(0, Ordering::Release);
        gate.in_poll.store(true, Ordering::Release);
        Self(gate)
    }

    fn take_woke(&self) -> u32 {
        self.0.sync_woke.swap(0, Ordering::AcqRel)
    }
}

impl Drop for PollGuard<'_> {
    fn drop(&mut self) {
        self.0.in_poll.store(false, Ordering::Release);
    }
}

unsafe extern "C" fn lower_read(context: *mut c_void, buffer: *mut u8, capacity: usize) -> isize {
    let _network = NetworkThread::enter();
    if capacity == 0 {
        return 0;
    }
    // SAFETY: `context` is the `LowerContext` allocated in `into_raw_stream`,
    // alive until `lower_close` runs.
    let ctx = unsafe { &*context.cast::<LowerContext>() };
    let _rt = ctx.runtime.as_ref().map(tokio::runtime::Handle::enter);
    let mut slot = ctx.stream.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(stream) = slot.as_mut() else {
        return NetError::SOCKET_NOT_CONNECTED.code() as isize;
    };
    // SAFETY: Cronet passes a writable buffer of `capacity` bytes.
    let slice = unsafe { slice::from_raw_parts_mut(buffer, capacity) };
    let mut cx = Context::from_waker(&ctx.read_waker);

    let mut deferred_other = 0u32;
    let outcome = {
        let guard = PollGuard::enter(&ctx.gate);
        let mut repolls = 0;
        loop {
            let mut read_buf = ReadBuf::new(slice);
            match Pin::new(&mut **stream).poll_read(&mut cx, &mut read_buf) {
                Poll::Ready(Ok(())) => break Ok(read_buf.filled().len() as isize),
                Poll::Ready(Err(error)) => break Err(NetError::from_io_error(&error)),
                Poll::Pending => {
                    let woke = guard.take_woke();
                    deferred_other |= woke & !READABLE;
                    if (woke & READABLE) != 0 {
                        if repolls < MAX_SYNC_REPOLLS {
                            repolls += 1;
                            continue;
                        }
                        deferred_other |= READABLE;
                    }
                    break Ok(IO_PENDING);
                }
            }
        }
    };
    drop(slot);
    if deferred_other != 0 {
        ctx.gate.signal_async(deferred_other);
    }
    match outcome {
        Ok(n) => n,
        Err(error) => error.code() as isize,
    }
}

unsafe extern "C" fn lower_write(context: *mut c_void, data: *const u8, length: usize) -> isize {
    let _network = NetworkThread::enter();
    if length == 0 {
        return 0;
    }
    // SAFETY: `context` is the `LowerContext` allocated in `into_raw_stream`,
    // alive until `lower_close` runs.
    let ctx = unsafe { &*context.cast::<LowerContext>() };
    let _rt = ctx.runtime.as_ref().map(tokio::runtime::Handle::enter);
    let mut slot = ctx.stream.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(stream) = slot.as_mut() else {
        return NetError::SOCKET_NOT_CONNECTED.code() as isize;
    };
    // SAFETY: Cronet passes `length` readable bytes.
    let slice = unsafe { slice::from_raw_parts(data, length) };
    let mut cx = Context::from_waker(&ctx.write_waker);

    let mut deferred_other = 0u32;
    let outcome = {
        let guard = PollGuard::enter(&ctx.gate);
        let mut repolls = 0;
        loop {
            match Pin::new(&mut **stream).poll_write(&mut cx, slice) {
                Poll::Ready(Ok(0)) => break Err(NetError::CONNECTION_CLOSED),
                Poll::Ready(Ok(written)) => {
                    let _ = Pin::new(&mut **stream).poll_flush(&mut cx);
                    deferred_other |= guard.take_woke();
                    break Ok(written as isize);
                }
                Poll::Ready(Err(error)) => break Err(NetError::from_io_error(&error)),
                Poll::Pending => {
                    let woke = guard.take_woke();
                    deferred_other |= woke & !WRITABLE;
                    if (woke & WRITABLE) != 0 {
                        if repolls < MAX_SYNC_REPOLLS {
                            repolls += 1;
                            continue;
                        }
                        deferred_other |= WRITABLE;
                    }
                    break Ok(IO_PENDING);
                }
            }
        }
    };
    drop(slot);
    if deferred_other != 0 {
        ctx.gate.signal_async(deferred_other);
    }
    match outcome {
        Ok(n) => n,
        Err(error) => error.code() as isize,
    }
}

unsafe extern "C" fn lower_close(context: *mut c_void) {
    let _network = NetworkThread::enter();
    if context.is_null() {
        return;
    }
    // SAFETY: Cronet calls `close` at most once and never calls `read` or
    // `write` afterwards.
    let ctx = unsafe { Box::from_raw(context.cast::<LowerContext>()) };
    let _rt = ctx.runtime.as_ref().map(tokio::runtime::Handle::enter);
    if let Some(mut stream) = ctx.stream.lock().unwrap_or_else(PoisonError::into_inner).take() {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let _ = Pin::new(&mut *stream).poll_shutdown(&mut cx);
    }
}

/// Wraps an async dial future into a [`Lower`] stream so Cronet's network
/// thread never blocks waiting for the connection to establish.
pub(crate) fn connecting<F, S>(future: F) -> Box<dyn Lower>
where
    F: Future<Output = io::Result<S>> + Send + 'static,
    S: Lower,
{
    Box::new(Connecting::Pending {
        future: Box::pin(future),
        wakers: Arc::new(Mutex::new((None, None))),
    })
}

type PairWakers = Mutex<(Option<Waker>, Option<Waker>)>;

struct ConnectWaker(Arc<PairWakers>);

impl Wake for ConnectWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let (r, w) = {
            let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            (slot.0.take(), slot.1.take())
        };
        if let Some(r) = r {
            r.wake();
        }
        if let Some(w) = w {
            w.wake();
        }
    }
}

enum Connecting<F, S> {
    Pending {
        future: Pin<Box<F>>,
        wakers: Arc<PairWakers>,
    },
    Ready(S),
    Failed,
}

impl<F, S> Connecting<F, S>
where
    F: Future<Output = io::Result<S>> + Send + 'static,
    S: Lower,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>, is_write: bool) -> Poll<io::Result<&mut S>> {
        loop {
            match self {
                Self::Pending { future, wakers } => {
                    {
                        let mut slot = wakers.lock().unwrap_or_else(PoisonError::into_inner);
                        if is_write {
                            slot.1 = Some(cx.waker().clone());
                        } else {
                            slot.0 = Some(cx.waker().clone());
                        }
                    }
                    let combined = Waker::from(Arc::new(ConnectWaker(wakers.clone())));
                    let mut sub_cx = Context::from_waker(&combined);
                    match future.as_mut().poll(&mut sub_cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(stream)) => {
                            let other = {
                                let mut slot = wakers.lock().unwrap_or_else(PoisonError::into_inner);
                                if is_write { slot.0.take() } else { slot.1.take() }
                            };
                            *self = Self::Ready(stream);
                            if let Some(other) = other {
                                other.wake();
                            }
                        }
                        Poll::Ready(Err(error)) => {
                            let other = {
                                let mut slot = wakers.lock().unwrap_or_else(PoisonError::into_inner);
                                if is_write { slot.0.take() } else { slot.1.take() }
                            };
                            *self = Self::Failed;
                            if let Some(other) = other {
                                other.wake();
                            }
                            return Poll::Ready(Err(error));
                        }
                    }
                }
                Self::Ready(stream) => return Poll::Ready(Ok(stream)),
                Self::Failed => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "stream dial failed")));
                }
            }
        }
    }
}

impl<F, S> AsyncRead for Connecting<F, S>
where
    F: Future<Output = io::Result<S>> + Send + 'static,
    S: Lower,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_ready(cx, false) {
            Poll::Ready(Ok(stream)) => Pin::new(stream).poll_read(cx, buf),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F, S> AsyncWrite for Connecting<F, S>
where
    F: Future<Output = io::Result<S>> + Send + 'static,
    S: Lower,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_ready(cx, true) {
            Poll::Ready(Ok(stream)) => Pin::new(stream).poll_write(cx, buf),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_ready(cx, true) {
            Poll::Ready(Ok(stream)) => Pin::new(stream).poll_flush(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_ready(cx, true) {
            Poll::Ready(Ok(stream)) => Pin::new(stream).poll_shutdown(cx),
            Poll::Ready(Err(_)) | Poll::Pending => Poll::Ready(Ok(())),
        }
    }
}
