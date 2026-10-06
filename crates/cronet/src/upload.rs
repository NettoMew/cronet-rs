//! Request bodies: the app provides them a piece at a time, when Cronet asks.

use std::{
    ffi::CString,
    fmt, io,
    ptr::NonNull,
    sync::{Mutex, PoisonError},
};

use cronet_sys as sys;

use crate::{BufferRef, Executor};

/// The body of a request, read by Cronet on the upload executor.
///
/// Each `read` and `rewind` must be answered once, at once or later and from
/// any thread, through the [`UploadRead`] or [`UploadRewind`] it is given;
/// dropping one unanswered reports an error to Cronet.
///
/// `std::io::Cursor` over bytes is a ready-made provider.
pub trait UploadDataProvider: Send + 'static {
    /// The body's length, or `None` for a chunked upload.
    fn length(&mut self) -> Option<u64>;

    /// Fill [`UploadRead::buffer`], then answer.
    fn read(&mut self, read: UploadRead);

    /// Start over from the beginning, for a redirect that keeps the body or a
    /// retry on a stale connection, then answer. Fail if that is impossible.
    fn rewind(&mut self, rewind: UploadRewind);

    /// The request no longer needs the body: release what it holds.
    fn close(&mut self) {}
}

/// A pending [`UploadDataProvider::read`].
#[must_use = "Cronet waits until the read is answered"]
pub struct UploadRead {
    sink: NonNull<sys::Cronet_UploadDataSink>,
    buffer: NonNull<sys::Cronet_Buffer>,
}

// SAFETY: the sink posts to the network thread from any thread, and the
// buffer is Cronet's, reserved for this read until it is answered.
unsafe impl Send for UploadRead {}

impl UploadRead {
    /// Where the data goes.
    pub fn buffer(&mut self) -> &mut BufferRef {
        // SAFETY: the buffer is reserved for this read until it is answered.
        unsafe { BufferRef::from_ptr_mut(self.buffer.as_ptr()) }
    }

    /// `bytes_read` bytes are in the buffer. `final_chunk` ends a chunked
    /// upload; it must be false otherwise.
    pub fn succeed(self, bytes_read: usize, final_chunk: bool) {
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: the sink is live until this read is answered, which this does once.
        unsafe { sys::Cronet_UploadDataSink_OnReadSucceeded(this.sink.as_ptr(), bytes_read as u64, final_chunk) }
    }

    /// The read failed; `message` reaches the request's
    /// [`on_failed`](crate::UrlRequestCallback::on_failed).
    pub fn fail(self, message: &str) {
        let this = std::mem::ManuallyDrop::new(self);
        Self::fail_raw(this.sink, message);
    }

    fn fail_raw(sink: NonNull<sys::Cronet_UploadDataSink>, message: &str) {
        let message = CString::new(message.replace('\0', " ")).expect("NUL bytes were replaced");
        // SAFETY: the sink is live until this read is answered, which this does once.
        unsafe { sys::Cronet_UploadDataSink_OnReadError(sink.as_ptr(), message.as_ptr()) }
    }
}

impl Drop for UploadRead {
    fn drop(&mut self) {
        Self::fail_raw(self.sink, "the upload read was dropped unanswered");
    }
}

impl fmt::Debug for UploadRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadRead")
            .field("sink", &self.sink)
            .finish_non_exhaustive()
    }
}

/// A pending [`UploadDataProvider::rewind`].
#[must_use = "Cronet waits until the rewind is answered"]
pub struct UploadRewind {
    sink: NonNull<sys::Cronet_UploadDataSink>,
}

// SAFETY: as for `UploadRead`.
unsafe impl Send for UploadRewind {}

impl UploadRewind {
    /// The body starts over.
    pub fn succeed(self) {
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: the sink is live until this rewind is answered, which this does once.
        unsafe { sys::Cronet_UploadDataSink_OnRewindSucceeded(this.sink.as_ptr()) }
    }

    /// The body cannot start over; `message` reaches the request's
    /// [`on_failed`](crate::UrlRequestCallback::on_failed).
    pub fn fail(self, message: &str) {
        let this = std::mem::ManuallyDrop::new(self);
        Self::fail_raw(this.sink, message);
    }

    fn fail_raw(sink: NonNull<sys::Cronet_UploadDataSink>, message: &str) {
        let message = CString::new(message.replace('\0', " ")).expect("NUL bytes were replaced");
        // SAFETY: the sink is live until this rewind is answered, which this does once.
        unsafe { sys::Cronet_UploadDataSink_OnRewindError(sink.as_ptr(), message.as_ptr()) }
    }
}

impl Drop for UploadRewind {
    fn drop(&mut self) {
        Self::fail_raw(self.sink, "the upload rewind was dropped unanswered");
    }
}

impl fmt::Debug for UploadRewind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadRewind").field("sink", &self.sink).finish()
    }
}

/// An in-memory body: its length is known, and rewinding is free.
impl<T: AsRef<[u8]> + Send + 'static> UploadDataProvider for io::Cursor<T> {
    fn length(&mut self) -> Option<u64> {
        Some(self.get_ref().as_ref().len() as u64)
    }

    fn read(&mut self, mut read: UploadRead) {
        let n = io::Read::read(self, read.buffer()).expect("reading from memory cannot fail");
        read.succeed(n, false);
    }

    fn rewind(&mut self, rewind: UploadRewind) {
        self.set_position(0);
        rewind.succeed();
    }
}

/// A provider handed to Cronet, with the executor it runs on. Cronet owns the
/// C object from the moment a request adopts it, and frees it by calling
/// `Close`; until then, dropping this frees it.
pub(crate) struct Upload {
    raw: NonNull<sys::Cronet_UploadDataProvider>,
    executor: Executor,
    adopted: bool,
}

// SAFETY: the provider is `Send`, behind a lock, and its C object has no
// thread affinity.
unsafe impl Send for Upload {}

type Provider = Mutex<Box<dyn UploadDataProvider>>;

impl Upload {
    pub(crate) fn new(provider: impl UploadDataProvider, executor: &Executor) -> Self {
        // SAFETY: the trampolines match the C function types.
        let raw = unsafe {
            sys::Cronet_UploadDataProvider_CreateWith(
                Some(provider_len),
                Some(provider_read),
                Some(provider_rewind),
                Some(provider_close),
            )
        };
        let raw = NonNull::new(raw).expect("Cronet_UploadDataProvider_CreateWith returned null");
        let provider: Box<Provider> = Box::new(Mutex::new(Box::new(provider)));
        // SAFETY: the context lives until `provider_close`, or until this is
        // dropped without being adopted.
        unsafe { sys::Cronet_UploadDataProvider_SetClientContext(raw.as_ptr(), Box::into_raw(provider).cast()) };
        Self {
            raw,
            executor: executor.clone(),
            adopted: false,
        }
    }

    pub(crate) fn as_ptr(&self) -> sys::Cronet_UploadDataProviderPtr {
        self.raw.as_ptr()
    }

    pub(crate) fn executor(&self) -> &Executor {
        &self.executor
    }

    /// A request took the provider: Cronet will close and so free it.
    pub(crate) fn adopt(mut self) -> Executor {
        self.adopted = true;
        self.executor.clone()
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        if !self.adopted {
            // SAFETY: no request uses the provider, so it and its context are ours to free.
            unsafe { free(self.raw.as_ptr()) }
        }
    }
}

/// # Safety
///
/// `raw` is a provider made by `Upload::new` that Cronet no longer uses.
unsafe fn free(raw: sys::Cronet_UploadDataProviderPtr) {
    // SAFETY: the context is the `Provider` boxed by `Upload::new`.
    unsafe {
        let provider = sys::Cronet_UploadDataProvider_GetClientContext(raw);
        sys::Cronet_UploadDataProvider_Destroy(raw);
        drop(Box::from_raw(provider.cast::<Provider>()));
    }
}

/// # Safety
///
/// `raw` is a live provider made by `Upload::new`.
unsafe fn provider<'a>(
    raw: sys::Cronet_UploadDataProviderPtr,
) -> std::sync::MutexGuard<'a, Box<dyn UploadDataProvider>> {
    // SAFETY: the context is the provider's `Provider`, alive until it closes.
    let provider = unsafe { &*sys::Cronet_UploadDataProvider_GetClientContext(raw).cast::<Provider>() };
    provider.lock().unwrap_or_else(PoisonError::into_inner)
}

unsafe extern "C" fn provider_len(raw: sys::Cronet_UploadDataProviderPtr) -> i64 {
    // SAFETY: Cronet calls the provider until it closes it.
    let length = unsafe { provider(raw) }.length();
    length.map_or(-1, |length| i64::try_from(length).unwrap_or(i64::MAX))
}

unsafe extern "C" fn provider_read(
    raw: sys::Cronet_UploadDataProviderPtr,
    sink: sys::Cronet_UploadDataSinkPtr,
    buffer: sys::Cronet_BufferPtr,
) {
    let read = UploadRead {
        sink: NonNull::new(sink).expect("Cronet passed a null upload sink"),
        buffer: NonNull::new(buffer).expect("Cronet passed a null upload buffer"),
    };
    // SAFETY: Cronet calls the provider until it closes it.
    unsafe { provider(raw) }.read(read);
}

unsafe extern "C" fn provider_rewind(raw: sys::Cronet_UploadDataProviderPtr, sink: sys::Cronet_UploadDataSinkPtr) {
    let rewind = UploadRewind {
        sink: NonNull::new(sink).expect("Cronet passed a null upload sink"),
    };
    // SAFETY: Cronet calls the provider until it closes it.
    unsafe { provider(raw) }.rewind(rewind);
}

unsafe extern "C" fn provider_close(raw: sys::Cronet_UploadDataProviderPtr) {
    // SAFETY: Cronet closes the provider last, and never uses it again.
    unsafe {
        provider(raw).close();
        free(raw);
    }
}
