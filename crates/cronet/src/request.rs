//! URL requests: one HTTP request and its response, driven by callbacks.

use std::{
    ffi::CString,
    fmt,
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
    ptr::NonNull,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use cronet_sys as sys;

use crate::{
    ApiError, Buffer, Engine, ErrorRef, Executor, RequestFinishedListener, UrlResponseInfoRef,
    ffi::{FromC, Opaque, c_enum, properties, string},
    upload::{Upload, UploadDataProvider},
};

c_enum! {
    /// How urgent a request is.
    pub enum RequestPriority: sys::Cronet_UrlRequestParams_REQUEST_PRIORITY {
        /// Lowest of all.
        Idle = sys::Cronet_UrlRequestParams_REQUEST_PRIORITY_REQUEST_PRIORITY_IDLE,
        /// Very low.
        Lowest = sys::Cronet_UrlRequestParams_REQUEST_PRIORITY_REQUEST_PRIORITY_LOWEST,
        /// Low.
        Low = sys::Cronet_UrlRequestParams_REQUEST_PRIORITY_REQUEST_PRIORITY_LOW,
        /// Medium: the default.
        Medium = sys::Cronet_UrlRequestParams_REQUEST_PRIORITY_REQUEST_PRIORITY_MEDIUM,
        /// Highest.
        Highest = sys::Cronet_UrlRequestParams_REQUEST_PRIORITY_REQUEST_PRIORITY_HIGHEST,
    }
    unknown => Medium;
}

c_enum! {
    /// Whether repeating a request is harmless, which decides whether QUIC
    /// may send it as 0-RTT data that an observer could replay.
    pub enum Idempotency: sys::Cronet_UrlRequestParams_IDEMPOTENCY {
        /// Only for safe methods: `GET`, `HEAD`, `OPTIONS` and `TRACE`.
        Default = sys::Cronet_UrlRequestParams_IDEMPOTENCY_DEFAULT_IDEMPOTENCY,
        /// Repeating it is harmless.
        Idempotent = sys::Cronet_UrlRequestParams_IDEMPOTENCY_IDEMPOTENT,
        /// Repeating it is not.
        NotIdempotent = sys::Cronet_UrlRequestParams_IDEMPOTENCY_NOT_IDEMPOTENT,
    }
    unknown => Default;
}

c_enum! {
    /// What a request is doing, as [`UrlRequest::status`] reports.
    pub enum RequestStatus: sys::Cronet_UrlRequestStatusListener_Status {
        /// Not started, or already done.
        Invalid = sys::Cronet_UrlRequestStatusListener_Status_INVALID,
        /// Idle: between steps.
        Idle = sys::Cronet_UrlRequestStatusListener_Status_IDLE,
        /// Waiting for a socket pool stalled by the global socket limit.
        WaitingForStalledSocketPool = sys::Cronet_UrlRequestStatusListener_Status_WAITING_FOR_STALLED_SOCKET_POOL,
        /// Waiting for a socket to its host to be free.
        WaitingForAvailableSocket = sys::Cronet_UrlRequestStatusListener_Status_WAITING_FOR_AVAILABLE_SOCKET,
        /// Waiting for the app.
        WaitingForDelegate = sys::Cronet_UrlRequestStatusListener_Status_WAITING_FOR_DELEGATE,
        /// Waiting for the cache.
        WaitingForCache = sys::Cronet_UrlRequestStatusListener_Status_WAITING_FOR_CACHE,
        /// Downloading a PAC script.
        DownloadingPacFile = sys::Cronet_UrlRequestStatusListener_Status_DOWNLOADING_PAC_FILE,
        /// Resolving the proxy for the URL.
        ResolvingProxyForUrl = sys::Cronet_UrlRequestStatusListener_Status_RESOLVING_PROXY_FOR_URL,
        /// Resolving a host name inside a PAC script.
        ResolvingHostInPacFile = sys::Cronet_UrlRequestStatusListener_Status_RESOLVING_HOST_IN_PAC_FILE,
        /// Establishing a tunnel through the proxy.
        EstablishingProxyTunnel = sys::Cronet_UrlRequestStatusListener_Status_ESTABLISHING_PROXY_TUNNEL,
        /// Resolving the host name.
        ResolvingHost = sys::Cronet_UrlRequestStatusListener_Status_RESOLVING_HOST,
        /// Connecting.
        Connecting = sys::Cronet_UrlRequestStatusListener_Status_CONNECTING,
        /// In the TLS handshake.
        SslHandshake = sys::Cronet_UrlRequestStatusListener_Status_SSL_HANDSHAKE,
        /// Sending the request.
        SendingRequest = sys::Cronet_UrlRequestStatusListener_Status_SENDING_REQUEST,
        /// Waiting for the response.
        WaitingForResponse = sys::Cronet_UrlRequestStatusListener_Status_WAITING_FOR_RESPONSE,
        /// Reading the response.
        ReadingResponse = sys::Cronet_UrlRequestStatusListener_Status_READING_RESPONSE,
    }
    unknown => Invalid;
}

/// How a request is made: method, headers, body, priority and more.
///
/// ```no_run
/// # use cronet::{UrlRequestParams, Executor};
/// let mut params = UrlRequestParams::new();
/// params.set_method("POST").add_header("Content-Type", "text/plain");
/// params.set_upload(std::io::Cursor::new(b"hello"), &Executor::thread());
/// ```
pub struct UrlRequestParams {
    raw: NonNull<sys::Cronet_UrlRequestParams>,
    upload: Option<Upload>,
    request_finished: Option<(RequestFinishedListener, Executor)>,
}

/// A borrowed [`UrlRequestParams`]: the settings Cronet itself keeps.
pub struct UrlRequestParamsRef(Opaque);

// SAFETY: the C object is plain data, and the attachments are `Send`.
unsafe impl Send for UrlRequestParams {}
// SAFETY: plain data; `&` only reads.
unsafe impl Send for UrlRequestParamsRef {}
// SAFETY: as above.
unsafe impl Sync for UrlRequestParamsRef {}

impl UrlRequestParams {
    /// Cronet's defaults: `GET` (or `POST` with a body), no headers.
    pub fn new() -> Self {
        // SAFETY: allocation has no preconditions.
        let raw = unsafe { sys::Cronet_UrlRequestParams_Create() };
        Self {
            raw: NonNull::new(raw).expect("Cronet_UrlRequestParams_Create returned null"),
            upload: None,
            request_finished: None,
        }
    }

    /// The request body, read on `executor`. Without an explicit method this
    /// makes the request a `POST`. Set a `Content-Type` header to say what the
    /// body is; Cronet does not add one.
    pub fn set_upload(&mut self, provider: impl UploadDataProvider, executor: &Executor) -> &mut Self {
        let upload = Upload::new(provider, executor);
        // SAFETY: the params object is live; the provider and executor stay
        // alive with `self`, and with the request it is used for.
        unsafe {
            sys::Cronet_UrlRequestParams_upload_data_provider_set(self.raw.as_ptr(), upload.as_ptr());
            sys::Cronet_UrlRequestParams_upload_data_provider_executor_set(
                self.raw.as_ptr(),
                upload.executor().as_ptr(),
            );
        }
        self.upload = Some(upload);
        self
    }

    /// A listener for this request alone, called on `executor` when it ends;
    /// see [`RequestFinishedListener`].
    pub fn set_request_finished_listener(
        &mut self,
        listener: &RequestFinishedListener,
        executor: &Executor,
    ) -> &mut Self {
        // SAFETY: all three are live; the request keeps the listener and executor.
        unsafe {
            sys::Cronet_UrlRequestParams_request_finished_listener_set(self.raw.as_ptr(), listener.as_ptr());
            sys::Cronet_UrlRequestParams_request_finished_executor_set(self.raw.as_ptr(), executor.as_ptr());
        }
        self.request_finished = Some((listener.clone(), executor.clone()));
        self
    }
}

impl Default for UrlRequestParams {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UrlRequestParams {
    fn drop(&mut self) {
        // SAFETY: the params are owned; a request copied what it needed.
        unsafe { sys::Cronet_UrlRequestParams_Destroy(self.raw.as_ptr()) }
    }
}

impl Deref for UrlRequestParams {
    type Target = UrlRequestParamsRef;

    fn deref(&self) -> &UrlRequestParamsRef {
        // SAFETY: the params live as long as `self`.
        unsafe { &*self.raw.as_ptr().cast::<UrlRequestParamsRef>() }
    }
}

impl DerefMut for UrlRequestParams {
    fn deref_mut(&mut self) -> &mut UrlRequestParamsRef {
        // SAFETY: the params live as long as `self`, borrowed uniquely.
        unsafe { &mut *self.raw.as_ptr().cast::<UrlRequestParamsRef>() }
    }
}

impl UrlRequestParamsRef {
    fn as_ptr(&self) -> sys::Cronet_UrlRequestParamsPtr {
        (self as *const Self).cast_mut().cast()
    }
}

properties!(UrlRequestParamsRef {
    /// The method: `GET`, `HEAD`, `DELETE`, `POST`, `PUT` or `CONNECT`. Unset,
    /// it is `GET`, or `POST` with a body.
    string method, set_method: sys::Cronet_UrlRequestParams_http_method_get, sys::Cronet_UrlRequestParams_http_method_set;
    /// Whether the request bypasses the cache; meaningless without one.
    bool as disable_cache, set_disable_cache:
        sys::Cronet_UrlRequestParams_disable_cache_get, sys::Cronet_UrlRequestParams_disable_cache_set;
    /// How urgent the request is.
    RequestPriority as priority, set_priority:
        sys::Cronet_UrlRequestParams_priority_get, sys::Cronet_UrlRequestParams_priority_set;
    /// Whether the request's executors may run callbacks inline, on Cronet's
    /// network thread. Only for callbacks that never block: no I/O, no locks,
    /// no code not carefully audited.
    bool as allow_direct_executor, set_allow_direct_executor:
        sys::Cronet_UrlRequestParams_allow_direct_executor_get, sys::Cronet_UrlRequestParams_allow_direct_executor_set;
    /// Whether repeating the request is harmless.
    Idempotency as idempotency, set_idempotency:
        sys::Cronet_UrlRequestParams_idempotency_get, sys::Cronet_UrlRequestParams_idempotency_set;
});

impl UrlRequestParamsRef {
    /// The request headers, in order.
    pub fn headers(&self) -> impl ExactSizeIterator<Item = &crate::HttpHeaderRef> + '_ {
        // SAFETY: the object is live.
        let len = unsafe { sys::Cronet_UrlRequestParams_request_headers_size(self.as_ptr()) };
        (0..len).map(move |index| {
            // SAFETY: `index` is in bounds, and the list is not modified while `self` is borrowed.
            unsafe {
                crate::HttpHeaderRef::from_ptr(sys::Cronet_UrlRequestParams_request_headers_at(self.as_ptr(), index))
            }
        })
    }

    /// Adds a header.
    ///
    /// # Panics
    ///
    /// If `name` or `value` contains a NUL byte.
    pub fn add_header(&mut self, name: &str, value: &str) -> &mut Self {
        let header = crate::HttpHeader::with(name, value);
        // SAFETY: both objects are live; Cronet copies the header.
        unsafe { sys::Cronet_UrlRequestParams_request_headers_add(self.as_ptr(), header.as_ptr()) };
        self
    }

    /// Removes every header.
    pub fn clear_headers(&mut self) -> &mut Self {
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_UrlRequestParams_request_headers_clear(self.as_ptr()) };
        self
    }

    /// Opaque values passed through to the
    /// [`RequestFinishedInfoRef::annotations`](crate::RequestFinishedInfoRef::annotations)
    /// listeners see, to tell requests apart.
    pub fn annotations(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        // SAFETY: the object is live.
        let len = unsafe { sys::Cronet_UrlRequestParams_annotations_size(self.as_ptr()) };
        // SAFETY: `index` is in bounds; annotations are opaque values.
        (0..len).map(move |index| unsafe { sys::Cronet_UrlRequestParams_annotations_at(self.as_ptr(), index) } as usize)
    }

    /// Adds to [`annotations`](Self::annotations).
    pub fn add_annotation(&mut self, annotation: usize) -> &mut Self {
        // SAFETY: the object is live; Cronet never dereferences annotations.
        unsafe { sys::Cronet_UrlRequestParams_annotations_add(self.as_ptr(), annotation as sys::Cronet_RawDataPtr) };
        self
    }

    /// Empties [`annotations`](Self::annotations).
    pub fn clear_annotations(&mut self) -> &mut Self {
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_UrlRequestParams_annotations_clear(self.as_ptr()) };
        self
    }
}

impl fmt::Debug for UrlRequestParamsRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UrlRequestParams")
            .field("method", &self.method())
            .field("headers", &self.headers().collect::<Vec<_>>())
            .field("disable_cache", &self.disable_cache())
            .field("priority", &self.priority())
            .field("allow_direct_executor", &self.allow_direct_executor())
            .field("idempotency", &self.idempotency())
            .field("annotations", &self.annotations().collect::<Vec<_>>())
            .finish()
    }
}

impl fmt::Debug for UrlRequestParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

/// What a [`UrlRequest`] reports, on its executor.
///
/// After a response starts, each step waits for the app: a read for every
/// [`on_read_completed`](Self::on_read_completed), a decision for every
/// redirect. Exactly one of `on_succeeded`, `on_failed` and `on_canceled`
/// ends the request; nothing is called after it.
pub trait UrlRequestCallback: Send + 'static {
    /// A redirect to `new_location_url`. The default follows it; otherwise
    /// call [`UrlRequest::follow_redirect`] or [`UrlRequest::cancel`].
    fn on_redirect_received(&mut self, request: &UrlRequest, info: &UrlResponseInfoRef, new_location_url: &str) {
        let _ = (info, new_location_url);
        let _ = request.follow_redirect();
    }

    /// The final headers arrived, after every redirect: start reading the
    /// body with [`UrlRequest::read`], or cancel.
    fn on_response_started(&mut self, request: &UrlRequest, info: &UrlResponseInfoRef);

    /// `bytes_read` bytes of the body are at the start of `buffer`, which is
    /// the app's again. Read on, or cancel.
    fn on_read_completed(&mut self, request: &UrlRequest, info: &UrlResponseInfoRef, buffer: Buffer, bytes_read: u64);

    /// The request completed.
    fn on_succeeded(&mut self, request: &UrlRequest, info: &UrlResponseInfoRef);

    /// The request failed; `info` is there if a response had arrived.
    fn on_failed(&mut self, request: &UrlRequest, info: Option<&UrlResponseInfoRef>, error: &ErrorRef);

    /// The request was [canceled](UrlRequest::cancel).
    fn on_canceled(&mut self, request: &UrlRequest, info: Option<&UrlResponseInfoRef>);
}

/// An HTTP request in flight, driven by its [`UrlRequestCallback`].
///
/// Cloning is cheap, and every method may be called from any thread. Once
/// started, a request runs to its end even if every clone is dropped; cancel
/// it to stop it.
#[derive(Clone)]
pub struct UrlRequest(Arc<Inner>);

struct Inner {
    raw: NonNull<sys::Cronet_UrlRequest>,
    callback_raw: NonNull<sys::Cronet_UrlRequestCallback>,
    phase: Mutex<Phase>,
    callback: Mutex<Box<dyn UrlRequestCallback>>,
    /// Everything Cronet calls into for this request, kept alive with it.
    _keep: (
        Engine,
        Executor,
        Option<Executor>,
        Option<(RequestFinishedListener, Executor)>,
    ),
}

// SAFETY: Cronet's request takes a lock in every method, the phase and the
// callback are behind locks, and the callback is `Send`.
unsafe impl Send for Inner {}
// SAFETY: as above.
unsafe impl Sync for Inner {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Initialized,
    /// Started: Cronet holds a strong reference until a final callback.
    Started,
    Done,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // SAFETY: the request never started or has ended, so Cronet is done
        // with it and with its callback object.
        unsafe {
            sys::Cronet_UrlRequest_Destroy(self.raw.as_ptr());
            sys::Cronet_UrlRequestCallback_Destroy(self.callback_raw.as_ptr());
        }
    }
}

impl UrlRequest {
    /// A request for `url` on `engine`, described by `params`, reporting to
    /// `callback` on `executor`. Nothing is sent until [`start`](Self::start).
    ///
    /// The executor must not run tasks on the thread that hands them over,
    /// unless the params [allow it](UrlRequestParamsRef::set_allow_direct_executor).
    ///
    /// # Errors
    ///
    /// The [`ApiError`] Cronet refused the request with, such as an invalid
    /// method or header (unless Cronet aborts instead), or
    /// [`ApiError::NullPointerUrl`] for a URL containing a NUL byte.
    pub fn new(
        engine: &Engine,
        url: &str,
        mut params: UrlRequestParams,
        callback: impl UrlRequestCallback,
        executor: &Executor,
    ) -> Result<Self, ApiError> {
        let url = CString::new(url).map_err(|_| ApiError::NullPointerUrl)?;
        // SAFETY: the trampolines match the C function types.
        let callback_raw = unsafe {
            sys::Cronet_UrlRequestCallback_CreateWith(
                Some(on_redirect_received),
                Some(on_response_started),
                Some(on_read_completed),
                Some(on_succeeded),
                Some(on_failed),
                Some(on_canceled),
            )
        };
        // SAFETY: allocation has no preconditions.
        let raw = unsafe { sys::Cronet_UrlRequest_Create() };
        let inner = Arc::new(Inner {
            raw: NonNull::new(raw).expect("Cronet_UrlRequest_Create returned null"),
            callback_raw: NonNull::new(callback_raw).expect("Cronet_UrlRequestCallback_CreateWith returned null"),
            phase: Mutex::new(Phase::Initialized),
            callback: Mutex::new(Box::new(callback)),
            _keep: (engine.clone(), executor.clone(), None, params.request_finished.take()),
        });
        let context = Arc::as_ptr(&inner).cast_mut().cast();
        // SAFETY: the context is the `Inner` owning the callback object, which
        // it outlives. Every object passed is live, and kept alive by `inner`.
        let result = unsafe {
            sys::Cronet_UrlRequestCallback_SetClientContext(callback_raw, context);
            sys::Cronet_UrlRequest_InitWithParams(
                raw,
                engine.as_ptr(),
                url.as_ptr(),
                params.raw.as_ptr(),
                callback_raw,
                executor.as_ptr(),
            )
        };
        ApiError::check(result)?;
        let mut inner = inner;
        if let Some(upload) = params.upload.take() {
            let upload_executor = upload.adopt();
            Arc::get_mut(&mut inner)
                .expect("nothing else holds the new request")
                ._keep
                .2 = Some(upload_executor);
        }
        Ok(Self(inner))
    }

    fn phase(&self) -> MutexGuard<'_, Phase> {
        self.0.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends the request. Only once.
    ///
    /// # Errors
    ///
    /// [`ApiError::IllegalStateRequestAlreadyStarted`] the second time, or
    /// whatever else Cronet refuses.
    pub fn start(&self) -> Result<(), ApiError> {
        let mut phase = self.phase();
        if *phase != Phase::Initialized {
            return Err(ApiError::IllegalStateRequestAlreadyStarted);
        }
        // Cronet's reference, taken before any callback can run, and
        // released by the final callback.
        let reference = Arc::into_raw(Arc::clone(&self.0));
        // SAFETY: the request is live and initialized.
        let result = ApiError::check(unsafe { sys::Cronet_UrlRequest_Start(self.as_ptr()) });
        match result {
            Ok(()) => *phase = Phase::Started,
            // SAFETY: no callback will come, so the reference is ours to drop.
            Err(_) => drop(unsafe { Arc::from_raw(reference) }),
        }
        result
    }

    /// Follows the redirect just reported. Once per
    /// [`on_redirect_received`](UrlRequestCallback::on_redirect_received).
    ///
    /// # Errors
    ///
    /// [`ApiError::IllegalStateUnexpectedRedirect`] without a pending redirect.
    pub fn follow_redirect(&self) -> Result<(), ApiError> {
        // SAFETY: the request is live.
        ApiError::check(unsafe { sys::Cronet_UrlRequest_FollowRedirect(self.as_ptr()) })
    }

    /// Reads part of the body into `buffer`, which Cronet holds until
    /// [`on_read_completed`](UrlRequestCallback::on_read_completed) returns
    /// it. Once per `on_response_started` or `on_read_completed`.
    ///
    /// # Errors
    ///
    /// [`ApiError::IllegalStateUnexpectedRead`] at the wrong time; the buffer
    /// is dropped.
    pub fn read(&self, buffer: Buffer) -> Result<(), ApiError> {
        let raw = buffer.into_raw();
        // SAFETY: the request is live; on success Cronet owns the buffer.
        let result = ApiError::check(unsafe { sys::Cronet_UrlRequest_Read(self.as_ptr(), raw) });
        if result.is_err() {
            // SAFETY: Cronet takes the buffer only when the read is accepted.
            drop(unsafe { Buffer::from_raw(raw) });
        }
        result
    }

    /// Cancels the request: [`on_canceled`](UrlRequestCallback::on_canceled)
    /// follows, unless it already ended or never started. With a
    /// single-threaded executor and a call from its thread, no other callback
    /// comes first; otherwise one at most may.
    pub fn cancel(&self) {
        // SAFETY: the request is live.
        unsafe { sys::Cronet_UrlRequest_Cancel(self.as_ptr()) }
    }

    /// Whether the request started and has ended.
    pub fn is_done(&self) -> bool {
        // SAFETY: the request is live.
        unsafe { sys::Cronet_UrlRequest_IsDone(self.as_ptr()) }
    }

    /// Asks what the request is doing; `on_status` gets the answer on the
    /// request's executor.
    pub fn status(&self, on_status: impl FnOnce(RequestStatus) + Send + 'static) {
        // SAFETY: `on_status_trampoline` matches `Cronet_UrlRequestStatusListener_OnStatusFunc`.
        let listener = unsafe { sys::Cronet_UrlRequestStatusListener_CreateWith(Some(on_status_trampoline)) };
        let on_status: Box<OnStatus> = Box::new(Some(Box::new(on_status)));
        // SAFETY: the listener frees itself and its context once called.
        unsafe {
            sys::Cronet_UrlRequestStatusListener_SetClientContext(listener, Box::into_raw(on_status).cast());
            sys::Cronet_UrlRequest_GetStatus(self.as_ptr(), listener);
        }
    }

    fn as_ptr(&self) -> sys::Cronet_UrlRequestPtr {
        self.0.raw.as_ptr()
    }
}

impl fmt::Debug for UrlRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UrlRequest")
            .field("phase", &*self.phase())
            .finish_non_exhaustive()
    }
}

type OnStatus = Option<Box<dyn FnOnce(RequestStatus) + Send>>;

unsafe extern "C" fn on_status_trampoline(
    listener: sys::Cronet_UrlRequestStatusListenerPtr,
    status: sys::Cronet_UrlRequestStatusListener_Status,
) {
    // SAFETY: the context is the `OnStatus` boxed by `status`; Cronet reports
    // once and then forgets the listener, so both are freed here.
    unsafe {
        let on_status =
            Box::from_raw(sys::Cronet_UrlRequestStatusListener_GetClientContext(listener).cast::<OnStatus>());
        sys::Cronet_UrlRequestStatusListener_Destroy(listener);
        if let Some(on_status) = *on_status {
            on_status(RequestStatus::from_c(status));
        }
    }
}

/// The request a callback is for, borrowed from Cronet's reference.
///
/// # Safety
///
/// `callback` belongs to a started request whose final callback has not
/// returned.
unsafe fn request(callback: sys::Cronet_UrlRequestCallbackPtr) -> ManuallyDrop<UrlRequest> {
    // SAFETY: the context is the request's `Inner`, kept alive by Cronet's
    // reference; `ManuallyDrop` leaves that reference alone.
    unsafe {
        let inner = sys::Cronet_UrlRequestCallback_GetClientContext(callback).cast::<Inner>();
        ManuallyDrop::new(UrlRequest(Arc::from_raw(inner)))
    }
}

impl UrlRequest {
    fn callback(&self) -> MutexGuard<'_, Box<dyn UrlRequestCallback>> {
        self.0.callback.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

unsafe extern "C" fn on_redirect_received(
    callback: sys::Cronet_UrlRequestCallbackPtr,
    _: sys::Cronet_UrlRequestPtr,
    info: sys::Cronet_UrlResponseInfoPtr,
    new_location_url: sys::Cronet_String,
) {
    // SAFETY: not the final callback; the arguments are live for the call.
    let (request, info, url) = unsafe {
        (
            request(callback),
            UrlResponseInfoRef::from_ptr(info),
            string(new_location_url),
        )
    };
    request.callback().on_redirect_received(&request, info, &url);
}

unsafe extern "C" fn on_response_started(
    callback: sys::Cronet_UrlRequestCallbackPtr,
    _: sys::Cronet_UrlRequestPtr,
    info: sys::Cronet_UrlResponseInfoPtr,
) {
    // SAFETY: not the final callback; the arguments are live for the call.
    let (request, info) = unsafe { (request(callback), UrlResponseInfoRef::from_ptr(info)) };
    request.callback().on_response_started(&request, info);
}

unsafe extern "C" fn on_read_completed(
    callback: sys::Cronet_UrlRequestCallbackPtr,
    _: sys::Cronet_UrlRequestPtr,
    info: sys::Cronet_UrlResponseInfoPtr,
    buffer: sys::Cronet_BufferPtr,
    bytes_read: u64,
) {
    // SAFETY: not the final callback; the arguments are live for the call,
    // and the buffer is handed back to the app.
    let (request, info, buffer) = unsafe {
        (
            request(callback),
            UrlResponseInfoRef::from_ptr(info),
            Buffer::from_raw(buffer),
        )
    };
    request.callback().on_read_completed(&request, info, buffer, bytes_read);
}

unsafe extern "C" fn on_succeeded(
    callback: sys::Cronet_UrlRequestCallbackPtr,
    _: sys::Cronet_UrlRequestPtr,
    info: sys::Cronet_UrlResponseInfoPtr,
) {
    // SAFETY: the final callback, with live arguments.
    unsafe {
        finish(callback, |callback, request| {
            callback.on_succeeded(request, UrlResponseInfoRef::from_ptr(info))
        })
    }
}

unsafe extern "C" fn on_failed(
    callback: sys::Cronet_UrlRequestCallbackPtr,
    _: sys::Cronet_UrlRequestPtr,
    info: sys::Cronet_UrlResponseInfoPtr,
    error: sys::Cronet_ErrorPtr,
) {
    // SAFETY: the final callback, with live arguments.
    unsafe {
        finish(callback, |callback, request| {
            let info = (!info.is_null()).then(|| UrlResponseInfoRef::from_ptr(info));
            callback.on_failed(request, info, ErrorRef::from_ptr(error));
        })
    }
}

unsafe extern "C" fn on_canceled(
    callback: sys::Cronet_UrlRequestCallbackPtr,
    _: sys::Cronet_UrlRequestPtr,
    info: sys::Cronet_UrlResponseInfoPtr,
) {
    // SAFETY: the final callback, with live arguments.
    unsafe {
        finish(callback, |callback, request| {
            let info = (!info.is_null()).then(|| UrlResponseInfoRef::from_ptr(info));
            callback.on_canceled(request, info);
        })
    }
}

/// Reports the end, then releases Cronet's reference: once nothing else holds
/// the request, it is destroyed, which Cronet allows from its final callback.
///
/// # Safety
///
/// Called once, from the final callback of a started request.
unsafe fn finish(
    callback: sys::Cronet_UrlRequestCallbackPtr,
    report: impl FnOnce(&mut dyn UrlRequestCallback, &UrlRequest),
) {
    // SAFETY: the final callback has not returned.
    let request = unsafe { request(callback) };
    report(&mut **request.callback(), &request);
    *request.phase() = Phase::Done;
    drop(ManuallyDrop::into_inner(request));
}
