//! Timings of a request, and the listener that receives them when it ends.

use std::{
    fmt,
    ptr::NonNull,
    sync::Arc,
    time::{Duration, SystemTime},
};

use cronet_sys as sys;

use crate::{
    ErrorRef, UrlResponseInfoRef,
    ffi::{c_enum, properties, value_type},
};

value_type! {
    /// A point in time, with millisecond precision.
    pub struct DateTime / DateTimeRef (sys::Cronet_DateTime) {
        create: sys::Cronet_DateTime_Create,
        destroy: sys::Cronet_DateTime_Destroy,
    }
}

impl DateTimeRef {
    /// The time, as the system clock read it.
    pub fn value(&self) -> SystemTime {
        // SAFETY: the object is live.
        let millis = unsafe { sys::Cronet_DateTime_value_get(self.as_ptr()) };
        let offset = Duration::from_millis(millis.unsigned_abs());
        if millis >= 0 {
            SystemTime::UNIX_EPOCH + offset
        } else {
            SystemTime::UNIX_EPOCH - offset
        }
    }

    /// Sets [`value`](Self::value), truncated to milliseconds.
    pub fn set_value(&mut self, value: SystemTime) -> &mut Self {
        let millis = match value.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
            Err(before) => i64::try_from(before.duration().as_millis()).map_or(i64::MIN, |millis| -millis),
        };
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_DateTime_value_set(self.as_ptr(), millis) };
        self
    }
}

impl From<SystemTime> for DateTime {
    fn from(value: SystemTime) -> Self {
        let mut date_time = Self::new();
        date_time.set_value(value);
        date_time
    }
}

impl fmt::Debug for DateTimeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value().fmt(f)
    }
}

impl fmt::Debug for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

value_type! {
    /// When each phase of a request happened, and how many bytes it moved.
    ///
    /// A phase that did not happen has no time: DNS, connection and TLS times
    /// are absent when the connection was reused, for instance.
    pub struct Metrics / MetricsRef (sys::Cronet_Metrics) {
        create: sys::Cronet_Metrics_Create,
        destroy: sys::Cronet_Metrics_Destroy,
    }
}

macro_rules! timestamps {
    ($( $(#[$meta:meta])* $name:ident, $set_name:ident: $get:path, $set:path; )*) => {
        impl MetricsRef {
            $(
                $(#[$meta])*
                pub fn $name(&self) -> Option<&DateTimeRef> {
                    // SAFETY: the object is live, and so is the time it owns while `self` is borrowed.
                    let raw = unsafe { $get(self.as_ptr()) };
                    // SAFETY: as above.
                    (!raw.is_null()).then(|| unsafe { DateTimeRef::from_ptr(raw) })
                }

                #[doc = concat!("Sets [`", stringify!($name), "`](Self::", stringify!($name), "), or clears it.")]
                pub fn $set_name(&mut self, value: Option<&DateTimeRef>) -> &mut Self {
                    let value = value.map_or(std::ptr::null_mut(), DateTimeRef::as_ptr);
                    // SAFETY: both objects are live; Cronet copies the time.
                    unsafe { $set(self.as_ptr(), value) };
                    self
                }
            )*
        }
    };
}

timestamps! {
    /// When the request started: when [`UrlRequest::start`](crate::UrlRequest::start) was called.
    request_start, set_request_start: sys::Cronet_Metrics_request_start_get, sys::Cronet_Metrics_request_start_set;
    /// When the DNS lookup started, from a server or the local cache alike.
    dns_start, set_dns_start: sys::Cronet_Metrics_dns_start_get, sys::Cronet_Metrics_dns_start_set;
    /// When the DNS lookup finished.
    dns_end, set_dns_end: sys::Cronet_Metrics_dns_end_get, sys::Cronet_Metrics_dns_end_set;
    /// When connecting started, typically when DNS resolution finished.
    connect_start, set_connect_start: sys::Cronet_Metrics_connect_start_get, sys::Cronet_Metrics_connect_start_set;
    /// When the connection was established, TLS handshake included. For QUIC
    /// 0-RTT, when the handshake was confirmed, which may be after
    /// [`sending_start`](Self::sending_start).
    connect_end, set_connect_end: sys::Cronet_Metrics_connect_end_get, sys::Cronet_Metrics_connect_end_set;
    /// When the TLS handshake started; for QUIC, the same as [`connect_start`](Self::connect_start).
    ssl_start, set_ssl_start: sys::Cronet_Metrics_ssl_start_get, sys::Cronet_Metrics_ssl_start_set;
    /// When the TLS handshake finished; for QUIC, the same as [`connect_end`](Self::connect_end).
    ssl_end, set_ssl_end: sys::Cronet_Metrics_ssl_end_get, sys::Cronet_Metrics_ssl_end_set;
    /// When sending the request headers started.
    sending_start, set_sending_start: sys::Cronet_Metrics_sending_start_get, sys::Cronet_Metrics_sending_start_set;
    /// When sending the request body finished.
    sending_end, set_sending_end: sys::Cronet_Metrics_sending_end_get, sys::Cronet_Metrics_sending_end_set;
    /// When the first byte of an HTTP/2 server push arrived.
    push_start, set_push_start: sys::Cronet_Metrics_push_start_get, sys::Cronet_Metrics_push_start_set;
    /// When the last byte of an HTTP/2 server push arrived.
    push_end, set_push_end: sys::Cronet_Metrics_push_end_get, sys::Cronet_Metrics_push_end_set;
    /// When the end of the response headers arrived.
    response_start, set_response_start: sys::Cronet_Metrics_response_start_get, sys::Cronet_Metrics_response_start_set;
    /// When the request finished.
    request_end, set_request_end: sys::Cronet_Metrics_request_end_get, sys::Cronet_Metrics_request_end_set;
}

properties!(MetricsRef {
    /// Whether the socket was reused from an earlier request. With HTTP/2 or
    /// QUIC, every stream after the first on a connection reuses it.
    bool as socket_reused, set_socket_reused: sys::Cronet_Metrics_socket_reused_get, sys::Cronet_Metrics_socket_reused_set;
    /// Bytes sent over the network transport, or -1 if not collected.
    i64 as sent_byte_count, set_sent_byte_count:
        sys::Cronet_Metrics_sent_byte_count_get, sys::Cronet_Metrics_sent_byte_count_set;
    /// Bytes received over the network transport, redirects excluded, or -1
    /// if not collected.
    i64 as received_byte_count, set_received_byte_count:
        sys::Cronet_Metrics_received_byte_count_get, sys::Cronet_Metrics_received_byte_count_set;
});

impl fmt::Debug for MetricsRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metrics")
            .field("request_start", &self.request_start())
            .field("dns_start", &self.dns_start())
            .field("dns_end", &self.dns_end())
            .field("connect_start", &self.connect_start())
            .field("connect_end", &self.connect_end())
            .field("ssl_start", &self.ssl_start())
            .field("ssl_end", &self.ssl_end())
            .field("sending_start", &self.sending_start())
            .field("sending_end", &self.sending_end())
            .field("push_start", &self.push_start())
            .field("push_end", &self.push_end())
            .field("response_start", &self.response_start())
            .field("request_end", &self.request_end())
            .field("socket_reused", &self.socket_reused())
            .field("sent_byte_count", &self.sent_byte_count())
            .field("received_byte_count", &self.received_byte_count())
            .finish()
    }
}

impl fmt::Debug for Metrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

c_enum! {
    /// How a request ended.
    pub enum FinishedReason: sys::Cronet_RequestFinishedInfo_FINISHED_REASON {
        /// It succeeded.
        Succeeded = sys::Cronet_RequestFinishedInfo_FINISHED_REASON_SUCCEEDED,
        /// It failed.
        Failed = sys::Cronet_RequestFinishedInfo_FINISHED_REASON_FAILED,
        /// It was canceled.
        Canceled = sys::Cronet_RequestFinishedInfo_FINISHED_REASON_CANCELED,
    }
    unknown => Failed;
}

value_type! {
    /// What a [`RequestFinishedListener`] learns about a request that ended.
    pub struct RequestFinishedInfo / RequestFinishedInfoRef (sys::Cronet_RequestFinishedInfo) {
        create: sys::Cronet_RequestFinishedInfo_Create,
        destroy: sys::Cronet_RequestFinishedInfo_Destroy,
    }
}

properties!(RequestFinishedInfoRef {
    /// How the request ended.
    FinishedReason as finished_reason, set_finished_reason:
        sys::Cronet_RequestFinishedInfo_finished_reason_get, sys::Cronet_RequestFinishedInfo_finished_reason_set;
});

impl RequestFinishedInfoRef {
    /// The request's timings.
    pub fn metrics(&self) -> Option<&MetricsRef> {
        // SAFETY: the object is live, and so are the metrics it owns while `self` is borrowed.
        let raw = unsafe { sys::Cronet_RequestFinishedInfo_metrics_get(self.as_ptr()) };
        // SAFETY: as above.
        (!raw.is_null()).then(|| unsafe { MetricsRef::from_ptr(raw) })
    }

    /// Sets [`metrics`](Self::metrics), or clears it.
    pub fn set_metrics(&mut self, metrics: Option<&MetricsRef>) -> &mut Self {
        let metrics = metrics.map_or(std::ptr::null_mut(), MetricsRef::as_ptr);
        // SAFETY: both objects are live; Cronet copies the metrics.
        unsafe { sys::Cronet_RequestFinishedInfo_metrics_set(self.as_ptr(), metrics) };
        self
    }

    /// The annotations the request was started with
    /// ([`UrlRequestParamsRef::add_annotation`](crate::UrlRequestParamsRef::add_annotation)),
    /// to tell requests apart.
    pub fn annotations(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        // SAFETY: the object is live.
        let len = unsafe { sys::Cronet_RequestFinishedInfo_annotations_size(self.as_ptr()) };
        // SAFETY: `index` is in bounds; annotations are opaque values.
        (0..len)
            .map(move |index| unsafe { sys::Cronet_RequestFinishedInfo_annotations_at(self.as_ptr(), index) } as usize)
    }

    /// Appends to [`annotations`](Self::annotations).
    pub fn add_annotation(&mut self, annotation: usize) -> &mut Self {
        // SAFETY: the object is live; Cronet never dereferences annotations.
        unsafe { sys::Cronet_RequestFinishedInfo_annotations_add(self.as_ptr(), annotation as sys::Cronet_RawDataPtr) };
        self
    }

    /// Empties [`annotations`](Self::annotations).
    pub fn clear_annotations(&mut self) -> &mut Self {
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_RequestFinishedInfo_annotations_clear(self.as_ptr()) };
        self
    }
}

impl fmt::Debug for RequestFinishedInfoRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestFinishedInfo")
            .field("finished_reason", &self.finished_reason())
            .field("annotations", &self.annotations().collect::<Vec<_>>())
            .field("metrics", &self.metrics())
            .finish()
    }
}

impl fmt::Debug for RequestFinishedInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

/// Called on its [`Executor`](crate::Executor) at the end of each request it
/// listens to, with the request's timings, its response if one arrived, and
/// its error if it failed.
///
/// Register one with an engine
/// ([`Engine::add_request_finished_listener`](crate::Engine::add_request_finished_listener))
/// or with a single request
/// ([`UrlRequestParams::set_request_finished_listener`](crate::UrlRequestParams::set_request_finished_listener)).
/// It runs before the request's final callback, though an asynchronous
/// executor may make it finish after.
///
/// Cloning is cheap; whatever a listener is registered with keeps a clone.
#[derive(Clone)]
pub struct RequestFinishedListener(Arc<ListenerInner>);

type OnFinished = dyn Fn(&RequestFinishedInfoRef, Option<&UrlResponseInfoRef>, Option<&ErrorRef>) + Send + Sync;

struct ListenerInner {
    raw: NonNull<sys::Cronet_RequestFinishedInfoListener>,
    on_finished: Box<OnFinished>,
}

// SAFETY: Cronet calls the listener on its executor's threads; the closure is `Send + Sync`.
unsafe impl Send for ListenerInner {}
// SAFETY: as above.
unsafe impl Sync for ListenerInner {}

impl Drop for ListenerInner {
    fn drop(&mut self) {
        // SAFETY: the last clone is gone, so nothing has the listener registered.
        unsafe { sys::Cronet_RequestFinishedInfoListener_Destroy(self.raw.as_ptr()) }
    }
}

impl RequestFinishedListener {
    /// A listener that calls `on_finished`.
    pub fn new(
        on_finished: impl Fn(&RequestFinishedInfoRef, Option<&UrlResponseInfoRef>, Option<&ErrorRef>)
        + Send
        + Sync
        + 'static,
    ) -> Self {
        // SAFETY: `on_finished_trampoline` matches `Cronet_RequestFinishedInfoListener_OnRequestFinishedFunc`.
        let raw = unsafe { sys::Cronet_RequestFinishedInfoListener_CreateWith(Some(on_finished_trampoline)) };
        let raw = NonNull::new(raw).expect("Cronet_RequestFinishedInfoListener_CreateWith returned null");
        let inner = Arc::new(ListenerInner {
            raw,
            on_finished: Box::new(on_finished),
        });
        // SAFETY: the context outlives the C object, which `ListenerInner` destroys.
        unsafe {
            sys::Cronet_RequestFinishedInfoListener_SetClientContext(
                raw.as_ptr(),
                Arc::as_ptr(&inner).cast_mut().cast(),
            )
        };
        Self(inner)
    }

    pub(crate) fn as_ptr(&self) -> sys::Cronet_RequestFinishedInfoListenerPtr {
        self.0.raw.as_ptr()
    }

    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for RequestFinishedListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RequestFinishedListener").field(&self.0.raw).finish()
    }
}

unsafe extern "C" fn on_finished_trampoline(
    raw: sys::Cronet_RequestFinishedInfoListenerPtr,
    info: sys::Cronet_RequestFinishedInfoPtr,
    response: sys::Cronet_UrlResponseInfoPtr,
    error: sys::Cronet_ErrorPtr,
) {
    // SAFETY: the context is the live `ListenerInner` owning this C object;
    // the other objects are live for the duration of the call.
    unsafe {
        let inner = &*sys::Cronet_RequestFinishedInfoListener_GetClientContext(raw).cast::<ListenerInner>();
        let response = (!response.is_null()).then(|| UrlResponseInfoRef::from_ptr(response));
        let error = (!error.is_null()).then(|| ErrorRef::from_ptr(error));
        (inner.on_finished)(RequestFinishedInfoRef::from_ptr(info), response, error);
    }
}
