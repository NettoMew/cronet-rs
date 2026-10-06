//! Chromium's network stack, as built by [naiveproxy]: a Rust port of
//! [cronet-go].
//!
//! - [`Engine`]: the network stack, configured by [`EngineParams`], with
//!   optional custom [TCP and UDP dialers](EngineBuilder).
//! - [`UrlRequest`]: an HTTP request driven by a [`UrlRequestCallback`], with
//!   bodies from an [`UploadDataProvider`].
//! - [`BidirectionalStream`]: one HTTP/2 or QUIC stream, read and written at
//!   once, reporting to a [`StreamCallback`].
//! - `BidirectionalConn` (feature `tokio`): a stream as `AsyncRead + AsyncWrite`.
//! - [`http`] (feature `http`): requests as `http::Request` and `http::Response`.
//!
//! libcronet is linked, or with the feature `dynamic` loaded at run time; see
//! [`cronet_sys`]. Everything here may be used from any thread. Callbacks run
//! on Cronet's network thread or on an [`Executor`], and must not panic: a
//! panic cannot unwind into Cronet, so it aborts the process.
//!
//! [naiveproxy]: https://github.com/klzgrad/naiveproxy
//! [cronet-go]: https://github.com/SagerNet/cronet-go

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

mod buffer;
mod engine;
mod error;
mod executor;
mod ffi;
mod metrics;
mod net_error;
mod params;
mod request;
mod response;
mod stream;
mod upload;

#[cfg(feature = "tokio")]
mod conn;
#[cfg(feature = "http")]
pub mod http;

pub use cronet_sys as sys;

pub use buffer::{Buffer, BufferRef};
#[cfg(feature = "tokio")]
pub use conn::{BidirectionalConn, ConnOptions, ResponseHeaders};
pub use engine::{DialedUdpSocket, Engine, EngineBuilder, Socket};
pub use error::{ApiError, Error, ErrorCode, ErrorRef};
pub use executor::{Executor, Runnable};
pub use metrics::{
    DateTime, DateTimeRef, FinishedReason, Metrics, MetricsRef, RequestFinishedInfo, RequestFinishedInfoRef,
    RequestFinishedListener,
};
pub use net_error::NetError;
pub use params::{
    EngineParams, EngineParamsRef, HttpCacheMode, PublicKeyPins, PublicKeyPinsRef, QuicHint, QuicHintRef,
};
pub use request::{
    Idempotency, RequestPriority, RequestStatus, UrlRequest, UrlRequestCallback, UrlRequestParams, UrlRequestParamsRef,
};
pub use response::{HttpHeader, HttpHeaderRef, UrlResponseInfo, UrlResponseInfoRef};
pub use stream::{BidirectionalStream, Headers, Stream, StreamCallback, StreamError, StreamPriority};
pub use upload::{UploadDataProvider, UploadRead, UploadRewind};

/// Opens libcronet from `path`, unless it is already open; see
/// [`cronet_sys::load`].
///
/// # Errors
///
/// When the library cannot be opened, or a symbol is missing.
#[cfg(feature = "dynamic")]
pub fn load_library(path: impl Into<std::path::PathBuf>) -> Result<(), cronet_sys::LoadError> {
    cronet_sys::load(path)
}
