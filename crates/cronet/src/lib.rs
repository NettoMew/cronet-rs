//! Chromium's network stack, as built by [naiveproxy]: a Rust port of
//! [cronet-go].
//!
//! - [`Engine`]: the network stack, configured by [`EngineParams`], with
//!   optional custom [TCP/UDP socket or byte-stream dialers](EngineBuilder) and
//!   synthetic [HTTPS/ECH endpoints](Endpoint).
//! - [`UrlRequest`]: an HTTP request driven by a [`UrlRequestCallback`], with
//!   bodies from an [`UploadDataProvider`].
//! - [`BidirectionalStream`]: one HTTP/2 or QUIC stream, read and written at
//!   once, reporting to a [`StreamCallback`].
//! - `BidirectionalConn` (feature `tokio`): a stream as `AsyncRead + AsyncWrite`.
//! - [`tls`]: standalone TLS client connections (`tls::Client` and
//!   `tls::TlsStream`) running on an [`Engine`]'s network thread over any
//!   `Lower` stream (feature `tokio`), sharing [`tls::Config`] with the
//!   engine.
//! - Stream dialers (feature `tokio`): Chromium's TCP connections over
//!   `AsyncRead + AsyncWrite` streams the application provides, each with a
//!   [`Target::connection_id`]; [`Endpoint`]s add ECH configurations and
//!   ALPNs per host; [`Engine::set_quic_send_rate`] drives QUIC Brutal
//!   congestion control per QUIC session.
//! - `http` (feature `http`): requests as `http::Request` and `http::Response`.
//!
//! libcronet is linked, or with the feature `dynamic` loaded at run time; see
//! [`cronet_sys`]. Everything here may be used from any thread. Callbacks run
//! on Cronet's network thread or on an [`Executor`], and must not panic: a
//! panic cannot unwind into Cronet, so it aborts the process.
//!
//! Dialers, `Lower` streams and callbacks that run on the network
//! thread must not block it: it serves every request, stream and connection
//! of the engine. Requests, streams, `tls::Client`s and their connections
//! each keep their [`Engine`] alive; the engine shuts down when the last of
//! them and its clones are gone.
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
pub mod tls;
mod upload;

#[cfg(feature = "tokio")]
mod conn;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "tokio")]
mod lower;

// The README's examples, compiled as doctests.
#[cfg(all(doctest, feature = "tokio", feature = "http"))]
#[doc = include_str!("../../../README.md")]
mod readme {}

pub use cronet_sys as sys;

pub use buffer::{Buffer, BufferRef};
#[cfg(feature = "tokio")]
pub use conn::{BidirectionalConn, ConnOptions, ResponseHeaders};
pub use engine::{DialedUdpSocket, Endpoint, Engine, EngineBuilder, Socket, Target};
pub use error::{ApiError, Error, ErrorCode, ErrorRef};
pub use executor::{Executor, Runnable};
#[cfg(feature = "tokio")]
pub use lower::Lower;
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
