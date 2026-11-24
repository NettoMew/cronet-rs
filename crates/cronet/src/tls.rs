//! Chromium's TLS client stack (`net::SSLClientSocket`) driven on an
//! [`Engine`]'s network thread over an application-supplied byte stream, plus
//! the unified [`Config`] shared with [`EngineBuilder::tls_config`](crate::EngineBuilder::tls_config).

use std::{
    borrow::Borrow,
    ffi::{CStr, CString, c_char},
    fmt, io,
    ptr::{self, NonNull},
    sync::Arc,
};

use cronet_sys as sys;

use crate::Engine;

/// Unified TLS verification, client-authentication, ALPN, and ECH settings.
///
/// Used both to configure an [`Engine`](crate::EngineBuilder::tls_config) and
/// to create a standalone [`Client`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// Skips server certificate verification when no pins are set.
    pub insecure: bool,
    /// Exclusive PEM root certificates: when set, only these roots are trusted
    /// (never the platform store or Chrome's built-in root store).
    pub root_certificates_pem: Option<String>,
    /// Verifies the server certificate against this name while still sending
    /// the connection's target host as the TLS SNI.
    pub verify_name: Option<String>,
    /// SHA-256 fingerprints of pinned leaf or intermediate certificates.
    pub cert_pins_sha256: Vec<[u8; 32]>,
    /// SHA-256 digests of pinned leaf SubjectPublicKeyInfo DER values.
    pub spki_pins_sha256: Vec<[u8; 32]>,
    /// PEM client certificate chain and private key (PEM or PKCS#8 DER)
    /// offered when a server requests client authentication.
    pub client_identity: Option<(Vec<u8>, Vec<u8>)>,
    /// ALPN protocol names to offer; empty offers Chrome's default
    /// (`["h2", "http/1.1"]`).
    pub alpn: Vec<String>,
    /// Default wire-encoded TLS `ECHConfigList` (`0xfe0d`) for connections
    /// made by a [`Client`] unless overridden per connection.
    pub ech: Vec<u8>,
    /// Rejects handshakes immediately with [`NetError::ECH_NOT_NEGOTIATED`](crate::NetError::ECH_NOT_NEGOTIATED)
    /// when ECH is not accepted, never retrying without ECH or accepting
    /// server `retry_configs`.
    pub strict_ech: bool,
    /// Offset in milliseconds added to the local clock during certificate
    /// validity verification.
    pub time_offset_ms: i64,
}

/// Keeps the C strings and byte arrays backing a `Cronet_TlsConfig` alive for
/// the duration of an FFI call.
pub(crate) struct RawConfig<'a> {
    roots: Option<CString>,
    verify_name: Option<CString>,
    alpn_csv: Option<CString>,
    raw: sys::Cronet_TlsConfig,
    _borrow: &'a Config,
}

impl<'a> RawConfig<'a> {
    pub(crate) fn new(config: &'a Config) -> io::Result<Self> {
        let to_cstring = |value: &str, field: &str| {
            CString::new(value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{field} contains a NUL byte")))
        };
        let roots = config
            .root_certificates_pem
            .as_deref()
            .map(|pem| to_cstring(pem, "root_certificates_pem"))
            .transpose()?;
        let verify_name = config
            .verify_name
            .as_deref()
            .map(|name| to_cstring(name, "verify_name"))
            .transpose()?;
        let alpn_csv = if config.alpn.is_empty() {
            None
        } else {
            Some(to_cstring(&config.alpn.join(","), "alpn")?)
        };
        let (client_cert_pem, client_cert_pem_len, client_key_data, client_key_data_len) = match &config.client_identity
        {
            Some((cert, key)) => (cert.as_ptr(), cert.len(), key.as_ptr(), key.len()),
            None => (ptr::null(), 0, ptr::null(), 0),
        };
        let raw = sys::Cronet_TlsConfig {
            insecure: config.insecure,
            pem_root_certs: roots.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            verify_name: verify_name.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            cert_pins_sha256: if config.cert_pins_sha256.is_empty() {
                ptr::null()
            } else {
                config.cert_pins_sha256.as_ptr().cast::<u8>()
            },
            cert_pins_count: config.cert_pins_sha256.len(),
            key_pins_sha256: if config.spki_pins_sha256.is_empty() {
                ptr::null()
            } else {
                config.spki_pins_sha256.as_ptr().cast::<u8>()
            },
            key_pins_count: config.spki_pins_sha256.len(),
            client_cert_pem,
            client_cert_pem_len,
            client_key_data,
            client_key_data_len,
            alpns_comma_separated: alpn_csv.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            ech_config_list: if config.ech.is_empty() {
                ptr::null()
            } else {
                config.ech.as_ptr()
            },
            ech_config_list_len: config.ech.len(),
            strict_ech: config.strict_ech,
            time_offset_ms: config.time_offset_ms,
        };
        Ok(Self {
            roots,
            verify_name,
            alpn_csv,
            raw,
            _borrow: config,
        })
    }

    pub(crate) fn as_ptr(&self) -> *const sys::Cronet_TlsConfig {
        let _ = (&self.roots, &self.verify_name, &self.alpn_csv);
        &self.raw
    }
}

pub(crate) fn read_error_buf(buf: &[c_char]) -> String {
    // SAFETY: `buf` is zero-initialized and C++ always NUL-terminates within bounds.
    unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
}

/// A TLS client running on an [`Engine`]'s network thread.
///
/// Cloning is cheap; every [`TlsStream`] keeps its `Client` (and the underlying
/// [`Engine`]) alive until the connection closes on the network thread.
#[derive(Clone)]
pub struct Client(Arc<ClientInner>);

struct ClientInner {
    raw: NonNull<sys::Cronet_TlsClient>,
    _engine: Engine,
}

// SAFETY: `Cronet_TlsClient` operations dispatch onto the engine's network thread.
unsafe impl Send for ClientInner {}
// SAFETY: as above.
unsafe impl Sync for ClientInner {}

impl Drop for ClientInner {
    fn drop(&mut self) {
        // SAFETY: every `TlsStream` holds a clone of `Client`, so no live
        // `Cronet_TlsConn` references `self.raw` once `ClientInner` drops.
        unsafe { sys::Cronet_TlsClient_Destroy(self.raw.as_ptr()) };
    }
}

impl Client {
    /// Builds a TLS client on `engine` using `config`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if root certificates, client
    /// credentials, or strings in `config` are invalid.
    pub fn new(engine: &Engine, config: impl Borrow<Config>) -> io::Result<Self> {
        let raw_cfg = RawConfig::new(config.borrow())?;
        let mut err_buf = [0 as c_char; 256];
        // SAFETY: `engine` is started and live; `raw_cfg` outlives the call;
        // `err_buf` is writable for `err_buf.len()` bytes.
        let ptr = unsafe {
            sys::Cronet_TlsClient_Create(engine.as_ptr(), raw_cfg.as_ptr(), err_buf.as_mut_ptr(), err_buf.len())
        };
        let Some(raw) = NonNull::new(ptr) else {
            let msg = read_error_buf(&err_buf);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                if msg.is_empty() {
                    "failed to create Cronet TLS client".to_owned()
                } else {
                    msg
                },
            ));
        };
        Ok(Self(Arc::new(ClientInner {
            raw,
            _engine: engine.clone(),
        })))
    }

    /// Updates the clock offset (in milliseconds) used when checking
    /// certificate validity for subsequent handshakes.
    pub fn set_time_offset(&self, offset_ms: i64) {
        // SAFETY: `self.0.raw` is live.
        unsafe { sys::Cronet_TlsClient_SetTimeOffset(self.0.raw.as_ptr(), offset_ms) };
    }

    /// Performs a TLS handshake over `lower` to `host` (either `"example.com"`
    /// for port 443 or `"example.com:8443"`), using [`Config::ech`] when set.
    #[cfg(feature = "tokio")]
    pub async fn connect(&self, host: &str, lower: impl crate::Lower) -> io::Result<TlsStream> {
        let (hostname, port) = split_host_port(host);
        self.connect_with(hostname, port, None, lower).await
    }

    /// Performs a TLS handshake over `lower` to `host:port`, overriding
    /// [`Config::ech`] when `ech` is `Some`.
    #[cfg(feature = "tokio")]
    pub async fn connect_with(
        &self,
        host: &str,
        port: u16,
        ech: Option<&[u8]>,
        lower: impl crate::Lower,
    ) -> io::Result<TlsStream> {
        tokio_tls::connect(self.clone(), host, port, ech, Box::new(lower)).await
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("tls::Client").field(&self.0.raw).finish()
    }
}

#[cfg(feature = "tokio")]
fn split_host_port(input: &str) -> (&str, u16) {
    if let Some(rest) = input.strip_prefix('[')
        && let Some((ipv6, tail)) = rest.split_once(']')
    {
        if let Some(port) = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()) {
            return (ipv6, port);
        }
        return (ipv6, 443);
    }
    if let Some((host, port_str)) = input.rsplit_once(':')
        && !host.contains(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        return (host, port);
    }
    (input, 443)
}

#[cfg(feature = "tokio")]
pub use tokio_tls::{HandshakeError, TlsStream};

#[cfg(feature = "tokio")]
mod tokio_tls {
    use std::{
        error,
        ffi::{CString, c_char, c_int, c_void},
        fmt, future, io,
        pin::Pin,
        ptr::{self, NonNull},
        slice,
        sync::{Arc, Mutex, MutexGuard, PoisonError},
        task::{Context, Poll, Waker},
    };

    use bytes::{Buf, BytesMut};
    use cronet_sys as sys;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::Client;
    use crate::{Lower, NetError, engine::NetworkThread, ffi::string, lower::into_raw_stream};

    const MAX_WRITE: usize = 64 * 1024;
    const MIN_READ: usize = 16 * 1024;

    /// Why a [`Client::connect`] handshake failed, carrying any server-supplied
    /// `ech_retry_configs` when [`Config::strict_ech`](super::Config::strict_ech)
    /// is `false`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HandshakeError {
        /// Chromium's underlying network/TLS error code.
        pub error: NetError,
        /// Wire-encoded `ECHConfigList` returned by the server on
        /// [`NetError::ECH_NOT_NEGOTIATED`] when strict ECH is off.
        pub ech_retry_configs: Vec<u8>,
    }

    impl HandshakeError {
        /// Extracts a `HandshakeError` wrapped inside `error`, if present.
        pub fn from_io_error(error: &io::Error) -> Option<&Self> {
            error.get_ref()?.downcast_ref::<Self>()
        }
    }

    impl fmt::Display for HandshakeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            Display::fmt(&self.error, f)
        }
    }

    use fmt::Display;

    impl error::Error for HandshakeError {
        fn source(&self) -> Option<&(dyn error::Error + 'static)> {
            Some(&self.error)
        }
    }

    /// An established TLS connection over a [`Lower`] stream, implementing
    /// `tokio::io::AsyncRead + AsyncWrite`.
    pub struct TlsStream {
        raw: NonNull<sys::Cronet_TlsConn>,
        shared: Arc<Shared>,
        alpn: Option<String>,
        ech_accepted: bool,
    }

    // SAFETY: all `Cronet_TlsConn_*` operations post onto the engine's network
    // thread, and `Shared` synchronizes state behind a `Mutex`.
    unsafe impl Send for TlsStream {}
    // SAFETY: as above.
    unsafe impl Sync for TlsStream {}

    struct Shared {
        state: Mutex<State>,
        _client: Client,
    }

    #[derive(Default)]
    struct State {
        handshake: Option<Result<(String, bool), HandshakeError>>,
        received: BytesMut,
        reading: bool,
        eof: bool,
        read_error: Option<NetError>,
        writing: bool,
        write_result: Option<Result<usize, NetError>>,
        shutdown: bool,
        closed: bool,
        handshake_waker: Option<Waker>,
        read_waker: Option<Waker>,
        write_waker: Option<Waker>,
    }

    impl Shared {
        fn state(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }

    static CALLBACKS: sys::Cronet_TlsConnCallbacks = sys::Cronet_TlsConnCallbacks {
        on_handshake: Some(on_handshake),
        on_read_completed: Some(on_read_completed),
        on_write_completed: Some(on_write_completed),
        on_closed: Some(on_closed),
    };

    pub(super) async fn connect(
        client: Client,
        host: &str,
        port: u16,
        ech: Option<&[u8]>,
        lower: Box<dyn Lower>,
    ) -> io::Result<TlsStream> {
        let host_c =
            CString::new(host).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "host contains a NUL byte"))?;
        let runtime = tokio::runtime::Handle::try_current().ok();
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            _client: client.clone(),
        });

        // Cronet's reference, released in `on_closed`.
        let cronet_ref = Arc::into_raw(shared.clone());
        let (ech_ptr, ech_len) = match ech {
            Some(bytes) if !bytes.is_empty() => (bytes.as_ptr(), bytes.len()),
            _ => (ptr::null(), 0),
        };
        let mut lower_handle: *mut sys::Cronet_LowerStreamHandle = ptr::null_mut();
        // SAFETY: `client` is live; `host_c` and `ech` live for the call;
        // `cronet_ref` stays valid until `on_closed`.
        let conn_ptr = unsafe {
            sys::Cronet_TlsConn_Create(
                client.0.raw.as_ptr(),
                host_c.as_ptr(),
                port,
                ech_ptr,
                ech_len,
                &CALLBACKS,
                cronet_ref.cast_mut().cast::<c_void>(),
                &mut lower_handle,
            )
        };
        let Some(raw) = NonNull::new(conn_ptr) else {
            // SAFETY: `Cronet_TlsConn_Create` failed, so `on_closed` will never run.
            unsafe { drop(Arc::from_raw(cronet_ref)) };
            if !lower_handle.is_null() {
                // SAFETY: freeing the unused handle.
                unsafe { sys::Cronet_LowerStreamHandle_Destroy(lower_handle) };
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cronet_TlsConn_Create returned null",
            ));
        };

        // SAFETY: `lower_handle` was created specifically for this stream.
        let raw_lower = unsafe { into_raw_stream(lower, lower_handle, runtime) };
        // SAFETY: `raw` is live, and `Cronet_TlsConn_Start` copies `raw_lower`
        // and takes ownership of closing it.
        unsafe { sys::Cronet_TlsConn_Start(raw.as_ptr(), &raw_lower) };

        let guard = ConnDropGuard {
            raw: Some(raw),
            shared: shared.clone(),
        };

        let outcome = future::poll_fn(|cx| {
            let mut state = shared.state();
            if let Some(result) = state.handshake.take() {
                return Poll::Ready(result);
            }
            state.handshake_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await;

        match outcome {
            Ok((alpn, ech_accepted)) => {
                let mut guard = guard;
                let raw = guard.raw.take().expect("connection handle present");
                Ok(TlsStream {
                    raw,
                    shared,
                    alpn: (!alpn.is_empty()).then_some(alpn),
                    ech_accepted,
                })
            }
            Err(handshake_err) => Err(io::Error::new(handshake_err.error.io_kind(), handshake_err)),
        }
    }

    /// Destroys an in-flight handshake connection if the caller cancels/drops
    /// the `connect` future before completion, or when the handshake fails.
    struct ConnDropGuard {
        raw: Option<NonNull<sys::Cronet_TlsConn>>,
        shared: Arc<Shared>,
    }

    impl Drop for ConnDropGuard {
        fn drop(&mut self) {
            if let Some(raw) = self.raw.take() {
                self.shared.state().closed = true;
                // SAFETY: `raw` was created once and has not been destroyed yet.
                unsafe { sys::Cronet_TlsConn_Destroy(raw.as_ptr()) };
            }
        }
    }

    impl TlsStream {
        /// The ALPN protocol negotiated during the handshake, if any.
        pub fn alpn(&self) -> Option<&str> {
            self.alpn.as_deref()
        }

        /// Whether Encrypted ClientHello (ECH) was accepted by the server.
        pub fn ech_accepted(&self) -> bool {
            self.ech_accepted
        }
    }

    impl Drop for TlsStream {
        fn drop(&mut self) {
            self.shared.state().closed = true;
            // SAFETY: `self.raw` is owned uniquely by `TlsStream`; `on_closed`
            // releases Cronet's `Arc<Shared>` once destruction finishes on the
            // network thread.
            unsafe { sys::Cronet_TlsConn_Destroy(self.raw.as_ptr()) };
        }
    }

    impl fmt::Debug for TlsStream {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TlsStream")
                .field("alpn", &self.alpn)
                .field("ech_accepted", &self.ech_accepted)
                .finish_non_exhaustive()
        }
    }

    impl AsyncRead for TlsStream {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let this = self.get_mut();
            let mut state = this.shared.state();
            if !state.received.is_empty() {
                let n = state.received.len().min(buf.remaining());
                buf.put_slice(&state.received[..n]);
                state.received.advance(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(error) = state.read_error.take() {
                return Poll::Ready(Err(error.into()));
            }
            if state.eof {
                return Poll::Ready(Ok(()));
            }
            if state.closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "TLS connection closed",
                )));
            }
            if !state.reading {
                let ask = buf.remaining().max(MIN_READ);
                state.reading = true;
                state.read_waker = Some(cx.waker().clone());
                drop(state);
                // SAFETY: `this.raw` is live until `TlsStream::drop`.
                unsafe { sys::Cronet_TlsConn_Read(this.raw.as_ptr(), ask) };
                return Poll::Pending;
            }
            state.read_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    impl AsyncWrite for TlsStream {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let mut state = this.shared.state();
            if state.closed || state.shutdown {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if let Some(done) = state.write_result.take() {
                return Poll::Ready(done.map_err(io::Error::from));
            }
            if data.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if state.writing {
                state.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let n = data.len().min(MAX_WRITE);
            state.writing = true;
            state.write_waker = Some(cx.waker().clone());
            drop(state);
            // SAFETY: `this.raw` is live; `Cronet_TlsConn_Write` copies the
            // `n` bytes synchronously before posting to the network thread.
            unsafe { sys::Cronet_TlsConn_Write(this.raw.as_ptr(), data.as_ptr(), n) };
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut state = self.shared.state();
            if let Some(Err(error)) = state.write_result.take() {
                return Poll::Ready(Err(error.into()));
            }
            if state.writing {
                state.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.as_mut().poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            self.shared.state().shutdown = true;
            Poll::Ready(Ok(()))
        }
    }

    /// # Safety
    ///
    /// `context` is the `Arc<Shared>` pointer passed to `Cronet_TlsConn_Create`,
    /// alive until `on_closed` finishes.
    unsafe fn shared<'a>(context: *mut c_void) -> &'a Shared {
        // SAFETY: forwarded to caller.
        unsafe { &*context.cast::<Shared>() }
    }

    unsafe extern "C" fn on_handshake(
        context: *mut c_void,
        net_error: c_int,
        negotiated_alpn: *const c_char,
        ech_accepted: bool,
        ech_retry_configs: *const u8,
        ech_retry_configs_len: usize,
    ) {
        let _network = NetworkThread::enter();
        // SAFETY: called before `on_closed`.
        let shared = unsafe { shared(context) };
        let result = if net_error == 0 {
            // SAFETY: `negotiated_alpn` is valid for the duration of the callback.
            let alpn = unsafe { string(negotiated_alpn) }.into_owned();
            Ok((alpn, ech_accepted))
        } else {
            let retry = if !ech_retry_configs.is_null() && ech_retry_configs_len > 0 {
                // SAFETY: C++ passes `ech_retry_configs_len` valid bytes.
                unsafe { slice::from_raw_parts(ech_retry_configs, ech_retry_configs_len) }.to_vec()
            } else {
                Vec::new()
            };
            Err(HandshakeError {
                error: NetError::from_code(net_error),
                ech_retry_configs: retry,
            })
        };
        let waker = {
            let mut state = shared.state();
            state.handshake = Some(result);
            state.handshake_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    unsafe extern "C" fn on_read_completed(context: *mut c_void, data: *const u8, bytes_read_or_error: c_int) {
        let _network = NetworkThread::enter();
        // SAFETY: called before `on_closed`.
        let shared = unsafe { shared(context) };
        let waker = {
            let mut state = shared.state();
            state.reading = false;
            match bytes_read_or_error.cmp(&0) {
                std::cmp::Ordering::Greater => {
                    let len = bytes_read_or_error as usize;
                    // SAFETY: `data` points to `len` valid bytes for this callback.
                    let bytes = unsafe { slice::from_raw_parts(data, len) };
                    state.received.extend_from_slice(bytes);
                }
                std::cmp::Ordering::Equal => {
                    state.eof = true;
                }
                std::cmp::Ordering::Less => {
                    state.read_error = Some(NetError::from_code(bytes_read_or_error));
                }
            }
            state.read_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    unsafe extern "C" fn on_write_completed(context: *mut c_void, bytes_written_or_error: c_int) {
        let _network = NetworkThread::enter();
        // SAFETY: called before `on_closed`.
        let shared = unsafe { shared(context) };
        let waker = {
            let mut state = shared.state();
            state.writing = false;
            state.write_result = Some(if bytes_written_or_error >= 0 {
                Ok(bytes_written_or_error as usize)
            } else {
                Err(NetError::from_code(bytes_written_or_error))
            });
            state.write_waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    unsafe extern "C" fn on_closed(context: *mut c_void) {
        let _network = NetworkThread::enter();
        // SAFETY: final callback for this `Cronet_TlsConn`; reclaims Cronet's
        // strong reference to `Shared`.
        let shared = unsafe { Arc::from_raw(context.cast::<Shared>()) };
        let (hw, rw, ww) = {
            let mut state = shared.state();
            state.closed = true;
            state.reading = false;
            state.writing = false;
            (
                state.handshake_waker.take(),
                state.read_waker.take(),
                state.write_waker.take(),
            )
        };
        if let Some(w) = hw {
            w.wake();
        }
        if let Some(w) = rw {
            w.wake();
        }
        if let Some(w) = ww {
            w.wake();
        }
    }
}
