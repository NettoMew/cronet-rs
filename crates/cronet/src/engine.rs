//! The engine: Chromium's network stack, started once and shared by every
//! request and stream made with it.

use std::{
    cell::Cell,
    ffi::{CStr, c_char, c_void},
    fmt, io, mem,
    net::{IpAddr, SocketAddr},
    path::Path,
    ptr::{self, NonNull},
    sync::{Arc, Mutex, PoisonError},
    thread,
};

use cronet_sys as sys;

use crate::{
    ApiError, EngineParamsRef, Executor, NetError, RequestFinishedListener,
    ffi::{c_string, string},
};

/// A socket handed to Cronet, which takes ownership of it.
#[cfg(unix)]
pub type Socket = std::os::fd::OwnedFd;
/// A socket handed to Cronet, which takes ownership of it.
#[cfg(windows)]
pub type Socket = std::os::windows::io::OwnedSocket;

#[cfg(unix)]
fn into_raw(socket: Socket) -> isize {
    use std::os::fd::IntoRawFd;
    socket.into_raw_fd() as isize
}

#[cfg(windows)]
fn into_raw(socket: Socket) -> isize {
    use std::os::windows::io::IntoRawSocket;
    socket.into_raw_socket() as isize
}

/// A UDP socket a [UDP dialer](EngineBuilder::udp_dialer) made for Cronet.
///
/// Cronet does not `connect` it. It may be an `AF_INET`/`AF_INET6` datagram
/// socket (connected or not), an `AF_UNIX` datagram socket on Unix, or on
/// Windows an `AF_UNIX` stream socket carrying each datagram behind a 16-bit
/// big-endian length.
pub struct DialedUdpSocket {
    socket: Socket,
    local_addr: Option<SocketAddr>,
    on_close: Option<Box<dyn FnOnce() + Send>>,
}

impl DialedUdpSocket {
    /// Hands `socket` to Cronet.
    pub fn new(socket: impl Into<Socket>) -> Self {
        Self {
            socket: socket.into(),
            local_addr: None,
            on_close: None,
        }
    }

    /// The local address Cronet should report for the socket.
    #[must_use]
    pub fn local_addr(mut self, local_addr: SocketAddr) -> Self {
        self.local_addr = Some(local_addr);
        self
    }

    /// Runs `on_close` on the network thread once Cronet releases the socket,
    /// including when it fails to adopt it. It must not block.
    #[must_use]
    pub fn on_close(mut self, on_close: impl FnOnce() + Send + 'static) -> Self {
        self.on_close = Some(Box::new(on_close));
        self
    }
}

impl fmt::Debug for DialedUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DialedUdpSocket")
            .field("socket", &self.socket)
            .field("local_addr", &self.local_addr)
            .field("on_close", &self.on_close.is_some())
            .finish()
    }
}

/// What a stream dialer (`EngineBuilder::stream_dialer` or
/// `EngineBuilder::async_stream_dialer`, feature `tokio`) is asked to
/// connect to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    /// Destination hostname, as in the URL but lowercased, or an IP literal
    /// when the URL names one. Never the synthetic address the engine's
    /// in-memory resolver gave the host (see [`Endpoint`]).
    pub host: String,
    /// Destination TCP port.
    pub port: u16,
    /// Identifier of this transport connection: non-zero, unique within the
    /// process (counting up from 1), with the high bit clear so it never
    /// collides with a QUIC session's `(1 << 63) | n`. Streams carried by the
    /// connection report it from
    /// [`Stream::connection_id`](crate::Stream::connection_id).
    pub connection_id: u64,
}

/// Synthetic DNS and HTTPS/SVCB metadata registered for a host via
/// [`Engine::endpoint`] or [`EngineBuilder::endpoint`].
///
/// Registering an endpoint (or calling [`EngineBuilder::enable_endpoints`],
/// or setting a stream dialer) before [`start`](EngineBuilder::start)
/// installs an in-memory resolver in place of DNS. From then on every
/// hostname resolves in memory to a synthetic, unroutable address: a
/// registered host with its metadata, any other host without. A stream
/// dialer receives the hostname back in [`Target::host`]; the socket
/// [`dialer`](EngineBuilder::dialer), the [`udp_dialer`](EngineBuilder::udp_dialer)
/// and QUIC see only the synthetic address, so endpoints are meant for
/// engines whose TCP connections go through a stream dialer.
///
/// ```no_run
/// # fn example(ech_config_list: Vec<u8>) -> Result<(), cronet::ApiError> {
/// use cronet::{Endpoint, Engine, EngineParams};
///
/// let engine = Engine::builder()
///     .endpoint("service.example.com", Endpoint {
///         ech: ech_config_list.clone(),
///         alpn: vec!["h2".into()],
///         strict: true,
///     })
///     .start(&EngineParams::new())?;
///
/// // Rotate the ECH configuration later, from any thread.
/// engine.endpoint("service.example.com", Endpoint {
///     ech: ech_config_list,
///     alpn: vec!["h2".into()],
///     strict: true,
/// });
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Endpoint {
    /// Wire-encoded TLS `ECHConfigList` (`0xfe0d`), or empty for plain TLS.
    pub ech: Vec<u8>,
    /// ALPN protocol names to advertise (such as `["h2"]` or `["h3", "h2"]`);
    /// empty uses Chrome's default (`["h2", "http/1.1"]`).
    pub alpn: Vec<String>,
    /// When `true`, ECH rejection fails immediately with
    /// [`NetError::ECH_NOT_NEGOTIATED`] without unencrypted fallback or
    /// `retry_configs` retry. [`tls::Config::strict_ech`](crate::tls::Config::strict_ech)
    /// on the engine makes every host strict.
    pub strict: bool,
}

type TcpDialer = dyn Fn(SocketAddr) -> Result<Socket, NetError> + Send + Sync;
type UdpDialer = dyn Fn(SocketAddr) -> Result<DialedUdpSocket, NetError> + Send + Sync;
#[cfg(feature = "tokio")]
type StreamDialer = (
    Box<dyn Fn(Target) -> io::Result<Box<dyn crate::Lower>> + Send + Sync>,
    Option<tokio::runtime::Handle>,
);
type OnClose = Box<dyn FnOnce() + Send>;

/// The dialers an engine calls back into; boxed twice so that the address
/// handed to Cronet stays put.
#[derive(Default)]
struct Dialers {
    tcp: Option<Box<Box<TcpDialer>>>,
    udp: Option<Box<Box<UdpDialer>>>,
    #[cfg(feature = "tokio")]
    stream: Option<Box<StreamDialer>>,
}

/// An engine not started yet: the place for what must be set before
/// [`start`](Self::start).
pub struct EngineBuilder {
    raw: NonNull<sys::Cronet_Engine>,
    dialers: Dialers,
}

// SAFETY: an engine that has not started has no threads of its own, and the
// dialers are `Send + Sync`.
unsafe impl Send for EngineBuilder {}

impl EngineBuilder {
    /// A new engine, not started.
    pub fn new() -> Self {
        // SAFETY: allocation has no preconditions.
        let raw = unsafe { sys::Cronet_Engine_Create() };
        Self {
            raw: NonNull::new(raw).expect("Cronet_Engine_Create returned null"),
            dialers: Dialers::default(),
        }
    }

    /// Makes TCP connections with `dialer` instead of the system's sockets.
    ///
    /// `dialer` runs on the network thread with the address to connect to; it
    /// returns a connected socket, or the [`NetError`] Chromium should see,
    /// such as [`NetError::CONNECTION_REFUSED`].
    #[must_use]
    pub fn dialer(mut self, dialer: impl Fn(SocketAddr) -> Result<Socket, NetError> + Send + Sync + 'static) -> Self {
        let dialer: Box<Box<TcpDialer>> = Box::new(Box::new(dialer));
        let context = ptr::from_ref::<Box<TcpDialer>>(&dialer).cast_mut().cast();
        // SAFETY: the engine is not started; the dialer lives as long as the engine.
        unsafe { sys::Cronet_Engine_SetDialer(self.raw.as_ptr(), Some(dial_tcp), context) };
        self.dialers.tcp = Some(dialer);
        self
    }

    /// Makes UDP sockets with `dialer` instead of the system's.
    #[must_use]
    pub fn udp_dialer(
        mut self,
        dialer: impl Fn(SocketAddr) -> Result<DialedUdpSocket, NetError> + Send + Sync + 'static,
    ) -> Self {
        let dialer: Box<Box<UdpDialer>> = Box::new(Box::new(dialer));
        let context = ptr::from_ref::<Box<UdpDialer>>(&dialer).cast_mut().cast();
        // SAFETY: the engine is not started; the dialer lives as long as the engine.
        unsafe { sys::Cronet_Engine_SetUdpDialer(self.raw.as_ptr(), Some(dial_udp), context, Some(udp_socket_closed)) };
        self.dialers.udp = Some(dialer);
        self
    }

    /// Makes TCP connections over application-provided [`Lower`](crate::Lower)
    /// byte streams instead of OS sockets.
    ///
    /// Takes precedence over [`dialer`](Self::dialer) for TCP while leaving
    /// [`udp_dialer`](Self::udp_dialer) in place for QUIC, and automatically
    /// enables the in-memory endpoint resolver so hostnames never query OS DNS
    /// (see [`Endpoint`] for what that means for QUIC and the socket dialers).
    ///
    /// `dialer` is called on Cronet's network thread, once per connection,
    /// with the [`Target`] to reach. It must return at once: for a connection
    /// that takes time to establish, use
    /// [`async_stream_dialer`](Self::async_stream_dialer), or return a stream
    /// that connects as it is polled. An error fails the connection with the
    /// [`NetError`] [`NetError::from_io_error`] maps it to.
    ///
    /// The returned stream is polled on the network thread too, never
    /// concurrently with itself, so its `poll_*` methods must not block; its
    /// wakers may be called from any thread. Cronet drops it when the
    /// connection closes, after a best-effort `poll_shutdown`.
    ///
    /// The Tokio runtime current when this method is called, if any, is
    /// entered around every dial and poll, so streams that need a reactor
    /// (such as `tokio::net::TcpStream`) work. Call it inside the runtime,
    /// and keep the runtime alive as long as the engine.
    ///
    /// ```no_run
    /// # fn example() -> Result<(), cronet::ApiError> {
    /// use cronet::{Engine, EngineParams, Lower};
    ///
    /// // A duplex pipe per connection; the other end would be served elsewhere.
    /// let engine = Engine::builder()
    ///     .stream_dialer(|target| {
    ///         let (client, _server) = tokio::io::duplex(64 * 1024);
    ///         println!("{}:{} is connection {}", target.host, target.port, target.connection_id);
    ///         Ok(Box::new(client) as Box<dyn Lower>)
    ///     })
    ///     .start(&EngineParams::new())?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "tokio")]
    #[must_use]
    pub fn stream_dialer(
        mut self,
        dialer: impl Fn(Target) -> io::Result<Box<dyn crate::Lower>> + Send + Sync + 'static,
    ) -> Self {
        let runtime = tokio::runtime::Handle::try_current().ok();
        let entry: Box<StreamDialer> = Box::new((Box::new(dialer), runtime));
        let context = ptr::from_ref::<StreamDialer>(&entry).cast_mut().cast();
        // SAFETY: the engine is not started; `entry` lives in `self.dialers.stream`
        // until after the engine shuts down.
        unsafe { sys::Cronet_Engine_SetStreamDialer(self.raw.as_ptr(), Some(dial_stream), context) };
        self.dialers.stream = Some(entry);
        self
    }

    /// Like [`stream_dialer`](Self::stream_dialer), for an asynchronous dial
    /// function: the returned future is polled without blocking Cronet's
    /// network thread.
    ///
    /// `dialer` itself runs on the network thread and should only build the
    /// future. The future is polled on the network thread when Cronet first
    /// reads or writes, with the same runtime entered as for
    /// [`stream_dialer`](Self::stream_dialer); an error from it fails the
    /// connection.
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), cronet::ApiError> {
    /// use cronet::{Engine, EngineParams};
    ///
    /// // Called inside the Tokio runtime that will drive the connections.
    /// let engine = Engine::builder()
    ///     .async_stream_dialer(|target| async move {
    ///         // Every connection goes to one relay; `target` says where it is meant for.
    ///         tokio::net::TcpStream::connect(("relay.example.com", 443)).await
    ///     })
    ///     .start(&EngineParams::new())?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "tokio")]
    #[must_use]
    pub fn async_stream_dialer<F, Fut, S>(self, dialer: F) -> Self
    where
        F: Fn(Target) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = io::Result<S>> + Send + 'static,
        S: crate::Lower,
    {
        self.stream_dialer(move |target| Ok(crate::lower::connecting(dialer(target))))
    }

    /// Registers synthetic DNS and HTTPS/SVCB metadata (`ECHConfigList`, ALPNs,
    /// and strict ECH policy) for `host`, enabling the in-memory host resolver
    /// (see [`Endpoint`]). `host` matches case-insensitively; registering it
    /// again replaces its entry.
    ///
    /// # Panics
    ///
    /// If `host` or an ALPN entry contains a NUL byte.
    #[must_use]
    pub fn endpoint(self, host: &str, endpoint: Endpoint) -> Self {
        set_endpoint_raw(self.raw.as_ptr(), host, &endpoint);
        self
    }

    /// Enables the in-memory endpoint resolver before [`start`](Self::start)
    /// even when endpoints will only be registered dynamically via
    /// [`Engine::endpoint`] afterwards. Every hostname then resolves in memory;
    /// see [`Endpoint`].
    #[must_use]
    pub fn enable_endpoints(self) -> Self {
        // SAFETY: the engine is live.
        unsafe { sys::Cronet_Engine_ClearEndpoints(self.raw.as_ptr()) };
        self
    }

    /// Configures the engine with the unified [`tls::Config`](crate::tls::Config)
    /// (exclusive root certificates, `verify_name`, certificate/SPKI SHA-256
    /// pins, client certificate, strict ECH default, and clock offset).
    ///
    /// The engine ignores [`alpn`](crate::tls::Config::alpn) and
    /// [`ech`](crate::tls::Config::ech), which only a
    /// [`tls::Client`](crate::tls::Client) uses; per-host ALPNs and ECH come
    /// from [`Endpoint`]s. `strict_ech` applies to every host, and `verify_name`
    /// to every server certificate. This replaces
    /// [`trusted_root_certificates`](Self::trusted_root_certificates).
    ///
    /// ```no_run
    /// # fn example(ca_pem: String) -> Result<(), Box<dyn std::error::Error>> {
    /// use cronet::{Engine, EngineParams, tls};
    ///
    /// let engine = Engine::builder()
    ///     .tls_config(&tls::Config {
    ///         root_certificates_pem: Some(ca_pem),
    ///         verify_name: Some("origin.example.com".into()),
    ///         ..tls::Config::default()
    ///     })?
    ///     .start(&EngineParams::new())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if certificates, keys, or strings
    /// in `config` fail validation.
    pub fn tls_config(self, config: &crate::tls::Config) -> io::Result<Self> {
        let raw_cfg = crate::tls::RawConfig::new(config)?;
        let mut err_buf = [0 as c_char; 256];
        // SAFETY: the engine is not started; `raw_cfg` outlives the call;
        // `err_buf` is writable for `err_buf.len()` bytes.
        let ok = unsafe {
            sys::Cronet_Engine_ConfigureTls(self.raw.as_ptr(), raw_cfg.as_ptr(), err_buf.as_mut_ptr(), err_buf.len())
        };
        if !ok {
            let msg = crate::tls::read_error_buf(&err_buf);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                if msg.is_empty() {
                    "failed to configure engine TLS".to_owned()
                } else {
                    msg
                },
            ));
        }
        Ok(self)
    }

    /// Trusts only the certificates in `pem` (one or more) as roots.
    ///
    /// Ignored when [`tls_config`](Self::tls_config) is also used; set
    /// [`root_certificates_pem`](crate::tls::Config::root_certificates_pem)
    /// there instead.
    ///
    /// # Errors
    ///
    /// [`ApiError::IllegalArgument`] if no certificate in `pem` parses.
    ///
    /// # Panics
    ///
    /// If `pem` contains a NUL byte.
    pub fn trusted_root_certificates(self, pem: &str) -> Result<Self, ApiError> {
        let pem = c_string(pem);
        // SAFETY: the string is valid for the call.
        let verifier = unsafe { sys::Cronet_CreateCertVerifierWithRootCerts(pem.as_ptr()) };
        if verifier.is_null() {
            return Err(ApiError::IllegalArgument);
        }
        // SAFETY: the engine is not started, and takes ownership of the verifier.
        unsafe { sys::Cronet_Engine_SetMockCertVerifierForTesting(self.raw.as_ptr(), verifier) };
        Ok(self)
    }

    /// The `User-Agent` the engine would send by default.
    pub fn default_user_agent(&self) -> String {
        // SAFETY: the engine is live; the string is copied before anything changes it.
        unsafe { string(sys::Cronet_Engine_GetDefaultUserAgent(self.raw.as_ptr())) }.into_owned()
    }

    /// Starts the engine with `params`.
    ///
    /// # Errors
    ///
    /// The [`ApiError`] Cronet refused `params` with, when
    /// [`enable_check_result`](EngineParamsRef::enable_check_result) is off;
    /// with it on, Cronet aborts instead.
    pub fn start(self, params: &EngineParamsRef) -> Result<Engine, ApiError> {
        // SAFETY: both objects are live; Cronet copies the parameters.
        ApiError::check(unsafe { sys::Cronet_Engine_StartWithParams(self.raw.as_ptr(), params.as_ptr()) })?;
        let this = mem::ManuallyDrop::new(self);
        // SAFETY: `this` is never dropped, so its fields move out exactly once.
        let dialers = unsafe { ptr::read(&this.dialers) };
        Ok(Engine(Arc::new(Inner {
            raw: this.raw,
            dialers,
            listeners: Mutex::default(),
        })))
    }
}

impl Default for EngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EngineBuilder {
    fn drop(&mut self) {
        // SAFETY: an engine that never started has nothing to shut down.
        unsafe { sys::Cronet_Engine_Destroy(self.raw.as_ptr()) }
    }
}

impl fmt::Debug for EngineBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineBuilder")
            .field("dialer", &self.dialers.tcp.is_some())
            .field("udp_dialer", &self.dialers.udp.is_some())
            .finish_non_exhaustive()
    }
}

/// A started engine: what requests and streams are made with.
///
/// Cloning is cheap. Every request, stream and clone keeps the engine alive;
/// when the last is gone it shuts down, waiting for its threads, and frees
/// its resources.
#[derive(Clone)]
pub struct Engine(Arc<Inner>);

struct Inner {
    raw: NonNull<sys::Cronet_Engine>,
    dialers: Dialers,
    /// Engine-wide listeners, kept alive while registered.
    listeners: Mutex<Vec<(RequestFinishedListener, Executor)>>,
}

// SAFETY: Cronet's engine is thread-safe, and the dialers are `Send + Sync`.
unsafe impl Send for Inner {}
// SAFETY: as above.
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        struct Shutdown(
            NonNull<sys::Cronet_Engine>,
            Dialers,
            Vec<(RequestFinishedListener, Executor)>,
        );
        // SAFETY: see `Inner`.
        unsafe impl Send for Shutdown {}

        impl Shutdown {
            fn run(self) {
                let Self(raw, dialers, listeners) = self;
                // SAFETY: nothing uses the engine any more: every request and
                // stream holds a clone. The dialers outlive it.
                unsafe {
                    sys::Cronet_Engine_Shutdown(raw.as_ptr());
                    sys::Cronet_Engine_Destroy(raw.as_ptr());
                }
                drop((dialers, listeners));
            }
        }

        let listeners = mem::take(self.listeners.get_mut().unwrap_or_else(PoisonError::into_inner));
        let shutdown = Shutdown(self.raw, mem::take(&mut self.dialers), listeners);
        // Shutdown waits for the network thread, so it cannot run on it.
        if NetworkThread::is_current() {
            thread::Builder::new()
                .name("cronet-shutdown".into())
                .spawn(move || shutdown.run())
                .expect("spawning the shutdown thread");
        } else {
            shutdown.run();
        }
    }
}

impl Engine {
    /// Starts an engine with `params` and the default sockets; see
    /// [`EngineBuilder`] for the rest.
    ///
    /// # Errors
    ///
    /// As [`EngineBuilder::start`].
    pub fn start(params: &EngineParamsRef) -> Result<Self, ApiError> {
        EngineBuilder::new().start(params)
    }

    /// A builder, for dialers and root certificates.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::new()
    }

    /// Cronet's version, such as `150.0.7871.63`.
    pub fn version(&self) -> String {
        // SAFETY: the engine is live; the string is copied at once.
        unsafe { string(sys::Cronet_Engine_GetVersionString(self.as_ptr())) }.into_owned()
    }

    /// The `User-Agent` the engine sends by default.
    pub fn default_user_agent(&self) -> String {
        // SAFETY: the engine is live; the string is copied at once.
        unsafe { string(sys::Cronet_Engine_GetDefaultUserAgent(self.as_ptr())) }.into_owned()
    }

    /// Starts writing a NetLog of every live engine to `path`, truncating it;
    /// does nothing if a log is already being written. View it at
    /// `chrome://net-internals/#import`.
    ///
    /// `log_all` includes cookies, credentials and every byte transferred:
    /// only with the user's consent, and never for a log that may become
    /// public.
    ///
    /// Returns whether logging started; a path that is not UTF-8 never does.
    pub fn start_net_log(&self, path: impl AsRef<Path>, log_all: bool) -> bool {
        let Some(path) = path
            .as_ref()
            .to_str()
            .and_then(|path| std::ffi::CString::new(path).ok())
        else {
            return false;
        };
        // SAFETY: the engine is live and the path valid for the call.
        unsafe { sys::Cronet_Engine_StartNetLogToFile(self.as_ptr(), path.as_ptr(), log_all) }
    }

    /// Stops the NetLog and flushes it, blocking until the file is complete.
    pub fn stop_net_log(&self) {
        // SAFETY: the engine is live.
        unsafe { sys::Cronet_Engine_StopNetLog(self.as_ptr()) }
    }

    /// Calls `listener` on `executor` when each request started from now on
    /// ends. The engine keeps both until they are removed.
    pub fn add_request_finished_listener(&self, listener: &RequestFinishedListener, executor: &Executor) {
        let mut listeners = self.0.listeners.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: all three objects are live, and stay so while registered.
        unsafe { sys::Cronet_Engine_AddRequestFinishedListener(self.as_ptr(), listener.as_ptr(), executor.as_ptr()) };
        listeners.push((listener.clone(), executor.clone()));
    }

    /// Unregisters `listener`, and its executor with it.
    pub fn remove_request_finished_listener(&self, listener: &RequestFinishedListener) {
        let mut listeners = self.0.listeners.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: both objects are live.
        unsafe { sys::Cronet_Engine_RemoveRequestFinishedListener(self.as_ptr(), listener.as_ptr()) };
        listeners.retain(|(registered, _)| !registered.same(listener));
    }

    /// Closes every connection the engine holds: socket pools, HTTP/2 and
    /// QUIC sessions. Frees their memory, or hurries a shutdown along.
    pub fn close_all_connections(&self) {
        // SAFETY: the engine is live and started.
        unsafe { sys::Cronet_Engine_CloseAllConnections(self.as_ptr()) }
    }

    /// Registers or updates synthetic endpoint metadata (`ECHConfigList`,
    /// ALPNs, and strict ECH policy) for `host`. May be called from any
    /// thread; connections made from then on use it.
    ///
    /// For engines started without a stream dialer
    /// (`EngineBuilder::stream_dialer`, feature `tokio`) or an initial
    /// [`EngineBuilder::endpoint`], call [`EngineBuilder::enable_endpoints`]
    /// before starting so the in-memory resolver is installed; otherwise this
    /// has no effect.
    ///
    /// # Panics
    ///
    /// If `host` or an ALPN entry contains a NUL byte.
    pub fn endpoint(&self, host: &str, endpoint: Endpoint) {
        set_endpoint_raw(self.as_ptr(), host, &endpoint);
    }

    /// Clears all registered endpoint entries on this engine while keeping the
    /// in-memory resolver active.
    pub fn clear_endpoints(&self) {
        // SAFETY: the engine is live.
        unsafe { sys::Cronet_Engine_ClearEndpoints(self.as_ptr()) }
    }

    /// Sets or updates the QUIC Brutal send rate (in bytes per second) for the
    /// QUIC session identified by `connection_id` (from
    /// [`Stream::connection_id`](crate::Stream::connection_id), or
    /// `BidirectionalConn::connection_id` with feature `tokio`) when the
    /// engine was started with the `BRTL` QUIC client connection option (see
    /// [`EngineParamsRef::set_quic_options`]).
    ///
    /// Passing `0` disables fixed-rate sending and delegates congestion control
    /// back to BBR. May be called from any thread; unknown or already closed
    /// `connection_id` values are ignored, as are TCP connection IDs (high bit
    /// clear); sessions that did not select `BRTL` are unaffected.
    ///
    /// The call posts to the network thread and returns at once. The rate
    /// applies to the whole session, every stream multiplexed onto it, and
    /// survives connection migration. It shapes only what this side sends;
    /// the peer's sending is up to the peer. With a rate set, the sender paces
    /// at `rate / ack_rate`, where `ack_rate` is the share of packets
    /// acknowledged over the last 5 seconds (counted once there are 50
    /// samples, and never below 0.8, so at most 1.25 times the rate), and
    /// keeps a congestion window of
    /// `2 × paced rate × (max(srtt, 1 ms) + max(peer max_ack_delay, 25 ms))`,
    /// at least 10 full-size packets. Rates above 125,000,000,000 bytes per second are
    /// clamped.
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use cronet::{Engine, EngineParams, Stream};
    ///
    /// let mut params = EngineParams::new();
    /// params.set_enable_quic(true).set_quic_options("", "BRTL", 0, 0)?;
    /// let engine = Engine::start(&params)?;
    ///
    /// // Later, once a stream on the engine has its response headers:
    /// fn shape(engine: &Engine, stream: &Stream) {
    ///     let id = stream.connection_id();
    ///     if id & (1 << 63) != 0 {
    ///         engine.set_quic_send_rate(id, 12_500_000); // 100 Mbit/s
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_quic_send_rate(&self, connection_id: u64, bytes_per_second: u64) {
        // SAFETY: the engine is live and started; the call posts to Cronet's network thread.
        unsafe { sys::Cronet_Engine_SetQuicSendRate(self.as_ptr(), connection_id, bytes_per_second) }
    }

    pub(crate) fn as_ptr(&self) -> sys::Cronet_EnginePtr {
        self.0.raw.as_ptr()
    }

    /// The engine bidirectional streams are made with; owned by the engine.
    pub(crate) fn stream_engine(&self) -> *mut sys::stream_engine {
        // SAFETY: the engine is live and started.
        unsafe { sys::Cronet_Engine_GetStreamEngine(self.as_ptr()) }
    }
}

impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Engine").field(&self.0.raw).finish()
    }
}

/// Marks the code Cronet's network thread runs in this crate, so that an
/// engine dropped there shuts down elsewhere.
pub(crate) struct NetworkThread(bool);

thread_local! {
    static ON_NETWORK_THREAD: Cell<bool> = const { Cell::new(false) };
}

impl NetworkThread {
    /// Until the guard drops, this thread counts as the network thread.
    pub(crate) fn enter() -> Self {
        Self(ON_NETWORK_THREAD.replace(true))
    }

    pub(crate) fn is_current() -> bool {
        ON_NETWORK_THREAD.get()
    }
}

fn set_endpoint_raw(engine: sys::Cronet_EnginePtr, host: &str, endpoint: &Endpoint) {
    let host = c_string(host);
    let alpn = if endpoint.alpn.is_empty() {
        None
    } else {
        Some(c_string(&endpoint.alpn.join(",")))
    };
    let (ech_ptr, ech_len) = if endpoint.ech.is_empty() {
        (ptr::null(), 0)
    } else {
        (endpoint.ech.as_ptr(), endpoint.ech.len())
    };
    // SAFETY: `engine` is live; all pointers remain valid for the duration of
    // the call, which copies their contents.
    unsafe {
        sys::Cronet_Engine_SetEndpoint(
            engine,
            host.as_ptr(),
            ech_ptr,
            ech_len,
            alpn.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            endpoint.strict,
        );
    }
}

#[cfg(feature = "tokio")]
unsafe extern "C" fn dial_stream(
    context: *mut c_void,
    host: *const c_char,
    port: u16,
    connection_id: u64,
    handle: *mut sys::Cronet_LowerStreamHandle,
    out_stream: *mut sys::Cronet_LowerStream,
) -> std::ffi::c_int {
    let _network = NetworkThread::enter();
    // SAFETY: `context` points to the engine's `StreamDialer`, alive until shutdown.
    let (dialer, runtime) = unsafe { &*context.cast::<StreamDialer>() };
    let _rt = runtime.as_ref().map(tokio::runtime::Handle::enter);
    // SAFETY: Cronet passes a valid NUL-terminated host string.
    let host = unsafe { string(host) }.into_owned();
    let target = Target {
        host,
        port,
        connection_id,
    };
    match dialer(target) {
        Ok(stream) => {
            // SAFETY: `out_stream` is valid and `handle` transfers to `into_raw_stream` on success.
            unsafe {
                *out_stream = crate::lower::into_raw_stream(stream, handle, runtime.clone());
            }
            0
        }
        Err(error) => NetError::from_io_error(&error).code(),
    }
}

impl Drop for NetworkThread {
    fn drop(&mut self) {
        ON_NETWORK_THREAD.set(self.0);
    }
}

/// # Safety
///
/// `address` is a nul-terminated string.
unsafe fn socket_addr(address: *const c_char, port: u16) -> Option<SocketAddr> {
    // SAFETY: forwarded to the caller.
    let address = unsafe { CStr::from_ptr(address) }.to_str().ok()?;
    Some(SocketAddr::new(address.parse::<IpAddr>().ok()?, port))
}

unsafe extern "C" fn dial_tcp(context: *mut c_void, address: *const c_char, port: u16) -> isize {
    let _network = NetworkThread::enter();
    // SAFETY: the context is the engine's TCP dialer, alive as long as the engine.
    let dialer = unsafe { &*context.cast::<Box<TcpDialer>>() };
    // SAFETY: Cronet passes a nul-terminated IP literal.
    let Some(address) = (unsafe { socket_addr(address, port) }) else {
        return NetError::ADDRESS_INVALID.code() as isize;
    };
    match dialer(address) {
        Ok(socket) => into_raw(socket),
        Err(error) => error.code() as isize,
    }
}

/// `INET6_ADDRSTRLEN`, the size of the buffer Cronet passes for the local
/// address, terminating NUL included.
const LOCAL_ADDRESS_CAPACITY: usize = 46;

unsafe extern "C" fn dial_udp(
    context: *mut c_void,
    address: *const c_char,
    port: u16,
    out_local_address: *mut c_char,
    out_local_port: *mut u16,
    out_socket_id: *mut u64,
) -> isize {
    let _network = NetworkThread::enter();
    // SAFETY: Cronet passes valid out-pointers; zero asks for no close notification.
    unsafe {
        if !out_socket_id.is_null() {
            *out_socket_id = 0;
        }
    }
    // SAFETY: the context is the engine's UDP dialer, alive as long as the engine.
    let dialer = unsafe { &*context.cast::<Box<UdpDialer>>() };
    // SAFETY: Cronet passes a nul-terminated IP literal.
    let Some(address) = (unsafe { socket_addr(address, port) }) else {
        return NetError::ADDRESS_INVALID.code() as isize;
    };
    let dialed = match dialer(address) {
        Ok(dialed) => dialed,
        Err(error) => return error.code() as isize,
    };
    // SAFETY: the out-pointers are valid when non-null, and the address
    // buffer holds `LOCAL_ADDRESS_CAPACITY` bytes.
    unsafe {
        if let Some(local) = dialed.local_addr {
            let ip = local.ip().to_string();
            if !out_local_address.is_null() && ip.len() < LOCAL_ADDRESS_CAPACITY {
                ptr::copy_nonoverlapping(ip.as_ptr(), out_local_address.cast::<u8>(), ip.len());
                *out_local_address.add(ip.len()) = 0;
            }
            if !out_local_port.is_null() {
                *out_local_port = local.port();
            }
        }
        if let Some(on_close) = dialed.on_close
            && !out_socket_id.is_null()
        {
            let on_close: Box<OnClose> = Box::new(on_close);
            *out_socket_id = Box::into_raw(on_close) as usize as u64;
        }
    }
    into_raw(dialed.socket)
}

unsafe extern "C" fn udp_socket_closed(socket_id: u64) {
    let _network = NetworkThread::enter();
    if socket_id != 0 {
        // SAFETY: a non-zero id is the `OnClose` `dial_udp` leaked, passed back once.
        let on_close = unsafe { Box::from_raw(socket_id as usize as *mut OnClose) };
        on_close();
    }
}
