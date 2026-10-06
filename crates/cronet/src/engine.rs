//! The engine: Chromium's network stack, started once and shared by every
//! request and stream made with it.

use std::{
    cell::Cell,
    ffi::{CStr, c_char, c_void},
    fmt, mem,
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

type TcpDialer = dyn Fn(SocketAddr) -> Result<Socket, NetError> + Send + Sync;
type UdpDialer = dyn Fn(SocketAddr) -> Result<DialedUdpSocket, NetError> + Send + Sync;
type OnClose = Box<dyn FnOnce() + Send>;

/// The dialers an engine calls back into; boxed twice so that the address
/// handed to Cronet stays put.
#[derive(Default)]
struct Dialers {
    tcp: Option<Box<Box<TcpDialer>>>,
    udp: Option<Box<Box<UdpDialer>>>,
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

    /// Trusts only the certificates in `pem` (one or more) as roots.
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

    fn is_current() -> bool {
        ON_NETWORK_THREAD.get()
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
