//! How an engine is configured: [`EngineParams`], with the QUIC hints and
//! public key pins it carries, and typed setters for the JSON experimental
//! options naiveproxy's Cronet understands.

use std::{
    fmt,
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use cronet_sys as sys;
use serde_json::{Map, Value, json};

use crate::ffi::{c_enum, c_string, properties, string, value_type};

c_enum! {
    /// What the engine caches.
    pub enum HttpCacheMode: sys::Cronet_EngineParams_HTTP_CACHE_MODE {
        /// Nothing.
        Disabled = sys::Cronet_EngineParams_HTTP_CACHE_MODE_DISABLED,
        /// Everything, HTTP data included, in memory.
        InMemory = sys::Cronet_EngineParams_HTTP_CACHE_MODE_IN_MEMORY,
        /// Everything but HTTP data, on disk.
        DiskNoHttp = sys::Cronet_EngineParams_HTTP_CACHE_MODE_DISK_NO_HTTP,
        /// Everything, HTTP data included, on disk.
        Disk = sys::Cronet_EngineParams_HTTP_CACHE_MODE_DISK,
    }
    unknown => Disabled;
}

value_type! {
    /// A hint that a host supports QUIC.
    pub struct QuicHint / QuicHintRef (sys::Cronet_QuicHint) {
        create: sys::Cronet_QuicHint_Create,
        destroy: sys::Cronet_QuicHint_Destroy,
    }
}

properties!(QuicHintRef {
    /// The host that supports QUIC.
    string host, set_host: sys::Cronet_QuicHint_host_get, sys::Cronet_QuicHint_host_set;
    /// The port of the server that supports QUIC.
    i32 as port, set_port: sys::Cronet_QuicHint_port_get, sys::Cronet_QuicHint_port_set;
    /// The port to use for QUIC.
    i32 as alternate_port, set_alternate_port: sys::Cronet_QuicHint_alternate_port_get, sys::Cronet_QuicHint_alternate_port_set;
});

impl QuicHint {
    /// A hint that `host:port` speaks QUIC on `alternate_port`.
    ///
    /// # Panics
    ///
    /// If `host` contains a NUL byte.
    pub fn with(host: &str, port: u16, alternate_port: u16) -> Self {
        let mut hint = Self::new();
        hint.set_host(host)
            .set_port(port.into())
            .set_alternate_port(alternate_port.into());
        hint
    }
}

impl fmt::Debug for QuicHintRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicHint")
            .field("host", &self.host())
            .field("port", &self.port())
            .field("alternate_port", &self.alternate_port())
            .finish()
    }
}

impl fmt::Debug for QuicHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

value_type! {
    /// Public keys a host's certificate chain must contain one of.
    pub struct PublicKeyPins / PublicKeyPinsRef (sys::Cronet_PublicKeyPins) {
        create: sys::Cronet_PublicKeyPins_Create,
        destroy: sys::Cronet_PublicKeyPins_Destroy,
    }
}

properties!(PublicKeyPinsRef {
    /// The host the keys are pinned for. A host of only digits and dots is
    /// invalid.
    string host, set_host: sys::Cronet_PublicKeyPins_host_get, sys::Cronet_PublicKeyPins_host_set;
    /// Whether the pins apply to the host's subdomains as well.
    bool as include_subdomains, set_include_subdomains:
        sys::Cronet_PublicKeyPins_include_subdomains_get, sys::Cronet_PublicKeyPins_include_subdomains_set;
});

impl PublicKeyPinsRef {
    /// The pins, each the SHA-256 of a certificate's DER-encoded Subject
    /// Public Key Info, as `sha256/<base64>`.
    pub fn pins_sha256(&self) -> impl ExactSizeIterator<Item = std::borrow::Cow<'_, str>> + '_ {
        // SAFETY: the object is live.
        let len = unsafe { sys::Cronet_PublicKeyPins_pins_sha256_size(self.as_ptr()) };
        (0..len).map(move |index| {
            // SAFETY: `index` is in bounds, and the list is not modified while `self` is borrowed.
            unsafe { string(sys::Cronet_PublicKeyPins_pins_sha256_at(self.as_ptr(), index)) }
        })
    }

    /// Adds a pin, as `sha256/<base64>`. A backup pin, for when the primary
    /// key is lost, is not required but strongly recommended.
    ///
    /// # Panics
    ///
    /// If `pin` contains a NUL byte.
    pub fn add_pin_sha256(&mut self, pin: &str) -> &mut Self {
        let pin = c_string(pin);
        // SAFETY: the object is live and uniquely borrowed; Cronet copies the string.
        unsafe { sys::Cronet_PublicKeyPins_pins_sha256_add(self.as_ptr(), pin.as_ptr()) };
        self
    }

    /// Removes every pin.
    pub fn clear_pins_sha256(&mut self) -> &mut Self {
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_PublicKeyPins_pins_sha256_clear(self.as_ptr()) };
        self
    }

    /// When the pins expire.
    pub fn expiration_date(&self) -> SystemTime {
        // SAFETY: the object is live.
        let millis = unsafe { sys::Cronet_PublicKeyPins_expiration_date_get(self.as_ptr()) };
        let offset = Duration::from_millis(millis.unsigned_abs());
        if millis >= 0 {
            SystemTime::UNIX_EPOCH + offset
        } else {
            SystemTime::UNIX_EPOCH - offset
        }
    }

    /// Sets [`expiration_date`](Self::expiration_date), to the millisecond.
    pub fn set_expiration_date(&mut self, date: SystemTime) -> &mut Self {
        let millis = match date.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
            Err(before) => i64::try_from(before.duration().as_millis()).map_or(i64::MIN, |millis| -millis),
        };
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_PublicKeyPins_expiration_date_set(self.as_ptr(), millis) };
        self
    }
}

impl fmt::Debug for PublicKeyPinsRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeyPins")
            .field("host", &self.host())
            .field("pins_sha256", &self.pins_sha256().collect::<Vec<_>>())
            .field("include_subdomains", &self.include_subdomains())
            .field("expiration_date", &self.expiration_date())
            .finish()
    }
}

impl fmt::Debug for PublicKeyPins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

value_type! {
    /// How to configure an [`Engine`](crate::Engine) when it starts.
    ///
    /// ```no_run
    /// let mut params = cronet::EngineParams::new();
    /// params.set_user_agent("example/1.0").set_enable_quic(true).set_async_dns(true)?;
    /// let engine = cronet::Engine::start(&params)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub struct EngineParams / EngineParamsRef (sys::Cronet_EngineParams) {
        create: sys::Cronet_EngineParams_Create,
        destroy: sys::Cronet_EngineParams_Destroy,
    }
}

properties!(EngineParamsRef {
    /// Whether a failed API call aborts the process (Cronet's default)
    /// instead of returning an [`ApiError`](crate::ApiError).
    bool as enable_check_result, set_enable_check_result:
        sys::Cronet_EngineParams_enable_check_result_get, sys::Cronet_EngineParams_enable_check_result_set;
    /// The `User-Agent` for every request; a request's own header overrides it.
    string user_agent, set_user_agent: sys::Cronet_EngineParams_user_agent_get, sys::Cronet_EngineParams_user_agent_set;
    /// The default `Accept-Language`; a request's own header overrides it.
    string accept_language, set_accept_language:
        sys::Cronet_EngineParams_accept_language_get, sys::Cronet_EngineParams_accept_language_set;
    /// The directory for the HTTP cache and preferences. It must exist.
    string storage_path, set_storage_path:
        sys::Cronet_EngineParams_storage_path_get, sys::Cronet_EngineParams_storage_path_set;
    /// Whether QUIC is enabled. With it, a QUIC user agent id naming the app
    /// and Cronet's version is sent to servers.
    bool as enable_quic, set_enable_quic: sys::Cronet_EngineParams_enable_quic_get, sys::Cronet_EngineParams_enable_quic_set;
    /// Whether HTTP/2 is enabled.
    bool as enable_http2, set_enable_http2:
        sys::Cronet_EngineParams_enable_http2_get, sys::Cronet_EngineParams_enable_http2_set;
    /// Whether Brotli is enabled, and advertised in `Accept-Encoding`.
    bool as enable_brotli, set_enable_brotli:
        sys::Cronet_EngineParams_enable_brotli_get, sys::Cronet_EngineParams_enable_brotli_set;
    /// What is cached, HTTP data and QUIC server information alike.
    HttpCacheMode as http_cache_mode, set_http_cache_mode:
        sys::Cronet_EngineParams_http_cache_mode_get, sys::Cronet_EngineParams_http_cache_mode_set;
    /// The cache's maximum size in bytes; advisory, and sometimes exceeded.
    i64 as http_cache_max_size, set_http_cache_max_size:
        sys::Cronet_EngineParams_http_cache_max_size_get, sys::Cronet_EngineParams_http_cache_max_size_set;
    /// Whether pinning is bypassed for certificates chaining to locally added
    /// trust anchors. Turning the bypass off is strongly discouraged: it
    /// breaks users who route traffic through a TLS-inspecting proxy.
    bool as enable_public_key_pinning_bypass_for_local_trust_anchors,
        set_enable_public_key_pinning_bypass_for_local_trust_anchors:
        sys::Cronet_EngineParams_enable_public_key_pinning_bypass_for_local_trust_anchors_get,
        sys::Cronet_EngineParams_enable_public_key_pinning_bypass_for_local_trust_anchors_set;
    /// Experimental options, as a JSON object. The typed setters below edit
    /// one key each.
    string experimental_options, set_experimental_options:
        sys::Cronet_EngineParams_experimental_options_get, sys::Cronet_EngineParams_experimental_options_set;
});

impl EngineParamsRef {
    /// Hosts known to support QUIC.
    pub fn quic_hints(&self) -> impl ExactSizeIterator<Item = &QuicHintRef> + '_ {
        // SAFETY: the object is live.
        let len = unsafe { sys::Cronet_EngineParams_quic_hints_size(self.as_ptr()) };
        (0..len).map(move |index| {
            // SAFETY: `index` is in bounds, and the list is not modified while `self` is borrowed.
            unsafe { QuicHintRef::from_ptr(sys::Cronet_EngineParams_quic_hints_at(self.as_ptr(), index)) }
        })
    }

    /// Adds a copy of `hint` to [`quic_hints`](Self::quic_hints).
    pub fn add_quic_hint(&mut self, hint: &QuicHintRef) -> &mut Self {
        // SAFETY: both objects are live; Cronet copies the hint.
        unsafe { sys::Cronet_EngineParams_quic_hints_add(self.as_ptr(), hint.as_ptr()) };
        self
    }

    /// Empties [`quic_hints`](Self::quic_hints).
    pub fn clear_quic_hints(&mut self) -> &mut Self {
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_EngineParams_quic_hints_clear(self.as_ptr()) };
        self
    }

    /// Public keys pinned for hosts.
    pub fn public_key_pins(&self) -> impl ExactSizeIterator<Item = &PublicKeyPinsRef> + '_ {
        // SAFETY: the object is live.
        let len = unsafe { sys::Cronet_EngineParams_public_key_pins_size(self.as_ptr()) };
        (0..len).map(move |index| {
            // SAFETY: `index` is in bounds, and the list is not modified while `self` is borrowed.
            unsafe { PublicKeyPinsRef::from_ptr(sys::Cronet_EngineParams_public_key_pins_at(self.as_ptr(), index)) }
        })
    }

    /// Adds a copy of `pins` to [`public_key_pins`](Self::public_key_pins).
    pub fn add_public_key_pins(&mut self, pins: &PublicKeyPinsRef) -> &mut Self {
        // SAFETY: both objects are live; Cronet copies the pins.
        unsafe { sys::Cronet_EngineParams_public_key_pins_add(self.as_ptr(), pins.as_ptr()) };
        self
    }

    /// Empties [`public_key_pins`](Self::public_key_pins).
    pub fn clear_public_key_pins(&mut self) -> &mut Self {
        // SAFETY: the object is live and uniquely borrowed.
        unsafe { sys::Cronet_EngineParams_public_key_pins_clear(self.as_ptr()) };
        self
    }

    /// The network thread's priority, if set: Android's
    /// `Process.setThreadPriority` values, or iOS's `NSThread` ones. Leave it
    /// unset on other platforms.
    pub fn network_thread_priority(&self) -> Option<f64> {
        // SAFETY: the object is live.
        let priority = unsafe { sys::Cronet_EngineParams_network_thread_priority_get(self.as_ptr()) };
        (!priority.is_nan()).then_some(priority)
    }

    /// Sets [`network_thread_priority`](Self::network_thread_priority), or unsets it.
    pub fn set_network_thread_priority(&mut self, priority: Option<f64>) -> &mut Self {
        // SAFETY: the object is live and uniquely borrowed; NaN means unset.
        unsafe { sys::Cronet_EngineParams_network_thread_priority_set(self.as_ptr(), priority.unwrap_or(f64::NAN)) };
        self
    }

    /// Sets one key of [`experimental_options`](Self::experimental_options),
    /// or removes it for `None`, keeping the others.
    pub fn set_experimental_option(&mut self, key: &str, value: Option<Value>) -> serde_json::Result<&mut Self> {
        let current = self.experimental_options();
        let mut options: Map<String, Value> = if current.trim().is_empty() {
            Map::new()
        } else {
            serde_json::from_str(&current)?
        };
        match value {
            Some(value) => options.insert(key.to_owned(), value),
            None => options.remove(key),
        };
        Ok(self.set_experimental_options(&serde_json::to_string(&options)?))
    }

    /// Whether Cronet resolves names with its own DNS client instead of the
    /// system's (`AsyncDNS`).
    pub fn set_async_dns(&mut self, enable: bool) -> serde_json::Result<&mut Self> {
        self.set_experimental_option("AsyncDNS", enable.then(|| json!({ "enable": true })))
    }

    /// Makes Cronet's own DNS client ask only these name servers
    /// (`DnsServerOverride`); an empty list removes the override.
    pub fn set_dns_server_override(&mut self, name_servers: &[SocketAddr]) -> serde_json::Result<&mut Self> {
        let name_servers: Vec<String> = name_servers.iter().map(SocketAddr::to_string).collect();
        self.set_experimental_option(
            "DnsServerOverride",
            (!name_servers.is_empty()).then(|| json!({ "nameservers": name_servers })),
        )
    }

    /// Rules overriding name resolution (`HostResolverRules`), such as
    /// `MAP example.com 1.2.3.4, EXCLUDE foo.com`; see Chromium's
    /// `net/dns/mapped_host_resolver.h`. Empty removes them.
    pub fn set_host_resolver_rules(&mut self, rules: &str) -> serde_json::Result<&mut Self> {
        self.set_experimental_option(
            "HostResolverRules",
            (!rules.is_empty()).then(|| json!({ "host_resolver_rules": rules })),
        )
    }

    /// Whether DNS HTTPS records (type 65) are looked up (`UseDnsHttpsSvcb`):
    /// they carry ECH configurations and ALPN hints, and ECH needs them.
    pub fn set_use_dns_https_svcb(&mut self, enable: bool) -> serde_json::Result<&mut Self> {
        self.set_experimental_option("UseDnsHttpsSvcb", Some(json!({ "enable": enable })))
    }

    /// HTTP/2's session and stream receive windows (`HTTP2Options`).
    pub fn set_http2_options(
        &mut self,
        session_max_receive_window_size: u64,
        initial_window_size: u64,
    ) -> serde_json::Result<&mut Self> {
        self.set_experimental_option(
            "HTTP2Options",
            Some(json!({
                "session_max_recv_window_size": session_max_receive_window_size,
                "initial_window_size": initial_window_size,
            })),
        )
    }

    /// QUIC's parameters (`QUIC`); empty strings and zeros are left out, and
    /// with nothing left the key is removed.
    ///
    /// Both are lists of QUIC connection option tags. `connection_options`
    /// travel to the server in the handshake and shape what it does;
    /// `client_connection_options` stay local and shape what this side does,
    /// such as which congestion controller sends (`TBBR`, `B2ON`, ...).
    pub fn set_quic_options(
        &mut self,
        connection_options: &str,
        client_connection_options: &str,
        initial_stream_receive_window_size: u64,
        initial_session_receive_window_size: u64,
    ) -> serde_json::Result<&mut Self> {
        let mut options = Map::new();
        if !connection_options.is_empty() {
            options.insert("connection_options".into(), connection_options.into());
        }
        if !client_connection_options.is_empty() {
            options.insert("client_connection_options".into(), client_connection_options.into());
        }
        if initial_stream_receive_window_size > 0 {
            options.insert(
                "initial_stream_recv_window_size".into(),
                initial_stream_receive_window_size.into(),
            );
        }
        if initial_session_receive_window_size > 0 {
            options.insert(
                "initial_session_recv_window_size".into(),
                initial_session_receive_window_size.into(),
            );
        }
        self.set_experimental_option("QUIC", (!options.is_empty()).then_some(Value::Object(options)))
    }

    /// How many sockets the engine may open (`SocketPoolOptions`): in all, per
    /// proxy chain, and per group.
    pub fn set_socket_pool_options(
        &mut self,
        max_per_pool: u32,
        max_per_proxy_chain: u32,
        max_per_group: u32,
    ) -> serde_json::Result<&mut Self> {
        self.set_experimental_option(
            "SocketPoolOptions",
            Some(json!({
                "max_sockets_per_pool": max_per_pool,
                "max_sockets_per_proxy_chain": max_per_proxy_chain,
                "max_sockets_per_group": max_per_group,
            })),
        )
    }
}

impl fmt::Debug for EngineParamsRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineParams")
            .field("enable_check_result", &self.enable_check_result())
            .field("user_agent", &self.user_agent())
            .field("accept_language", &self.accept_language())
            .field("storage_path", &self.storage_path())
            .field("enable_quic", &self.enable_quic())
            .field("enable_http2", &self.enable_http2())
            .field("enable_brotli", &self.enable_brotli())
            .field("http_cache_mode", &self.http_cache_mode())
            .field("http_cache_max_size", &self.http_cache_max_size())
            .field("quic_hints", &self.quic_hints().collect::<Vec<_>>())
            .field("public_key_pins", &self.public_key_pins().collect::<Vec<_>>())
            .field(
                "enable_public_key_pinning_bypass_for_local_trust_anchors",
                &self.enable_public_key_pinning_bypass_for_local_trust_anchors(),
            )
            .field("network_thread_priority", &self.network_thread_priority())
            .field("experimental_options", &self.experimental_options())
            .finish()
    }
}

impl fmt::Debug for EngineParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}
