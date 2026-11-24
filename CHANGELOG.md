# Changelog

## 0.2.0

### Added

- **Byte-stream dialer (`StreamDialer` / `Lower`)**:
  `EngineBuilder::stream_dialer` and `EngineBuilder::async_stream_dialer` let
  Chromium run HTTP/1.1 and HTTP/2 connections over any `AsyncRead + AsyncWrite`
  byte stream (`Cronet_LowerStream`) without owning OS file descriptors,
  exposing per-connection IDs via `Target::connection_id`,
  `Stream::connection_id`, and `BidirectionalConn::connection_id`.
- **Synthetic HTTPS/ECH endpoints with strict mode (`Endpoint`)**:
  `EngineBuilder::endpoint`, `EngineBuilder::enable_endpoints`,
  `Engine::endpoint`, and `Engine::clear_endpoints` resolve hostnames in memory
  without querying DNS, attaching `ECHConfigList`, ALPN lists, and `strict` ECH
  enforcement (immediate `NetError::ECH_NOT_NEGOTIATED` failure when ECH is not
  accepted, with zero unencrypted fallback attempts and zero `retry_configs`
  retries).
- **Unified TLS configuration and standalone `tls::Client`**:
  `cronet::tls::Config` configures exclusive custom PEM root anchors,
  `verify_name` overrides, SHA-256 certificate and SPKI pins, client
  certificates (`client_identity`), ALPNs, ECH (`strict_ech`), and clock offsets
  across both `EngineBuilder::tls_config` and `cronet::tls::Client`
  (`TlsStream` via `connect` / `connect_with` over any `Lower` stream on the
  engine's network thread, exposing `alpn()`, `ech_accepted()`, and
  `retry_configs()`).
- **Mach-O static archive symbol localization**: `cargo xtask package` now
  prelinks `libcronet.a` on Apple targets (`macOS`, `iOS`, `tvOS`, and
  simulators) with `-exported_symbols_list` (matching the existing ELF `ld -r`
  step on Linux and Android), localizing bundled BoringSSL and libc++ symbols
  while preserving `MH_SUBSECTIONS_VIA_SYMBOLS` for `-dead_strip` so `libcronet.a`
  links cleanly alongside external BoringSSL or OpenSSL crates with only
  `Cronet_*` and `bidirectional_stream_*` symbols global.
- **Patch layer in `xtask`**: `cargo xtask fetch` and `cargo xtask upgrade`
  apply `patches/*.patch` in lexical order and overlay `patches/src/` onto the
  checked-out `naiveproxy` tree, failing immediately with the locked naiveproxy
  commit on conflict.
- **Target filtering in CI**: `.github/workflows/libcronet.yml` accepts a
  `targets` input (`default`, `all`, or a comma/space-separated list of Rust
  triples) on `workflow_dispatch` and `workflow_call`.

### Fixed

- **Cross-direction readiness wakeups on `Lower` streams**: `lower_read` and
  `lower_write` now preserve synchronous cross-direction wakeups when a
  `Poll::Ready` poll on an underlying stream wakes the opposite direction in the
  same turn (for example, duplex upgrade wrappers where read and write state
  share a waker), preventing lost readiness notifications during TLS handshakes.
- **`Send` futures on `tls::Client::connect`**: `tls::Client::connect` and
  `tls::Client::connect_with` futures are `Send` across `.await` points for
  multi-threaded `tokio::spawn` executors.
