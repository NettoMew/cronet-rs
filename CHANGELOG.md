# Changelog

## 0.3.0

### Added

- **QUIC Brutal congestion control (`BRTL` / `Engine::set_quic_send_rate`)**:
  passing `BRTL` in `client_connection_options`
  (`EngineParamsRef::set_quic_options`) selects `BrutalSender` on client QUIC
  sessions. Until a rate is configured (or after setting `0`), `BrutalSender`
  delegates to an embedded `BbrSender`; once `Engine::set_quic_send_rate`
  (`Cronet_Engine_SetQuicSendRate`) sets a non-zero byte-per-second target for a
  session's `connection_id`, it paces at `rate / ack_rate` using a 5-second
  sliding ACK/loss window (50-sample activation threshold, `0.8` minimum ACK
  rate = `1.25x` maximum loss compensation), sizes its congestion window to
  `max(4 * MSS, compensated_rate * max(srtt, 1ms) * 2)`, and preserves the
  configured rate across QUIC connection migrations.
- **Session-level QUIC `connection_id` on bidirectional streams**:
  `Stream::connection_id` and `BidirectionalConn::connection_id`
  (`Cronet_BidirectionalStream_GetConnectionId`) now report `(1 << 63) | n` for
  HTTP/3 streams, uniquely identifying each `QuicChromiumClientSession` across
  multiplexed streams and UDP socket migrations while keeping stream-dialed TCP
  IDs (`(id & (1 << 63)) == 0`) disjoint and default OS-socket TCP streams at
  `0`.

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
  `Cronet_*` and `bidirectional_stream_*` symbols global. Hand-written Apple
  assembly sources that omitted `.subsections_via_symbols` now emit it on both
  `arm64` and `x86_64`, and `cargo xtask package` verifies every input `.o`
  member carries `MH_SUBSECTIONS_VIA_SYMBOLS` before `ld -r`.
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
- **Terminal state visibility in final callbacks**: `BidirectionalStream` and
  `UrlRequest` now mark the stream or request closed before invoking
  `on_succeeded`, `on_failed`, or `on_canceled`, so operations called inside or
  woken by a final callback consistently observe `StreamError::Closed`.
