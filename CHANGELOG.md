# Changelog

## Unreleased

### Documentation

- README examples for stream dialers, ECH endpoints, `tls::Client` and QUIC
  Brutal, compiled as doctests, and a section on threads and lifetimes.
- Rustdoc for every public item added in 0.2.0 and 0.3.0, comments on the
  C declarations added to `cronet_c.h` (carried by the patches that add them
  and by `cronet-sys`), and `patches/README.md`.

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
  `max(10 * MSS, 2 * compensated_rate * (max(srtt, 1ms) + max(peer_max_ack_delay, 25ms)))`
  with `peer_max_ack_delay` synchronized from negotiated QUIC transport
  parameters and `ACK_FREQUENCY` updates so delayed ACKs and coarse OS timer
  ticks never starve pacing, and preserves the configured rate across QUIC
  connection migrations. Rates are clamped to 125,000,000,000 bytes per
  second, and the RTT and ACK delay terms to at most 60 s. The call may be
  made from any thread: it posts to the network thread and returns at once,
  ignoring `0`, unknown or closed IDs and TCP IDs; sessions without `BRTL`
  are unaffected. The rate shapes only what the client sends. Chromium side:
  `patches/0005-quic-brutal.patch` and `BrutalSender` under `patches/src/`.
- **Session-level QUIC `connection_id` on bidirectional streams**:
  `Stream::connection_id` and `BidirectionalConn::connection_id`
  (`Cronet_BidirectionalStream_GetConnectionId`) now report `(1 << 63) | n` for
  HTTP/3 streams, uniquely identifying each `QuicChromiumClientSession` across
  multiplexed streams and UDP socket migrations while keeping stream-dialed TCP
  IDs (`1, 2, ...`, `(id & (1 << 63)) == 0`) disjoint and default OS-socket TCP
  streams at `0`. Both counters are process-wide.

### Changed

- **Releases carry every target**: the `release` workflow calls the
  `libcronet` workflow with `targets: all`, so each release publishes
  libcronet for all 30 targets instead of the 12 default ones.

## 0.2.0

### Added

- **Byte-stream dialer (`StreamDialer` / `Lower`, feature `tokio`)**:
  `EngineBuilder::stream_dialer` and `EngineBuilder::async_stream_dialer` let
  Chromium run HTTP/1.1 and HTTP/2 connections over any `AsyncRead + AsyncWrite`
  byte stream (`Cronet_Engine_SetStreamDialer`, `Cronet_LowerStream`,
  `Cronet_LowerStreamHandle_Notify`): Chromium no longer opens the TCP socket
  itself, the caller supplies the lower stream. Dialers and streams run on
  Cronet's network thread, inside the Tokio runtime current when the dialer
  was set. Each connection gets a non-zero, process-wide `connection_id`,
  exposed via `Target::connection_id`, `Stream::connection_id`, and
  `BidirectionalConn::connection_id`
  (`Cronet_BidirectionalStream_GetConnectionId`). Chromium side:
  `patches/0001-stream-dialer.patch`.
- **Synthetic HTTPS/ECH endpoints with strict mode (`Endpoint`)**:
  `EngineBuilder::endpoint`, `EngineBuilder::enable_endpoints`,
  `Engine::endpoint`, and `Engine::clear_endpoints`
  (`Cronet_Engine_SetEndpoint`, `Cronet_Engine_ClearEndpoints`) resolve
  hostnames in memory without querying DNS, attaching `ECHConfigList`, ALPN
  lists, and `strict` ECH enforcement (immediate `NetError::ECH_NOT_NEGOTIATED`
  failure when ECH is not accepted, with zero unencrypted fallback attempts and
  zero `retry_configs` retries). The resolver is installed at start by a
  stream dialer, an endpoint, or `enable_endpoints`; from then on every
  hostname resolves to a synthetic address, which only a stream dialer maps
  back to the hostname. Chromium side: `patches/0002-endpoint-ech.patch`.
- **Unified TLS configuration and standalone `tls::Client`**:
  `cronet::tls::Config` configures exclusive custom PEM root anchors,
  `verify_name` overrides, SHA-256 certificate and SPKI pins (which replace
  chain verification), client certificates (`client_identity`), ALPNs, ECH
  (`strict_ech`), and clock offsets across both `EngineBuilder::tls_config`
  (`Cronet_Engine_ConfigureTls`; the engine ignores `alpn` and `ech`) and
  `cronet::tls::Client` (`Cronet_TlsClient_*`, `Cronet_TlsConn_*`):
  `TlsStream` via `connect` / `connect_with` over any `Lower` stream on the
  engine's network thread, exposing `alpn()` and `ech_accepted()`; a failed
  handshake's `io::Error` wraps a `tls::HandshakeError` whose
  `ech_retry_configs` holds the server's retry configs when `strict_ech` is
  off. Chromium side: `patches/0003-tls-client.patch`.
- **Mach-O static archive symbol localization**: `cargo xtask package` now
  prelinks `libcronet.a` on Apple targets (`macOS`, `iOS`, `tvOS`, and
  simulators) with `-exported_symbols_list` (matching the existing ELF `ld -r`
  step on Linux and Android), localizing bundled BoringSSL and libc++ symbols
  while preserving `MH_SUBSECTIONS_VIA_SYMBOLS` for `-dead_strip` so `libcronet.a`
  links cleanly alongside external BoringSSL or OpenSSL crates with only
  `Cronet_*` and `bidirectional_stream_*` symbols global. Hand-written Apple
  assembly sources that omitted `.subsections_via_symbols` now emit it on both
  `arm64` and `x86_64` (`patches/0004-apple-subsections-via-symbols.patch`),
  and `cargo xtask package` verifies every input `.o` member carries
  `MH_SUBSECTIONS_VIA_SYMBOLS` before `ld -r`.
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
  `UrlRequest` now mark the stream or request done before invoking
  `on_succeeded`, `on_failed`, or `on_canceled`, so operations called inside or
  woken by a final callback consistently see it ended: stream operations fail
  with `StreamError::Closed`, and `UrlRequest::start` with
  `ApiError::IllegalStateRequestAlreadyStarted`.
- **Patches on Windows**: `*.patch` files are checked out with LF line endings
  (`.gitattributes`), and the naiveproxy tree is reset with
  `core.autocrlf=false` / `core.eol=lf` before patching, so the patches apply
  on Windows hosts with `core.autocrlf=true`.
- **Hidden Mach-O symbols**: the Apple prelink exports only symbols `nm`
  reports as `external`, not hidden (`private external`) helpers that
  `ld -r -exported_symbols_list` refuses to export.
