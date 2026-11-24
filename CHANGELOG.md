# Changelog

## Unreleased

### Added

- **Patch layer in `xtask`**: `cargo xtask fetch` and `cargo xtask upgrade` now
  apply `patches/*.patch` in lexical order and overlay `patches/src/` onto the
  checked-out `naiveproxy` tree, failing immediately with the locked naiveproxy
  commit on conflict.
- **Target filtering in CI**: `.github/workflows/libcronet.yml` accepts a
  `targets` input (`default`, `all`, or a comma/space-separated list of Rust
  triples) on `workflow_dispatch` and `workflow_call`.
- **Byte-stream dialer (`StreamDialer` / `Lower`)**:
  `EngineBuilder::stream_dialer` and `EngineBuilder::async_stream_dialer` let
  Chromium run HTTP/1.1 and HTTP/2 connections over any `AsyncRead + AsyncWrite`
  stream without owning OS file descriptors, exposing per-connection IDs via
  `Target::connection_id`, `Stream::connection_id`, and
  `BidirectionalConn::connection_id`.
- **Synthetic HTTPS/ECH endpoints (`Endpoint`)**: `EngineBuilder::endpoint`,
  `EngineBuilder::enable_endpoints`, `Engine::endpoint`, and
  `Engine::clear_endpoints` resolve hostnames in-memory without querying DNS,
  attaching `ECHConfigList`, ALPN lists, and strict ECH enforcement (immediate
  `NetError::ECH_NOT_NEGOTIATED` failure without unencrypted fallback or
  `retry_configs` retry).
- **Unified TLS configuration and standalone `tls::Client`**:
  `cronet::tls::Config` configures exclusive custom PEM root anchors,
  `verify_name` overrides, SHA-256 certificate and SPKI pins, client
  certificates (`client_identity`), ALPNs, ECH, and clock offsets across both
  `EngineBuilder::tls_config` and `cronet::tls::Client` (`TlsStream` over any
  `Lower` stream on the engine's network thread).
