# Patches

`cargo xtask fetch` (and so `build`, `package` and `upgrade`) checks out the
naiveproxy commit in `naiveproxy.lock`, applies every `*.patch` here with
`git apply` in lexical order, then copies `src/` over `naiveproxy/src/`. A
patch that no longer applies stops the build, naming the naiveproxy commit.
Patches are kept with LF line endings (`.gitattributes`), and the checkout
is reset with `core.autocrlf=false`, so they apply on Windows too.

The patches edit existing Chromium files; new files live in `src/`. The C
declarations they add to `components/cronet/native/include/cronet_c.h` are
what `crates/cronet-sys/include/cronet_c.h` carries, and their comments
document the C API.

| patch | what it does | new files in `src/` |
|---|---|---|
| `0001-stream-dialer.patch` | `Cronet_Engine_SetStreamDialer`: TCP connections over embedder-provided `Cronet_LowerStream`s instead of sockets, woken through `Cronet_LowerStreamHandle_Notify`. Each connection gets a process-wide `connection_id` (1, 2, ...), reported by `Cronet_BidirectionalStream_GetConnectionId`. | `components/cronet/native/stream_dialer.{h,cc}` |
| `0002-endpoint-ech.patch` | `Cronet_Engine_SetEndpoint` / `Cronet_Engine_ClearEndpoints`: an in-memory resolver giving hosts synthetic addresses and HTTPS-record metadata (`ECHConfigList`, ALPNs), with a strict mode in which a rejected ECH handshake fails with `ERR_ECH_NOT_NEGOTIATED` instead of retrying. A stream dialer gets the hostname back from the synthetic address. | `components/cronet/native/endpoint_resolver.{h,cc}` |
| `0003-tls-client.patch` | `Cronet_TlsConfig`, `Cronet_Engine_ConfigureTls` (exclusive roots, `verify_name`, certificate and SPKI pins, client certificate, strict ECH, clock offset for the engine), and `Cronet_TlsClient_*` / `Cronet_TlsConn_*`: Chromium's `SSLClientSocket` over a `Cronet_LowerStream` on the engine's network thread. | `components/cronet/native/tls_client.{h,cc}` |
| `0004-apple-subsections-via-symbols.patch` | Adds `.subsections_via_symbols` to the Apple assembly sources that lacked it, so every object in `libcronet.a` keeps `MH_SUBSECTIONS_VIA_SYMBOLS` and `-dead_strip` still works after `cargo xtask package` prelinks the archive with `ld -r`. | |
| `0005-quic-brutal.patch` | QUIC Brutal congestion control: the `BRTL` connection option selects `BrutalSender`, and `Cronet_Engine_SetQuicSendRate` sets a session's rate. QUIC sessions get `connection_id`s `(1 << 63) \| n`. | `net/third_party/quiche/src/quiche/quic/core/congestion_control/brutal_sender{.h,.cc,_test.cc}` |

`BrutalSender` delegates to BBR until a session has a non-zero rate. With a
rate, it paces at `rate / ack_rate`, where `ack_rate` is the share of packets
acknowledged over a 5-second window (used from 50 samples on, floored at
0.8, so at most 1.25 times the rate), and keeps a congestion window of
`2 × paced rate × (max(srtt, 1 ms) + max(peer max_ack_delay, 25 ms))`, at
least 10 full-size packets. Setting the rate back to 0 returns the session
to BBR.
