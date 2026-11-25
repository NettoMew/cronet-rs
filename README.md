# cronet-rs

Rust bindings to [Cronet], Chromium's network stack as a library, built from
[naiveproxy]: Chrome's TLS, HTTP/2 and QUIC, its connection pooling and
DNS, with additions for embedding it in custom transports — TCP/UDP socket and
in-memory byte-stream dialers, synthetic HTTPS/ECH endpoint registration,
unified TLS verification (exclusive roots, `verify_name`, SHA-256 pins, client
certificates), standalone TLS client streams on the engine's network thread,
per-session QUIC Brutal congestion control, and closing every connection on
demand.

| crate | what it is |
|---|---|
| [`cronet-sys`](crates/cronet-sys) | The C API, generated from the headers in `crates/cronet-sys/include`. Links libcronet, or (feature `dynamic`) opens it at run time. |
| [`cronet`](crates/cronet) | A safe API over it: engines, URL requests, bidirectional streams, Chromium's network errors. |
| [`xtask`](xtask) | Builds libcronet from the naiveproxy commit in `naiveproxy.lock`, packages it, regenerates the bindings, upgrades. |

## Using it

```toml
[dependencies]
cronet = { git = "https://github.com/NettoMew/cronet-rs", tag = "v0.3.0", features = ["tokio", "http"] }
```

| feature | adds |
|---|---|
| `dynamic` | Opens libcronet at run time instead of linking it, unless `CRONET_LINK_KIND` asks for it linked. |
| `tokio` | `BidirectionalConn`, byte-stream dialers (`EngineBuilder::stream_dialer` / `async_stream_dialer` over `Lower`), and `cronet::tls::TlsStream` (`tokio::io::AsyncRead + AsyncWrite`). |
| `http` | `cronet::http::Client`: requests and responses as `http::Request` / `http::Response`, runtime-agnostic. |

An HTTP request:

```rust
let client = cronet::http::Client::new()?;
let request = http::Request::get("https://example.com/").body(cronet::http::Body::empty())?;
let response = client.send(request).await?;
println!("{} {:?}", response.status(), response.into_body().bytes().await?);
```

A tunnel through an HTTP/2 proxy, with sockets the application dials itself:

```rust
use cronet::{BidirectionalConn, ConnOptions, Engine, EngineParams, NetError, Socket, StreamPriority};

let engine = Engine::builder()
    .dialer(|address| {
        std::net::TcpStream::connect(address).map(Socket::from).map_err(|e| NetError::from_io_error(&e))
    })
    .start(&EngineParams::new())?;

let mut tunnel = BidirectionalConn::new(&engine, ConnOptions { read_wait_headers: true, ..Default::default() });
tunnel.start(
    "CONNECT",
    "https://proxy.example:443",
    &[("-connect-authority", "example.com:443"), ("proxy-authorization", "Basic ...")],
    StreamPriority::Medium,
    false,
)?;
assert_eq!(tunnel.headers().await?.status(), Some(200));
// `tunnel` is now an AsyncRead + AsyncWrite byte stream.
```

HTTP/2 streams over any `AsyncRead + AsyncWrite` byte stream (`Lower`, without
Chromium owning an OS socket), with synthetic ECH endpoint metadata in strict
mode:

```rust
use cronet::{BidirectionalConn, ConnOptions, Endpoint, Engine, EngineParams, StreamPriority, tls};

let tls_cfg = tls::Config {
    root_certificates_pem: Some(ca_pem), // exclusive root set; ignores OS/Chrome roots
    strict_ech: true,
    ..tls::Config::default()
};
let engine = Engine::builder()
    .tls_config(&tls_cfg)?
    .endpoint("service.example", Endpoint {
        ech: ech_config_list.clone(),
        alpn: vec!["h2".into(), "http/1.1".into()],
        strict: true, // fail closed with ECH_NOT_NEGOTIATED; never retry without ECH
    })
    .async_stream_dialer(|target| async move {
        // Any `AsyncRead + AsyncWrite + Send + Unpin + 'static` stream works
        // (TCP, custom userspace transports, tunnels, or in-memory pipes).
        // `target.connection_id` matches `BidirectionalConn::connection_id()`.
        tokio::net::TcpStream::connect(("proxy.example", target.port)).await
    })
    .start(&EngineParams::new())?;

// Endpoints can also be added or rotated dynamically on a running engine:
engine.endpoint("alt.example", Endpoint {
    ech: ech_config_list.clone(),
    alpn: vec!["h2".into()],
    strict: true,
});

let mut stream = BidirectionalConn::new(&engine, ConnOptions::default());
stream.start("POST", "https://service.example/v1/stream", &[], StreamPriority::Medium, false)?;
let headers = stream.headers().await?;
println!("status={:?} conn_id={}", headers.status(), stream.connection_id());
```

Standalone TLS client (`cronet::tls::Client`) sharing an engine's network thread
and Chromium's `SSLClientSocket` handshake over caller-supplied streams:

```rust
use cronet::tls;

let tls_client = tls::Client::new(&engine, &tls_cfg)?;
let mut tls_stream = tls_client
    .connect_with("service.example", 8443, Some(&ech_config_list), lower_stream)
    .await?;
assert!(tls_stream.ech_accepted());
assert_eq!(tls_stream.alpn(), Some("h2"));
// `tls_stream` implements `tokio::io::AsyncRead + AsyncWrite`.
```

Per-session QUIC Brutal congestion control (`BRTL`), activated dynamically once
an HTTP/3 stream negotiates a target send rate:

```rust
let mut params = EngineParams::new();
params.set_enable_quic(true).set_quic_options("", "BRTL", 0, 0)?;
let engine = Engine::builder().start(&params)?;

let mut h3_stream = BidirectionalConn::new(&engine, ConnOptions::default());
h3_stream.start("POST", "https://quic.example/v1/stream", &[], StreamPriority::Medium, false)?;
let _headers = h3_stream.headers().await?;
// QUIC sessions report `(1 << 63) | n`; `0` falls back to BBR.
engine.set_quic_send_rate(h3_stream.connection_id(), 12_500_000);
```

Underneath, everything Cronet's C API offers is there: `UrlRequest` with a
`UrlRequestCallback`, uploads from an `UploadDataProvider`, `Executor`s,
request-finished listeners with metrics, `BidirectionalStream` with a
`StreamCallback`, NetLog, QUIC hints, public key pins, and typed setters for
the experimental options (async DNS, DNS server override, host resolver
rules, HTTPS records for ECH, HTTP/2 and QUIC windows, socket pool limits).
Callbacks run on Cronet's network thread or an `Executor`; every type may be
used from any thread.

## Getting libcronet

Each [release](https://github.com/NettoMew/cronet-rs/releases) carries
`libcronet-<triple>.tar.xz`: the library, `cronet.link` (what a static link
also needs), `VERSION`, and Chromium's `LICENSE`. Releases publish the default
targets (`x86_64`/`aarch64` Linux glibc and musl, `x86_64` Windows,
`x86_64`/`aarch64` macOS, `aarch64` iOS and simulator, and
`aarch64`/`x86_64`/`armv7` Android); `xtask` and the `libcronet` workflow
(`targets: all`) support the full table below.

| | targets |
|---|---|
| Linux (glibc) | `x86_64`, `i686`, `aarch64`, `armv7` (`gnueabihf`), `riscv64gc`, `loongarch64`, `mipsel`, `mips64el` (`gnuabi64`) |
| Linux (musl, static) | `x86_64`, `i686`, `aarch64`, `armv7` (`musleabihf`), `mipsel`, `riscv64gc`, `loongarch64` |
| Windows (DLL) | `x86_64`, `i686`, `aarch64` |
| macOS, iOS, tvOS | `x86_64`, `aarch64`, and the simulators |
| Android | `aarch64`, `x86_64`, `armv7`, `i686` |

Then either:

- **link it**: point `CRONET_LIB_DIR` at the unpacked directory. Linux and
  Apple targets link `libcronet.a` statically (set `CRONET_LINK_KIND=dylib`
  for `libcronet.so`); Windows links `cronet.dll` through its import library,
  and the DLL ships next to the executable. A static Linux link needs
  Chromium's clang and `lld`: `cargo xtask env --target <triple>` prints the
  settings. Without `CRONET_LIB_DIR`, `cronet` is linked from the linker's
  own path.

  On Linux, Android, and Apple platforms, `libcronet.a` is prelinked so that it
  keeps Chromium to itself, as `libcronet.so` does: only Cronet's C API is
  global in it (and, where Chromium's allocator is built in, the allocation
  functions it replaces), so its BoringSSL and libc++ link beside any other
  copy of theirs, such as `boring`'s or `openssl`'s.

- **load it** (feature `dynamic`): nothing is linked. The library is opened
  on first use from next to the executable or the system's library path, or
  explicitly with `cronet::load_library(path)`.

  The program being built has the last word: with `CRONET_LINK_KIND` set (as
  `cargo xtask env` sets it), the library is linked even where a dependency
  turned on `dynamic`, and is open from the start. A static executable, which
  can open nothing at run time, gets it that way.

## Building libcronet

```sh
cargo xtask build --target x86_64-unknown-linux-gnu   # several --target, or `all`
cargo xtask package --target x86_64-unknown-linux-gnu # into lib/<triple>/
eval "$(cargo xtask env --target x86_64-unknown-linux-gnu --export)"
```

The build first checks out the naiveproxy commit `naiveproxy.lock` names
into `naiveproxy/` (`cargo xtask fetch`, shallow, ignored by git; a large
part of Chromium, so nothing that merely depends on these crates downloads
it), then applies any `patches/*.patch` in lexical order and overlays
`patches/src/` onto `naiveproxy/src/` (stopping at once on a conflict and
naming the naiveproxy commit). It then runs naiveproxy's own `get-clang.sh`, which fetches Chromium's
clang, GN, PGO profiles, and the Debian, OpenWrt or Android sysroot the target
needs, then builds Cronet's `cronet_static` (and `cronet`, where Chromium
offers it) with naiveproxy's release configuration. Hosts are those
naiveproxy builds on: Linux for Linux, OpenWrt and Android; Windows for
Windows; macOS for Apple platforms. The [`libcronet`](.github/workflows/libcronet.yml)
workflow builds the standard release targets by default, or any subset (or
`all`) passed in its `targets` input.

`cargo xtask bindgen` regenerates `cronet-sys` from its headers, and
`cargo xtask net-errors` regenerates `cronet::NetError` from Chromium's
`net/base/net_error_list.h`.

## Versions and releases

`naiveproxy.lock` names the naiveproxy commit everything comes from: the
headers, the bindings, the network errors and every released library.
`cronet_sys::CHROMIUM_VERSION` names its Chromium release; a matching library
reports the same from `Engine::version`.

The [`release`](.github/workflows/release.yml) workflow keeps both moving:

- **Daily**, `cargo xtask upgrade` looks for a newer naiveproxy. By default it
  follows the commit SagerNet's cronet-go pins, which that project has built,
  tested and released; it never moves to an older Chromium. Run by hand, the
  workflow can follow a branch of the naiveproxy fork instead, such as
  `cronet-go-dev-v154`.
- An upgrade moves `naiveproxy.lock`, and brings along the headers, the
  bindings, the network error table and the crates' version: a new minor
  version when the C API changed, a patch otherwise. It is checked, then
  committed to `main`.
- **Any version without a tag**, from an upgrade or from a push that edits
  `Cargo.toml`, is released: libcronet is built for every target, and the
  release `v<version>` carries every package.

Locally, `cargo xtask upgrade [--branch <branch> | --to <commit>]` does the
same upgrade.

## Testing

```sh
cargo test --workspace --all-features   # tests needing the library skip without it
CRONET_LIBRARY=/path/to/libcronet.so cargo test --workspace --all-features
```

## License

cronet-rs is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT), at your option. libcronet itself is Chromium's
code, under its [BSD-style license](crates/cronet-sys/include/LICENSE), which
every packaged library carries.

## Related

[cronet-go](https://github.com/SagerNet/cronet-go) provides Go bindings to the
same naiveproxy build of Cronet.

[Cronet]: https://chromium.googlesource.com/chromium/src/+/main/components/cronet/
[naiveproxy]: https://github.com/klzgrad/naiveproxy
