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

Every example below is compiled as a doctest (`no_run`): `cargo test --doc -p cronet --features tokio,http`.

An HTTP request:

```rust,no_run
async fn get() -> Result<(), Box<dyn std::error::Error>> {
    let client = cronet::http::Client::new()?;
    let request = http::Request::get("https://example.com/").body(cronet::http::Body::empty())?;
    let response = client.send(request).await?;
    println!("{} {:?}", response.status(), response.into_body().bytes().await?);
    Ok(())
}
```

A tunnel through an HTTP/2 proxy, with sockets the application dials itself:

```rust,no_run
use cronet::{BidirectionalConn, ConnOptions, Engine, EngineParams, NetError, Socket, StreamPriority};

async fn tunnel() -> Result<(), Box<dyn std::error::Error>> {
    let engine = Engine::builder()
        .dialer(|address| {
            std::net::TcpStream::connect(address).map(Socket::from).map_err(|e| NetError::from_io_error(&e))
        })
        .start(&EngineParams::new())?;

    let tunnel = BidirectionalConn::new(&engine, ConnOptions { read_wait_headers: true, ..Default::default() });
    tunnel.start(
        "CONNECT",
        "https://proxy.example.com:443",
        &[("-connect-authority", "example.com:443"), ("proxy-authorization", "Basic ...")],
        StreamPriority::Medium,
        false,
    )?;
    assert_eq!(tunnel.headers().await?.status(), Some(200));
    // `tunnel` is now an AsyncRead + AsyncWrite byte stream.
    Ok(())
}
```

### Byte-stream dialers

With a stream dialer (feature `tokio`), Chromium does not open TCP sockets:
for each connection it calls the dialer with a `Target` (host, port and a
`connection_id`) and runs HTTP/1.1, HTTP/2 and TLS over the
`AsyncRead + AsyncWrite` stream it gets back: a TCP stream, a tunnel, an
in-memory pipe. Each stream on that connection reports the same
`connection_id`. `stream_dialer` takes a function that returns the stream at
once; `async_stream_dialer` takes one that returns a future of it:

```rust,no_run
use cronet::{BidirectionalConn, ConnOptions, Engine, EngineParams, StreamPriority};

async fn over_a_relay() -> Result<(), Box<dyn std::error::Error>> {
    let engine = Engine::builder()
        .async_stream_dialer(|target| async move {
            // Any `AsyncRead + AsyncWrite + Send + Unpin + 'static` stream works.
            println!("dialing {}:{} as connection {}", target.host, target.port, target.connection_id);
            tokio::net::TcpStream::connect(("relay.example.com", 8443)).await
        })
        .start(&EngineParams::new())?;

    let stream = BidirectionalConn::new(&engine, ConnOptions::default());
    stream.start("POST", "https://service.example.com/v1/stream", &[("content-type", "application/octet-stream")], StreamPriority::Medium, false)?;
    let headers = stream.headers().await?;
    println!("status={:?} connection_id={}", headers.status(), stream.connection_id());
    Ok(())
}
```

A stream dialer also turns on the in-memory resolver described next, so no
hostname goes to DNS.

### ECH endpoints

An `Endpoint` gives a hostname an `ECHConfigList`, ALPNs and a strict flag,
as an HTTPS DNS record would, without a DNS query. With `strict`, a server
that rejects ECH fails the connection with `NetError::ECH_NOT_NEGOTIATED`:
no retry without ECH, none with the server's retry configs. Registering an
endpoint before `start` (or `enable_endpoints`, or a stream dialer) installs
the in-memory resolver; after that, every hostname resolves to a synthetic
address that only a stream dialer maps back to the name, so pair endpoints
with a stream dialer. `Engine::endpoint` adds or replaces entries while the
engine runs.

```rust,no_run
use cronet::{BidirectionalConn, ConnOptions, Endpoint, Engine, EngineParams, StreamPriority, tls};

async fn with_ech(ca_pem: String, ech_config_list: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let engine = Engine::builder()
        .tls_config(&tls::Config {
            root_certificates_pem: Some(ca_pem), // the only roots; ignores the OS's and Chrome's
            ..tls::Config::default()
        })?
        .endpoint("service.example.com", Endpoint {
            ech: ech_config_list.clone(),
            alpn: vec!["h2".into()],
            strict: true,
        })
        .async_stream_dialer(|target| async move { tokio::net::TcpStream::connect((target.host, target.port)).await })
        .start(&EngineParams::new())?;

    // Rotate the configuration later:
    engine.endpoint("service.example.com", Endpoint { ech: ech_config_list, alpn: vec!["h2".into()], strict: true });

    let stream = BidirectionalConn::new(&engine, ConnOptions::default());
    stream.start("GET", "https://service.example.com/", &[("accept", "*/*")], StreamPriority::Medium, true)?;
    println!("{:?}", stream.headers().await?.status());
    Ok(())
}
```

`tls::Config` sets how the engine verifies servers: exclusive roots,
`verify_name` (check certificates against another name, still sending the
host as SNI), SHA-256 certificate and SubjectPublicKeyInfo pins (which
replace chain verification), a client certificate, `strict_ech` for every
host, and a clock offset.

### Standalone TLS

`tls::Client` runs Chromium's TLS client (the same `SSLClientSocket`, with
ECH, ALPN, pins and client certificates) over any `Lower` stream, on the
engine's network thread, without HTTP:

```rust,no_run
use cronet::{Engine, tls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn tls_only(engine: &Engine, ech_config_list: &[u8]) -> std::io::Result<()> {
    let client = tls::Client::new(engine, tls::Config {
        alpn: vec!["h2".into()],
        strict_ech: true,
        ..tls::Config::default()
    })?;
    let tcp = tokio::net::TcpStream::connect(("service.example.com", 443)).await?;
    let mut stream = client.connect_with("service.example.com", 443, Some(ech_config_list), tcp).await?;
    assert!(stream.ech_accepted());
    assert_eq!(stream.alpn(), Some("h2"));
    stream.write_all(b"ping").await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    Ok(())
}
```

A failed handshake's `io::Error` carries a `tls::HandshakeError`
(`HandshakeError::from_io_error`), with the server's ECH retry configs when
`strict_ech` is off.

### QUIC Brutal

`BRTL` in the client connection options selects the Brutal congestion
controller for the engine's QUIC sessions. It behaves as BBR until
`Engine::set_quic_send_rate` gives a session a rate in bytes per second;
from then on it sends at that rate, raised by the measured loss (up to
1.25 times) instead of backing off. `0` hands the session back to BBR. A QUIC
session's `connection_id` is `(1 << 63) | n`, shared by every stream on it;
TCP connections from a stream dialer count 1, 2, ... with the high bit
clear.

```rust,no_run
use cronet::{BidirectionalConn, ConnOptions, Engine, EngineParams, QuicHint, StreamPriority};

async fn brutal() -> Result<(), Box<dyn std::error::Error>> {
    let mut params = EngineParams::new();
    params
        .set_enable_quic(true)
        .add_quic_hint(&QuicHint::with("quic.example.com", 443, 443))
        .set_quic_options("", "BRTL", 0, 0)?;
    let engine = Engine::start(&params)?;

    let upload = BidirectionalConn::new(&engine, ConnOptions::default());
    upload.start("POST", "https://quic.example.com/upload", &[("-force-quic", "on")], StreamPriority::Medium, false)?;
    upload.headers().await?;
    let id = upload.connection_id();
    assert_ne!(id & (1 << 63), 0, "an HTTP/3 session");
    engine.set_quic_send_rate(id, 12_500_000); // 100 Mbit/s, for this session's uploads
    Ok(())
}
```

The rate shapes what this side sends; the server's sending is its own.

### Threads and lifetimes

- Everything may be used from any thread. Callbacks, dialers and the
  `Lower` streams handed to Cronet run on Cronet's network thread, which
  serves the whole engine: they must not block, and must not panic (a panic
  cannot unwind into Cronet and aborts the process).
- `Engine` is a cheap clone. Requests, streams, `tls::Client`s and TLS
  streams each keep it alive; when the last is gone it shuts down, waiting
  for the network thread (from another thread if dropped on it).
- Dialers, `tls_config`, root certificates and `enable_endpoints` are set on
  `EngineBuilder`, before `start`. `Engine::endpoint` works while running,
  but only on an engine started with the resolver in place.
- A stream dialer enters the Tokio runtime that was current when
  `stream_dialer` / `async_stream_dialer` was called, and
  `tls::Client::connect` the one current at the call; keep that runtime
  alive as long as the connections.
- `tls::Client::new` blocks until the network thread has built its verifier.
  Dropping a `connect` future abandons the handshake; dropping a `TlsStream`
  closes it and its lower stream. Its `poll_shutdown` sends no `close_notify`.
- `connection_id()` is known once a stream is ready or has its headers, and
  stays readable after it ends. `set_quic_send_rate` posts to the network
  thread and returns at once; IDs of closed sessions, of TCP connections, or
  of sessions without `BRTL` change nothing.

Underneath, everything Cronet's C API offers is there: `UrlRequest` with a
`UrlRequestCallback`, uploads from an `UploadDataProvider`, `Executor`s,
request-finished listeners with metrics, `BidirectionalStream` with a
`StreamCallback`, NetLog, QUIC hints, public key pins, and typed setters for
the experimental options (async DNS, DNS server override, host resolver
rules, HTTPS records for ECH, HTTP/2 and QUIC windows, socket pool limits).
The C additions behind the features above are in `cronet_c.h`
(`Cronet_Engine_SetStreamDialer`, `Cronet_Engine_SetEndpoint`,
`Cronet_Engine_ConfigureTls`, `Cronet_TlsClient_*`, `Cronet_TlsConn_*`,
`Cronet_Engine_SetQuicSendRate`), documented there and in `cronet-sys`.

## Getting libcronet

Each [release](https://github.com/NettoMew/cronet-rs/releases) carries
`libcronet-<triple>.tar.xz`: the library, `cronet.link` (what a static link
also needs), `VERSION`, and Chromium's `LICENSE`, for every one of the 30
targets below (the release workflow builds with `targets: all`).

| | targets |
|---|---|
| Linux (glibc) | `x86_64`, `i686`, `aarch64`, `armv7` (`gnueabihf`), `riscv64gc`, `loongarch64`, `mipsel`, `mips64el` (`gnuabi64`) |
| Linux (musl, static) | `x86_64`, `i686`, `aarch64`, `armv7` (`musleabihf`), `mipsel`, `riscv64gc`, `loongarch64` |
| Windows (DLL) | `x86_64`, `i686`, `aarch64` |
| macOS | `x86_64`, `aarch64` |
| iOS, tvOS | `aarch64`, and the `aarch64` and `x86_64` simulators |
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
naming the naiveproxy commit; [`patches/README.md`](patches/README.md) says
what each patch does). It then runs naiveproxy's own `get-clang.sh`, which fetches Chromium's
clang, GN, PGO profiles, and the Debian, OpenWrt or Android sysroot the target
needs, then builds Cronet's `cronet_static` (and `cronet`, where Chromium
offers it) with naiveproxy's release configuration. Hosts are those
naiveproxy builds on: Linux for Linux, OpenWrt and Android; Windows for
Windows; macOS for Apple platforms. The [`libcronet`](.github/workflows/libcronet.yml)
workflow builds what its `targets` input names: `default` (or nothing) for
12 common targets (`x86_64`/`aarch64` Linux glibc and musl, `aarch64`/`x86_64`/`armv7`
Android, `x86_64` Windows, `x86_64`/`aarch64` macOS, `aarch64` iOS and its
simulator), `all`, or a comma- or space-separated list of triples.

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
  `Cargo.toml`, is released: libcronet is built for every target
  (`targets: all`), and the release `v<version>` carries every package.

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
