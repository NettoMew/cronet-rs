# cronet-rs

Rust bindings to [Cronet], Chromium's network stack as a library, built from
[naiveproxy]: Chrome's TLS, HTTP/2 and QUIC, its connection pooling and
DNS, with naiveproxy's additions for embedding it in a proxy — custom TCP and
UDP dialers, custom root certificates, and closing every connection on demand.

| crate | what it is |
|---|---|
| [`cronet-sys`](crates/cronet-sys) | The C API, generated from the headers in `crates/cronet-sys/include`. Links libcronet, or (feature `dynamic`) opens it at run time. |
| [`cronet`](crates/cronet) | A safe API over it: engines, URL requests, bidirectional streams, Chromium's network errors. |
| [`xtask`](xtask) | Builds libcronet from the naiveproxy commit in `naiveproxy.lock`, packages it, regenerates the bindings, upgrades. |

## Using it

```toml
[dependencies]
cronet = { git = "https://github.com/NettoMew/cronet-rs", features = ["tokio", "http"] }
```

| feature | adds |
|---|---|
| `dynamic` | Opens libcronet at run time instead of linking it, unless `CRONET_LINK_KIND` asks for it linked. |
| `tokio` | `BidirectionalConn`: a stream as `tokio::io::AsyncRead + AsyncWrite`. |
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
`libcronet-<triple>.tar.xz` for every target below: the library, `cronet.link`
(what a static link also needs), `VERSION`, and Chromium's `LICENSE`.

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
it). It then runs naiveproxy's own `get-clang.sh`, which fetches Chromium's
clang, GN, PGO profiles, and the Debian, OpenWrt or Android sysroot the target
needs, then builds Cronet's `cronet_static` (and `cronet`, where Chromium
offers it) with naiveproxy's release configuration. Hosts are those
naiveproxy builds on: Linux for Linux, OpenWrt and Android; Windows for
Windows; macOS for Apple platforms. The [`libcronet`](.github/workflows/libcronet.yml)
workflow builds them all.

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
