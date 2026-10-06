//! Tells rustc how to link libcronet, unless the `dynamic` feature opens it at
//! run time instead.
//!
//! - `CRONET_LIB_DIR`: a directory produced by `cargo xtask package`. It holds
//!   `libcronet.a` (static, with `cronet.link` listing the system libraries it
//!   needs), `libcronet.so` / `libcronet.dylib`, or on Windows `cronet.dll` and
//!   its import library `cronet.dll.lib`.
//! - `CRONET_LINK_KIND`: `static` or `dylib`, when the directory holds both.
//!
//! Without `CRONET_LIB_DIR`, `cronet` is linked from the linker's own path.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo::rerun-if-env-changed=CRONET_LIB_DIR");
    println!("cargo::rerun-if-env-changed=CRONET_LINK_KIND");
    if env::var_os("CARGO_FEATURE_DYNAMIC").is_some() {
        return;
    }

    let Some(directory) = env::var_os("CRONET_LIB_DIR").map(PathBuf::from) else {
        println!("cargo::rustc-link-lib=dylib=cronet");
        return;
    };
    println!("cargo::rerun-if-changed={}", directory.display());
    println!("cargo::rustc-link-search=native={}", directory.display());

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // Chromium builds Windows with a static CRT and its own libc++, which
        // only a DLL keeps apart from the Rust side: link its import library.
        println!("cargo::rustc-link-lib=dylib=cronet.dll");
        return;
    }

    let kind = env::var("CRONET_LINK_KIND").ok();
    let has_static = directory.join("libcronet.a").is_file();
    match kind.as_deref() {
        Some("static") | None if has_static => {
            println!("cargo::rustc-link-lib=static=cronet");
            link_system_libraries(&directory.join("cronet.link"));
        }
        Some("static") => panic!(
            "CRONET_LINK_KIND=static, but {} has no libcronet.a",
            directory.display()
        ),
        Some("dylib") | None => println!("cargo::rustc-link-lib=dylib=cronet"),
        Some(other) => panic!("CRONET_LINK_KIND must be `static` or `dylib`, not `{other}`"),
    }
}

/// `cronet.link` lists, one per line, what the static library needs from the
/// system: `lib=NAME` and `framework=NAME`. Linker flags (`arg=...`) cannot be
/// passed on from a dependency; `cargo xtask env` prints them for the final
/// build instead.
fn link_system_libraries(manifest: &std::path::Path) {
    println!("cargo::rerun-if-changed={}", manifest.display());
    let Ok(text) = fs::read_to_string(manifest) else { return };
    for line in text.lines().map(str::trim) {
        if let Some(library) = line.strip_prefix("lib=") {
            println!("cargo::rustc-link-lib=dylib={library}");
        } else if let Some(framework) = line.strip_prefix("framework=") {
            println!("cargo::rustc-link-lib=framework={framework}");
        }
    }
}
