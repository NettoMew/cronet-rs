//! Building libcronet from naiveproxy, checked out at the locked commit
//! (see [`crate::lock`]) into `naiveproxy/`.
//!
//! naiveproxy's own scripts do the heavy lifting: `get-clang.sh` fetches
//! Chromium's clang, GN, PGO profiles, the NDK, and the Debian or OpenWrt
//! sysroot a target builds against, and `get-sysroot.sh` says where that
//! sysroot is. What is left here is to choose GN arguments for Cronet's
//! libraries rather than for the `naive` binary, to build them, and to
//! package them where `cronet-sys` can link them.

mod targets;

use std::{fs, path::Path, process::Command};

use anyhow::{Context, Result, bail};

pub(crate) use targets::Target;
use targets::{Output, TARGETS};

use crate::{Workspace, bindgen, lock, output, run};

/// Which targets a command works on.
#[derive(clap::Args)]
pub(crate) struct Targets {
    /// A Rust target triple; repeat for several, or `all`. Defaults to this
    /// machine's.
    #[arg(short, long = "target", value_name = "TRIPLE")]
    triples: Vec<String>,
}

impl Targets {
    pub(crate) fn resolve(&self) -> Result<Vec<&'static Target>> {
        if self.triples.is_empty() {
            return Ok(vec![Target::host()?]);
        }
        if self.triples.iter().any(|triple| triple == "all") {
            return Ok(TARGETS.iter().collect());
        }
        self.triples.iter().map(|triple| Target::find(triple)).collect()
    }

    pub(crate) fn resolve_one(&self) -> Result<&'static Target> {
        match self.resolve()?.as_slice() {
            [target] => Ok(target),
            _ => bail!("give exactly one --target"),
        }
    }
}

/// Runs one of naiveproxy's scripts in its source tree, for `target`.
///
/// They are POSIX shell scripts. `sh`, not `bash`: on Windows, programs are
/// looked up in System32 before `PATH`, and the `bash` there is WSL's, while
/// the only `sh` is Git's.
fn script(workspace: &Workspace, target: &Target, script: &str) -> Command {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(script)
        .current_dir(workspace.src_root())
        .env("EXTRA_FLAGS", target.gn);
    match target.openwrt {
        Some(openwrt) => command.env("OPENWRT_FLAGS", openwrt),
        None => command.env_remove("OPENWRT_FLAGS"),
    };
    command
}

/// The sysroot `target` builds against, relative to the source tree, as
/// naiveproxy's `get-sysroot.sh` decides it; empty when there is none.
fn sysroot(workspace: &Workspace, target: &Target) -> Result<String> {
    let sysroot = output(&mut script(
        workspace,
        target,
        r#". ./get-sysroot.sh >/dev/null && printf %s "$WITH_SYSROOT""#,
    ))?;
    Ok(sysroot.trim().to_owned())
}

fn out_dir(target: &Target) -> String {
    format!("out/cronet-{}", target.triple)
}

/// Fetches what building `targets` needs, without building.
pub(crate) fn toolchain(workspace: &Workspace, targets: &[&Target]) -> Result<()> {
    lock::fetch(workspace)?;
    for target in targets {
        eprintln!("[xtask] fetching the toolchain for {target}");
        run(&mut script(workspace, target, "./get-clang.sh"))?;
    }
    Ok(())
}

/// The GN arguments of a libcronet build: naiveproxy's release arguments
/// (`build.sh`), less what only suits a self-contained executable, plus the
/// target's own.
fn gn_args(workspace: &Workspace, target: &Target) -> Result<String> {
    let mut args = vec![
        // A release build, as naiveproxy's.
        "is_official_build=true",
        "is_chrome_branded=true",
        "exclude_unwind_tables=true",
        "enable_resource_allowlist_generation=false",
        "symbol_level=0",
        "is_clang=true",
        "use_sysroot=false",
        "fatal_linker_warnings=false",
        "treat_warnings_as_errors=false",
        "use_clang_modules=false",
        // Cronet, without the parts of the browser it does not use.
        "is_cronet_build=true",
        "use_udev=false",
        "use_aura=false",
        "use_ozone=false",
        "use_gio=false",
        "use_glib=false",
        "use_platform_icu_alternatives=true",
        "is_perfetto_embedder=true",
        "disable_file_support=true",
        "enable_websockets=false",
        "use_kerberos=false",
        "disable_zstd_filter=false",
        "enable_mdns=false",
        "enable_reporting=false",
        "include_transport_security_state_preload_list=false",
        "enable_device_bound_sessions=false",
        "enable_bracketed_proxy_uris=true",
        "enable_quic_proxy_support=true",
        "enable_disk_cache_sql_backend=false",
        "use_nss_certs=false",
        "enable_backup_ref_ptr_support=false",
        "enable_dangling_raw_ptr_checks=false",
        // A library other linkers consume: plain object code, so no LTO, and
        // so no control-flow integrity, which needs it.
        "use_thin_lto=false",
        "is_cfi=false",
        "use_cfi_icall=false",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();

    let os = target.gn_arg("target_os");
    // Optimized with the profiles `get-clang.sh` fetches, which it does for
    // every platform but iOS.
    args.push(format!("chrome_pgo_phase={}", if os == Some("ios") { 0 } else { 2 }));
    match os {
        Some("mac") => args.extend(
            [
                "mac_allow_system_xcode_for_official_builds_for_testing=true",
                "enable_dsyms=false",
            ]
            .map(Into::into),
        ),
        Some("ios") => args.extend(["ios_enable_code_signing=false", "enable_dsyms=false"].map(Into::into)),
        Some("android") => {
            args.extend(["is_desktop_android=true", "default_min_sdk_version=24"].map(Into::into));
            // Chromium defines the version codes `is_high_end_android` reads
            // for 64-bit CPUs only; `//components/cronet` imports them.
            if matches!(target.gn_arg("target_cpu"), Some("arm64" | "x64")) {
                args.push("is_high_end_android=true".into());
            }
        }
        _ => {}
    }

    let sysroot = sysroot(workspace, target)?;
    if !sysroot.is_empty() {
        args.push(format!("target_sysroot=\"//{sysroot}\""));
    }
    let wrapper = if cfg!(windows) { "sccache" } else { "ccache" };
    if Command::new(wrapper)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        args.push(format!("cc_wrapper=\"{wrapper}\""));
    }
    args.push(target.gn.to_owned());
    Ok(args.join(" "))
}

/// Builds libcronet for each of `targets`.
pub(crate) fn build(workspace: &Workspace, targets: &[&Target]) -> Result<()> {
    for target in targets {
        toolchain(workspace, &[target])?;
        let out = out_dir(target);
        let gn = workspace
            .src_root()
            .join(if cfg!(windows) { "gn/out/gn.exe" } else { "gn/out/gn" });
        eprintln!("[xtask] gn gen {out}");
        run(Command::new(gn)
            .args(["gen", &out, &format!("--args={}", gn_args(workspace, target)?)])
            .current_dir(workspace.src_root())
            // Visual Studio, not depot_tools' packaged toolchain.
            .env("DEPOT_TOOLS_WIN_TOOLCHAIN", "0"))?;
        let ninja_targets: &[&str] = match target.output() {
            Output::Dll => &["cronet"],
            Output::StaticAndShared => &["cronet_static", "cronet"],
            Output::Static => &["cronet_static"],
        };
        eprintln!("[xtask] ninja -C {out} {}", ninja_targets.join(" "));
        run(Command::new("ninja")
            .args(["-C", &out])
            .args(ninja_targets)
            .current_dir(workspace.src_root()))?;
    }
    Ok(())
}

/// The headers `cronet-sys` binds, in the source tree.
pub(crate) const HEADERS: [&str; 4] = [
    "components/cronet/native/include/cronet_c.h",
    "components/cronet/native/include/cronet_export.h",
    "components/cronet/native/generated/cronet.idl_c.h",
    "components/grpc_support/include/bidirectional_stream_c.h",
];

/// Copies the headers and the Chromium version into `cronet-sys`
/// (regenerating its bindings), and each target's libraries into
/// `lib/<triple>/`.
pub(crate) fn package(workspace: &Workspace, targets: &[&Target]) -> Result<()> {
    lock::fetch(workspace)?;
    for header in HEADERS {
        let name = Path::new(header).file_name().expect("headers are files");
        copy(&workspace.src_root().join(header), &workspace.sys_include().join(name))?;
    }
    let version = fs::read_to_string(workspace.naive_root().join("CHROMIUM_VERSION"))?;
    fs::write(
        workspace.sys_include().join("CHROMIUM_VERSION"),
        format!("{}\n", version.trim()),
    )?;
    bindgen::run(workspace)?;

    for target in targets {
        let out = workspace.src_root().join(out_dir(target));
        let package = workspace.lib_root().join(target.triple);
        if package.exists() {
            fs::remove_dir_all(&package)?;
        }
        fs::create_dir_all(&package)?;
        match target.output() {
            Output::Dll => {
                copy(&out.join("cronet.dll"), &package.join("cronet.dll"))?;
                copy(&out.join("cronet.dll.lib"), &package.join("cronet.dll.lib"))?;
            }
            output => {
                let archive = out.join("obj/components/cronet/libcronet_static.a");
                if target.elf() {
                    prelink(workspace, &archive, &out, &package.join("libcronet.a"))?;
                } else {
                    copy(&archive, &package.join("libcronet.a"))?;
                }
                if output == Output::StaticAndShared {
                    copy(&out.join("libcronet.so"), &package.join("libcronet.so"))?;
                }
                let ninja = fs::read_to_string(out.join("obj/components/cronet/cronet_sample.ninja"))
                    .context("reading the link line of cronet_sample")?;
                fs::write(package.join("cronet.link"), link_manifest(&ninja))?;
            }
        }
        fs::write(package.join("VERSION"), version.trim())?;
        // The library is Chromium's, under its BSD license, which travels with it.
        copy(&workspace.naive_root().join("LICENSE"), &package.join("LICENSE"))?;
        eprintln!("[xtask] packaged {}", package.display());
    }
    Ok(())
}

/// The C library's allocation functions, as Chromium's allocator shim
/// replaces them in a program that links it statically
/// (`allocator_shim_override_libc_symbols.h`, and for glibc
/// `allocator_shim_override_glibc_weak_symbols.h`).
const SHIM: [&str; 21] = [
    "aligned_alloc",
    "calloc",
    "cfree",
    "free",
    "malloc",
    "malloc_size",
    "malloc_usable_size",
    "memalign",
    "posix_memalign",
    "pvalloc",
    "realloc",
    "valloc",
    "__libc_calloc",
    "__libc_cfree",
    "__libc_free",
    "__libc_malloc",
    "__libc_memalign",
    "__libc_pvalloc",
    "__libc_realloc",
    "__libc_valloc",
    "__posix_memalign",
];

/// What of a static libcronet stays global once it is prelinked: Cronet's C
/// API, and what Chromium means the whole program to use, its allocator
/// shim's replacements of the C library's allocation functions and their
/// `__wrap_` forms, which the `-wrap` flags in Android's `cronet.link` name.
fn stays_global(symbol: &str) -> bool {
    symbol.starts_with("Cronet_")
        || symbol.starts_with("bidirectional_stream_")
        || symbol.starts_with("__wrap_")
        || SHIM.contains(&symbol)
}

/// The symbols in `nm`'s list that stay global, each once, in order.
fn globals(nm: &str) -> Vec<&str> {
    let mut globals: Vec<&str> = nm
        .lines()
        .map(str::trim)
        .filter(|symbol| stays_global(symbol))
        .collect();
    globals.sort_unstable();
    globals.dedup();
    globals
}

/// `libcronet_static.a` made as self-contained as `libcronet.so`: the
/// members a program would take from it, linked into one object, with every
/// symbol made local but those that [stay global](stays_global). Its
/// BoringSSL, its libc++ and the rest of Chromium then meet no other copy of
/// theirs in the program (another BoringSSL, say), and what the API never
/// reaches, such as code calling into parts of Chromium the build leaves
/// out, never comes in. Nor are COMDAT groups left in it: a linker keeps one
/// group of each name in a program, and could keep another object's in place
/// of one whose code the object, its symbols now local, still calls.
/// `scratch` holds what is made on the way.
///
/// Chromium's own `lld` and LLVM tools do it: they read the CREL relocations
/// its clang writes for most Linux CPUs, as whatever links the result must.
fn prelink(workspace: &Workspace, archive: &Path, scratch: &Path, to: &Path) -> Result<()> {
    let tool = |name: &str| {
        workspace
            .src_root()
            .join("third_party/llvm-build/Release+Asserts/bin")
            .join(name)
    };
    let defined = output(
        Command::new(tool("llvm-nm"))
            .args(["--defined-only", "--extern-only", "--format=just-symbols", "--quiet"])
            .arg(archive),
    )?;
    let globals = globals(&defined);
    if !globals.iter().any(|symbol| symbol.starts_with("Cronet_")) {
        bail!("{} defines none of Cronet's C API", archive.display());
    }
    let object = scratch.join("libcronet_prelinked.o");
    let list = scratch.join("libcronet_globals.txt");
    fs::write(&list, globals.join("\n") + "\n")?;
    // As a program linking the archive would take its members: those that
    // define what it asks for, and what they need in turn.
    run(Command::new(tool("ld.lld"))
        .args(["-r", "--force-group-allocation"])
        .args(globals.iter().flat_map(|symbol| ["-u", symbol]))
        .arg(archive)
        .arg("-o")
        .arg(&object))?;
    run(Command::new(tool("llvm-objcopy"))
        .arg(format!("--keep-global-symbols={}", list.display()))
        .arg(&object))?;
    run(Command::new(tool("llvm-ar")).arg("rcsD").arg(to).arg(&object))
}

fn copy(from: &Path, to: &Path) -> Result<()> {
    fs::copy(from, to).with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    Ok(())
}

/// What linking the static library needs besides it, for `cronet-sys`'s
/// build script: one `lib=NAME`, `framework=NAME` or `arg=FLAG` per line.
///
/// Chromium's `cronet_sample` exists for this: its link line in its ninja
/// file is that of a program linking `cronet_static`. Only the allocator
/// shim's `-Wl,-wrap,` flags matter among its linker flags.
fn link_manifest(ninja: &str) -> String {
    let mut manifest = String::new();
    let value = |line: &str, key: &str| {
        line.trim()
            .strip_prefix(key)?
            .trim_start()
            .strip_prefix('=')
            .map(str::to_owned)
    };
    for line in ninja.lines() {
        if let Some(libs) = value(line, "libs") {
            for lib in libs.split_whitespace().filter(|lib| !lib.ends_with(".lds")) {
                match lib.strip_prefix("-l") {
                    Some(name) if !name.starts_with(':') => manifest.push_str(&format!("lib={name}\n")),
                    _ => manifest.push_str(&format!("arg={lib}\n")),
                }
            }
        } else if let Some(frameworks) = value(line, "frameworks") {
            let mut words = frameworks.split_whitespace();
            while let Some(word) = words.next() {
                if word == "-framework"
                    && let Some(name) = words.next()
                {
                    manifest.push_str(&format!("framework={name}\n"));
                }
            }
        } else if let Some(ldflags) = value(line, "ldflags") {
            for flag in ldflags.split_whitespace().filter(|flag| flag.starts_with("-Wl,-wrap,")) {
                manifest.push_str(&format!("arg={flag}\n"));
            }
        }
    }
    manifest
}

/// Prints what a Cargo build for `target` needs to link the packaged
/// library: `CRONET_LIB_DIR`, and for Linux the linker and sysroot of the
/// build, since the library expects Chromium's clang and `lld`.
pub(crate) fn env(workspace: &Workspace, target: &Target, export: bool) -> Result<()> {
    lock::fetch(workspace)?;
    let package = workspace.lib_root().join(target.triple);
    // The kind named, so that the library is linked even into a program
    // whose dependencies ask `cronet` to open it at run time.
    let kind = match target.output() {
        Output::Dll => "dylib",
        Output::StaticAndShared | Output::Static => "static",
    };
    let mut variables = vec![
        ("CRONET_LIB_DIR".to_owned(), package.display().to_string()),
        ("CRONET_LINK_KIND".to_owned(), kind.to_owned()),
    ];

    let manifest = fs::read_to_string(package.join("cronet.link")).unwrap_or_default();
    let mut link_args: Vec<String> = manifest
        .lines()
        .filter_map(|line| line.strip_prefix("arg="))
        .map(str::to_owned)
        .collect();

    let cargo_target = target.triple.to_uppercase().replace('-', "_");
    if let Some(clang_target) = target.clang {
        let sysroot = workspace.src_root().join(sysroot(workspace, target)?);
        let clang = workspace
            .src_root()
            .join("third_party/llvm-build/Release+Asserts/bin/clang");
        let flags = format!("--target={clang_target} --sysroot={}", sysroot.display());
        let cc_target = target.triple.replace('-', "_");
        variables.push((format!("CC_{cc_target}"), format!("{} {flags}", clang.display())));
        variables.push((format!("CXX_{cc_target}"), format!("{}++ {flags}", clang.display())));
        variables.push((
            format!("CARGO_TARGET_{cargo_target}_LINKER"),
            clang.display().to_string(),
        ));
        variables.push(("QEMU_LD_PREFIX".to_owned(), sysroot.display().to_string()));
        let mut linker = vec![
            format!("--target={clang_target}"),
            format!("--sysroot={}", sysroot.display()),
        ];
        linker.push("-fuse-ld=lld".to_owned());
        linker.append(&mut link_args);
        link_args = linker;
    }
    if !link_args.is_empty() {
        let flags: Vec<String> = link_args.iter().map(|arg| format!("-C link-arg={arg}")).collect();
        variables.push((format!("CARGO_TARGET_{cargo_target}_RUSTFLAGS"), flags.join(" ")));
    }

    for (name, value) in variables {
        if export {
            println!("export {name}={}", shell_quote(&value));
        } else {
            println!("{name}={value}");
        }
    }
    Ok(())
}

/// `value` as one shell word.
fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:+,".contains(c))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_manifest_keeps_what_linking_needs() {
        let ninja = "\
defines = -DFOO
ldflags = -Wl,--gc-sections -Wl,-wrap,malloc -fuse-ld=lld
libs = -ldl -lpthread obj/build/linker.lds -l:libunwind.a
frameworks = -framework Foundation -framework Security
";
        assert_eq!(
            link_manifest(ninja),
            "arg=-Wl,-wrap,malloc\nlib=dl\nlib=pthread\narg=-l:libunwind.a\nframework=Foundation\nframework=Security\n"
        );
    }

    #[test]
    fn what_stays_global() {
        // As `llvm-nm --format=just-symbols` lists an archive: a blank line
        // and a header before each member's symbols.
        let nm = [
            "",
            "libcronet_static.a(cronet_c.o):",
            "Cronet_Engine_Create",
            "bidirectional_stream_create",
            "SSL_new",
            "_ZNSt4__Cr12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev",
            "_Znwm",
            "malloc",
            "__libc_malloc",
            "__wrap_strdup",
            "Cronet_Engine_Create",
        ]
        .join("\n");
        assert_eq!(
            globals(&nm),
            [
                "Cronet_Engine_Create",
                "__libc_malloc",
                "__wrap_strdup",
                "bidirectional_stream_create",
                "malloc",
            ]
        );
    }

    #[test]
    fn shell_words() {
        assert_eq!(shell_quote("/opt/lib-dir"), "/opt/lib-dir");
        assert_eq!(shell_quote("clang --target=x"), "'clang --target=x'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
