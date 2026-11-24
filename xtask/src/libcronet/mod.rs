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
                } else if target.apple() {
                    prelink_apple(target, &archive, &out, &package.join("libcronet.a"))?;
                } else {
                    copy(&archive, &package.join("libcronet.a"))?;
                }
                if output == Output::StaticAndShared {
                    copy(&out.join("libcronet.so"), &package.join("libcronet.so"))?;
                }
                let ninja = fs::read_to_string(out.join("obj/components/cronet/cronet_sample.ninja"))
                    .context("reading the link line of cronet_sample")?;
                let mut manifest = link_manifest(&ninja);
                if target.apple() && !manifest.lines().any(|line| line == "lib=c++abi") {
                    // `prelink_apple` drops bundled `cxa_personality.o` so
                    // `___gxx_personality_v0` resolves to system `libc++abi`.
                    manifest.push_str("lib=c++abi\n");
                }
                fs::write(package.join("cronet.link"), manifest)?;
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

/// What of a Mach-O static libcronet stays global once prelinked: Cronet's C
/// API (`_Cronet_*` and `_bidirectional_stream_*`), with the leading Mach-O C
/// symbol underscore intact.
fn stays_global_apple(symbol: &str) -> bool {
    let Some(name) = symbol.strip_prefix('_') else {
        return false;
    };
    name.starts_with("Cronet_") || name.starts_with("bidirectional_stream_")
}

/// Extracts defined, publicly visible (`external`, not `private external`)
/// Mach-O global symbols from `xcrun nm -gU -m` output.
///
/// Mach-O sets `N_EXT` on both exported (`external`) and hidden
/// (`private external`, `N_PEXT`) symbols, so `nm -gU -j` includes hidden C++
/// helpers (such as non-`CRONET_EXPORT` `Cronet_Metrics_*_move` methods) that
/// `ld -r -exported_symbols_list` rejects with `cannot export hidden symbol`.
fn globals_apple(nm_macho: &str) -> Vec<&str> {
    let mut globals: Vec<&str> = nm_macho
        .lines()
        .filter_map(visible_external_apple)
        .filter(|symbol| stays_global_apple(symbol))
        .collect();
    globals.sort_unstable();
    globals.dedup();
    globals
}

fn visible_external_apple(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.ends_with(':') {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let [addr, section, middle @ .., symbol] = tokens.as_slice() else {
        return None;
    };
    if middle.is_empty() || !addr.bytes().all(|b| b.is_ascii_hexdigit()) || !section.starts_with('(') {
        return None;
    }
    if !middle.contains(&"external") || middle.contains(&"private") || middle.contains(&"non-external") {
        return None;
    }
    Some(symbol)
}

/// Parses `otool -l`'s `LC_BUILD_VERSION` block into `(platform, minos, sdk)`
/// for `ld -platform_version`.
fn apple_build_version(otool: &str) -> Result<(&'static str, String, String)> {
    let mut in_block = false;
    let mut platform: Option<&'static str> = None;
    let mut minos: Option<String> = None;
    let mut sdk: Option<String> = None;
    for line in otool.lines().map(str::trim) {
        if let Some(cmd) = line.strip_prefix("cmd ") {
            if in_block {
                break;
            }
            in_block = cmd.trim() == "LC_BUILD_VERSION";
            continue;
        }
        if !in_block {
            continue;
        }
        if let Some(raw) = line.strip_prefix("platform ") {
            platform = Some(match raw.trim().to_ascii_lowercase().as_str() {
                "1" | "macos" => "macos",
                "2" | "ios" => "ios",
                "3" | "tvos" => "tvos",
                "7" | "iossimulator" | "ios-simulator" => "ios-simulator",
                "8" | "tvossimulator" | "tvos-simulator" => "tvos-simulator",
                other => bail!("unsupported Mach-O platform `{other}` in LC_BUILD_VERSION"),
            });
        } else if let Some(raw) = line.strip_prefix("minos ") {
            minos = Some(raw.trim().to_owned());
        } else if let Some(raw) = line.strip_prefix("sdk ") {
            let trimmed = raw.trim();
            sdk = Some(if trimmed.is_empty() || trimmed == "n/a" || trimmed == "0.0" {
                String::new()
            } else {
                trimmed.to_owned()
            });
        }
    }
    let platform = platform.context("no LC_BUILD_VERSION platform in Mach-O object")?;
    let minos = minos.context("no LC_BUILD_VERSION minos in Mach-O object")?;
    let sdk = sdk.filter(|s| !s.is_empty()).unwrap_or_else(|| minos.clone());
    Ok((platform, minos, sdk))
}

/// Mach-O 64-bit little-endian header constants (`<mach-o/loader.h>`).
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_OBJECT: u32 = 0x1;
const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;

/// Returns whether `MH_SUBSECTIONS_VIA_SYMBOLS` is set on a 64-bit Mach-O
/// `MH_OBJECT` header.
fn macho_has_subsections_via_symbols(bytes: &[u8]) -> Result<bool> {
    if bytes.len() < 32 {
        bail!("Mach-O object header truncated ({} bytes)", bytes.len());
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let filetype = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    if magic != MH_MAGIC_64 || filetype != MH_OBJECT {
        bail!("unexpected Mach-O header (magic=0x{magic:08x}, filetype={filetype})");
    }
    let flags = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    Ok((flags & MH_SUBSECTIONS_VIA_SYMBOLS) != 0)
}

/// Verifies in a single pass over `archive_file` that every `.o` member carries
/// `MH_SUBSECTIONS_VIA_SYMBOLS`, returning an error naming all members that
/// omit it.
///
/// Even one input object without `MH_SUBSECTIONS_VIA_SYMBOLS` causes Apple's
/// `ld -r` to clear that flag on the entire merged relocatable object,
/// preventing `-dead_strip` in downstream builds from stripping unreachable
/// code.
fn verify_macho_archive_subsections_via_symbols(archive_label: &Path, archive_file: &Path) -> Result<()> {
    let bytes = fs::read(archive_file).with_context(|| format!("reading {}", archive_file.display()))?;
    if !bytes.starts_with(b"!<arch>\n") {
        bail!("{} is not a standard `ar` archive", archive_label.display());
    }

    let mut offset = 8usize;
    let mut gnu_strtab: &[u8] = &[];
    let mut missing = Vec::new();
    let mut checked = 0usize;

    while offset < bytes.len() {
        if offset % 2 == 1 {
            offset += 1;
            if offset >= bytes.len() {
                break;
            }
        }
        if bytes.len() - offset < 60 {
            bail!(
                "truncated `ar` member header at offset {offset} in {}",
                archive_label.display()
            );
        }
        let header = &bytes[offset..offset + 60];
        if &header[58..60] != b"`\n" {
            bail!(
                "invalid `ar` member header magic at offset {offset} in {}",
                archive_label.display()
            );
        }
        let raw_name = std::str::from_utf8(&header[0..16])
            .context("non-UTF-8 `ar` member name")?
            .trim_end_matches(' ');
        let size: usize = std::str::from_utf8(&header[48..58])
            .context("non-UTF-8 `ar` member size")?
            .trim()
            .parse()
            .context("invalid `ar` member size")?;
        offset += 60;
        if bytes.len() - offset < size {
            bail!(
                "truncated `ar` member payload ({size} bytes) in {}",
                archive_label.display()
            );
        }
        let payload = &bytes[offset..offset + size];
        offset += size;

        if raw_name == "//" {
            gnu_strtab = payload;
            continue;
        }
        let (name, obj_bytes) = if let Some(ext_len) = raw_name.strip_prefix("#1/") {
            let name_len: usize = ext_len.parse().context("invalid BSD `#1/` extended name length")?;
            if payload.len() < name_len {
                bail!(
                    "BSD `#1/{name_len}` name exceeds member size in {}",
                    archive_label.display()
                );
            }
            let name = String::from_utf8_lossy(&payload[..name_len])
                .trim_end_matches('\0')
                .to_owned();
            (name, &payload[name_len..])
        } else if let Some(off_str) = raw_name.strip_prefix('/')
            && !off_str.is_empty()
            && off_str.bytes().all(|b| b.is_ascii_digit())
        {
            let off: usize = off_str.parse().context("invalid GNU `ar` string table offset")?;
            let tail = gnu_strtab
                .get(off..)
                .context("GNU `ar` string table offset out of bounds")?;
            let end = tail
                .iter()
                .position(|&b| b == b'/' || b == b'\n' || b == 0)
                .unwrap_or(tail.len());
            (String::from_utf8_lossy(&tail[..end]).into_owned(), payload)
        } else {
            (raw_name.trim_end_matches('/').to_owned(), payload)
        };

        if name.is_empty() || name == "/" || name.starts_with("__.SYMDEF") {
            continue;
        }
        checked += 1;
        let has_flag = macho_has_subsections_via_symbols(obj_bytes)
            .with_context(|| format!("inspecting Mach-O member `{name}` in {}", archive_label.display()))?;
        if !has_flag {
            missing.push(name);
        }
    }

    if checked == 0 {
        bail!("no object members found in Mach-O archive {}", archive_label.display());
    }
    if !missing.is_empty() {
        bail!(
            "{} has {} Mach-O member(s) without MH_SUBSECTIONS_VIA_SYMBOLS (would disable -dead_strip after `ld -r`): {}",
            archive_label.display(),
            missing.len(),
            missing.join(", ")
        );
    }
    Ok(())
}

/// Prelinks a Mach-O `libcronet_static.a` into a single relocatable object via
/// Apple's `ld -r -exported_symbols_list` so Chromium's internal BoringSSL,
/// libc++ and support symbols become private and never collide with another
/// BoringSSL or C++ library linked into the same binary.
fn prelink_apple(target: &Target, archive: &Path, scratch: &Path, to: &Path) -> Result<()> {
    let arch = match target.gn_arg("target_cpu") {
        Some("arm64") => "arm64",
        Some("x64") => "x86_64",
        other => bail!("unsupported Apple target_cpu {other:?} for {target}"),
    };

    let input = scratch.join("libcronet_input.a");
    copy(archive, &input)?;
    let members = output(Command::new("xcrun").args(["ar", "-t"]).arg(&input))?;
    // Chromium's static archive bundles libc++abi's `cxa_personality.o`
    // (`___gxx_personality_v0`). Localizing it with `ld -r` would create a
    // private personality routine alongside the system `libc++abi.dylib`'s
    // `___gxx_personality_v0`, `base::apple::CxxPersonalityRoutine`, and a host
    // language's personality (such as `_rust_eh_personality`), exceeding
    // Mach-O's 3-slot compact unwind table limit. Dropping `cxa_personality.o`
    // lets `___gxx_personality_v0` resolve to `libSystem` as normal.
    if members.lines().any(|line| line.trim() == "cxa_personality.o") {
        run(Command::new("xcrun")
            .args(["ar", "d"])
            .arg(&input)
            .arg("cxa_personality.o"))?;
    }

    if let Err(err) = verify_macho_archive_subsections_via_symbols(archive, &input) {
        let _ = fs::remove_file(&input);
        return Err(err);
    }

    let defined = output(Command::new("xcrun").args(["nm", "-gU", "-m"]).arg(&input))?;
    let globals = globals_apple(&defined);
    if !globals.iter().any(|symbol| symbol.starts_with("_Cronet_")) {
        let _ = fs::remove_file(&input);
        bail!("{} defines none of Cronet's C API", archive.display());
    }

    let first_member = members
        .lines()
        .map(str::trim)
        .find(|name| name.ends_with(".o") && *name != "cxa_personality.o")
        .context("no object member found in Mach-O archive")?;
    let probe_bytes = Command::new("xcrun")
        .args(["ar", "-p"])
        .arg(&input)
        .arg(first_member)
        .output()
        .context("extracting Mach-O probe object")?;
    if !probe_bytes.status.success() {
        bail!("`xcrun ar -p` failed on {}", input.display());
    }
    let probe = scratch.join("libcronet_probe.o");
    fs::write(&probe, &probe_bytes.stdout)?;
    let headers = output(Command::new("xcrun").args(["otool", "-l"]).arg(&probe))?;
    let _ = fs::remove_file(&probe);
    let (platform, minos, sdk) = apple_build_version(&headers)?;

    let object = scratch.join("libcronet_prelinked.o");
    let list = scratch.join("libcronet_globals.txt");
    fs::write(&list, globals.join("\n") + "\n")?;
    let link_res = run(Command::new("xcrun")
        .args([
            "ld",
            "-r",
            "-arch",
            arch,
            "-platform_version",
            platform,
            &minos,
            &sdk,
            "-exported_symbols_list",
        ])
        .arg(&list)
        .args(globals.iter().flat_map(|symbol| ["-u", *symbol]))
        .arg(&input)
        .arg("-o")
        .arg(&object));
    let _ = fs::remove_file(&input);
    link_res?;

    let prelinked_hdr = fs::read(&object).with_context(|| format!("reading {}", object.display()))?;
    if !macho_has_subsections_via_symbols(&prelinked_hdr)? {
        let _ = fs::remove_file(&object);
        bail!(
            "{} lost MH_SUBSECTIONS_VIA_SYMBOLS during `ld -r`; downstream -dead_strip would break",
            object.display()
        );
    }

    let _ = fs::remove_file(to);
    let ar_res = run(Command::new("xcrun")
        .args(["libtool", "-static", "-D", "-o"])
        .arg(to)
        .arg(&object));
    let _ = fs::remove_file(&object);
    ar_res
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

    #[test]
    fn apple_globals_and_build_version() {
        let nm = [
            "",
            "libcronet_input.a(cronet_c.o):",
            "0000000000001d78 (__TEXT,__text) external _Cronet_Engine_Create",
            "0000000000000010 (__TEXT,__text) external [no dead strip] _bidirectional_stream_create",
            "0000000000000020 (__TEXT,__text) weak external _Cronet_Buffer_Create",
            "0000000000000030 (__TEXT,__text) external [cold func] _Cronet_Error_message_get",
            "0000000000002b04 (__TEXT,__text) private external _Cronet_Metrics_request_start_move",
            "0000000000002c00 (__TEXT,__text) weak private external _Cronet_Metrics_dns_start_move",
            "0000000000002d00 (__TEXT,__text) private external [cold func] _Cronet_Metrics_ssl_start_move",
            "0000000000000100 (__TEXT,__text) non-external _Cronet_Internal_Helper",
            "                 (undefined) external _Cronet_Undefined_Ref",
            "0000000000000200 (__TEXT,__text) external _SSL_new",
            "0000000000000300 (__TEXT,__text) external _malloc",
            "0000000000000400 (__TEXT,__text) external ___gxx_personality_v0",
            "0000000000001d78 (__TEXT,__text) external _Cronet_Engine_Create",
        ]
        .join("\n");
        assert_eq!(
            globals_apple(&nm),
            [
                "_Cronet_Buffer_Create",
                "_Cronet_Engine_Create",
                "_Cronet_Error_message_get",
                "_bidirectional_stream_create",
            ]
        );

        let macos_otool = "\
Load command 1
      cmd LC_BUILD_VERSION
  cmdsize 24
 platform 1
    minos 13.0
      sdk 27.0
   ntools 0
Load command 2
      cmd LC_SYMTAB
";
        assert_eq!(
            apple_build_version(macos_otool).unwrap(),
            ("macos", "13.0".to_owned(), "27.0".to_owned())
        );

        let sim_otool = "\
Load command 0
      cmd LC_BUILD_VERSION
  cmdsize 24
 platform 7
    minos 15.0
      sdk n/a
";
        assert_eq!(
            apple_build_version(sim_otool).unwrap(),
            ("ios-simulator", "15.0".to_owned(), "15.0".to_owned())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn prelink_apple_hides_internal_symbols_and_drops_cxa_personality() {
        let cases = [
            ("aarch64-apple-darwin", "macosx", "arm64-apple-macos13.0", "arm64"),
            ("x86_64-apple-darwin", "macosx", "x86_64-apple-macos13.0", "x86_64"),
            ("aarch64-apple-ios", "iphoneos", "arm64-apple-ios15.0", "arm64"),
            (
                "aarch64-apple-ios-sim",
                "iphonesimulator",
                "arm64-apple-ios15.0-simulator",
                "arm64",
            ),
            (
                "x86_64-apple-ios",
                "iphonesimulator",
                "x86_64-apple-ios15.0-simulator",
                "x86_64",
            ),
            ("aarch64-apple-tvos", "appletvos", "arm64-apple-tvos15.0", "arm64"),
            (
                "aarch64-apple-tvos-sim",
                "appletvsimulator",
                "arm64-apple-tvos15.0-simulator",
                "arm64",
            ),
            (
                "x86_64-apple-tvos",
                "appletvsimulator",
                "x86_64-apple-tvos15.0-simulator",
                "x86_64",
            ),
        ];

        for (triple, sdk_name, clang_target, clang_arch) in cases {
            let sdk_out = Command::new("xcrun")
                .args(["--sdk", sdk_name, "--show-sdk-path"])
                .output()
                .unwrap();
            if !sdk_out.status.success() {
                assert_ne!(sdk_name, "macosx", "macosx SDK must be available to test {triple}");
                continue;
            }
            let sdk_path = String::from_utf8(sdk_out.stdout).unwrap().trim().to_owned();

            let dir = std::env::temp_dir().join(format!("xtask-prelink-{triple}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();

            let target = Target::find(triple).unwrap();
            fs::write(
                dir.join("api.c"),
                "int SSL_new(void);\nint asm_helper(void);\n__attribute__((visibility(\"default\"))) int Cronet_Test_Entry(void) { return SSL_new() + asm_helper(); }\n__attribute__((visibility(\"default\"), cold)) int Cronet_Test_Cold(void) { return 7; }\n__attribute__((visibility(\"hidden\"))) void Cronet_Metrics_request_start_move(void) {}\n",
            )
            .unwrap();
            fs::write(
                dir.join("ssl.c"),
                "extern int UnusedExternal(void);\nint SSL_new(void) { return 41; }\nint DeadUnreachable(void) { return UnusedExternal(); }\n",
            )
            .unwrap();
            fs::write(
                dir.join("cxa_personality.c"),
                "int __gxx_personality_v0(void) { return 0; }\n",
            )
            .unwrap();
            // Assembly objects deliberately omitting `.subsections_via_symbols`
            // (both >16-char BSD `#1/` extended name and short name) must be
            // rejected by `prelink_apple` with every offending member named.
            let asm_no_flag_a = match clang_arch {
                "arm64" => ".text\n.globl _missing_a\n_missing_a:\n  mov w0, #1\n  ret\n",
                _ => ".text\n.globl _missing_a\n_missing_a:\n  movl $1, %eax\n  retq\n",
            };
            let asm_no_flag_b = match clang_arch {
                "arm64" => ".text\n.globl _missing_b\n_missing_b:\n  mov w0, #2\n  ret\n",
                _ => ".text\n.globl _missing_b\n_missing_b:\n  movl $2, %eax\n  retq\n",
            };
            let asm_with_flag = match clang_arch {
                "arm64" => ".text\n.globl _asm_helper\n_asm_helper:\n  mov w0, #1\n  ret\n.subsections_via_symbols\n",
                _ => ".text\n.globl _asm_helper\n_asm_helper:\n  movl $1, %eax\n  retq\n.subsections_via_symbols\n",
            };
            fs::write(dir.join("missing_alpha_asm.s"), asm_no_flag_a).unwrap();
            fs::write(dir.join("missing_b.s"), asm_no_flag_b).unwrap();
            fs::write(dir.join("asm_helper.s"), asm_with_flag).unwrap();

            for (src, obj) in [
                ("api.c", "api.o"),
                ("ssl.c", "ssl.o"),
                ("cxa_personality.c", "cxa_personality.o"),
                ("missing_alpha_asm.s", "missing_alpha_asm.o"),
                ("missing_b.s", "missing_b.o"),
                ("asm_helper.s", "asm_helper.o"),
            ] {
                run(Command::new("xcrun")
                    .args(["clang", "-c", "-target", clang_target, "-isysroot", &sdk_path])
                    .arg(dir.join(src))
                    .arg("-o")
                    .arg(dir.join(obj)))
                .unwrap();
            }

            let bad_raw = dir.join("libcronet_bad_static.a");
            run(Command::new("xcrun")
                .args(["ar", "rcs"])
                .arg(&bad_raw)
                .arg(dir.join("api.o"))
                .arg(dir.join("ssl.o"))
                .arg(dir.join("cxa_personality.o"))
                .arg(dir.join("missing_alpha_asm.o"))
                .arg(dir.join("missing_b.o")))
            .unwrap();
            let out = dir.join("libcronet.a");
            let err = prelink_apple(target, &bad_raw, &dir, &out).unwrap_err().to_string();
            assert!(
                err.contains("MH_SUBSECTIONS_VIA_SYMBOLS")
                    && err.contains("missing_alpha_asm.o")
                    && err.contains("missing_b.o")
                    && !err.contains("api.o"),
                "expected missing-flag error naming both members for {triple}, got: {err}"
            );

            let raw = dir.join("libcronet_static.a");
            run(Command::new("xcrun")
                .args(["ar", "rcs"])
                .arg(&raw)
                .arg(dir.join("api.o"))
                .arg(dir.join("ssl.o"))
                .arg(dir.join("cxa_personality.o"))
                .arg(dir.join("asm_helper.o")))
            .unwrap();

            prelink_apple(target, &raw, &dir, &out).unwrap();
            verify_macho_archive_subsections_via_symbols(&out, &out).unwrap();

            let globals_list = fs::read_to_string(dir.join("libcronet_globals.txt")).unwrap();
            assert_eq!(
                globals_list.lines().collect::<Vec<_>>(),
                ["_Cronet_Test_Cold", "_Cronet_Test_Entry"],
                "hidden Cronet_* helpers must not enter -exported_symbols_list or -u ({triple})"
            );
            let exported = output(Command::new("xcrun").args(["nm", "-gU", "-m"]).arg(&out)).unwrap();
            assert_eq!(
                globals_apple(&exported),
                ["_Cronet_Test_Cold", "_Cronet_Test_Entry"],
                "{triple}"
            );
            assert!(
                !exported.contains("private external"),
                "prelinked Mach-O archive for {triple} must not retain private external symbols: {exported}"
            );

            // Downstream `-dead_strip` must strip `DeadUnreachable` (and its
            // unresolved `_UnusedExternal` reference) thanks to preserved
            // `MH_SUBSECTIONS_VIA_SYMBOLS`.
            fs::write(
                dir.join("host.c"),
                "int Cronet_Test_Entry(void);\n__attribute__((visibility(\"default\"))) int host_entry(void) { return Cronet_Test_Entry(); }\n",
            )
            .unwrap();
            let dylib = dir.join("libhost.dylib");
            run(Command::new("xcrun")
                .args([
                    "clang",
                    "-dynamiclib",
                    "-target",
                    clang_target,
                    "-isysroot",
                    &sdk_path,
                    "-Wl,-dead_strip",
                ])
                .arg(dir.join("host.c"))
                .arg(&out)
                .arg("-o")
                .arg(&dylib))
            .unwrap();
            let undefs = output(Command::new("xcrun").args(["nm", "-u", "-j"]).arg(&dylib)).unwrap();
            assert!(!undefs.lines().any(|l| l.trim() == "_UnusedExternal"), "{triple}");

            let _ = fs::remove_dir_all(&dir);
        }
    }
}
