//! The targets libcronet is built for, named by their Rust target triples,
//! and how naiveproxy's build describes each.

use std::fmt;

use anyhow::{Result, bail};

/// One target: a Rust triple, and the build settings that make libcronet for
/// it. The settings follow naiveproxy's CI (`.github/workflows/build.yml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Target {
    /// The Rust target triple, which also names the build and its package.
    pub(crate) triple: &'static str,
    /// GN arguments selecting the target: what naiveproxy's scripts read as
    /// `EXTRA_FLAGS`.
    pub(crate) gn: &'static str,
    /// For OpenWrt targets, the SDK whose musl sysroot they build against:
    /// what naiveproxy's scripts read as `OPENWRT_FLAGS`.
    pub(crate) openwrt: Option<&'static str>,
    /// What clang calls the target, for Linux targets linked with Chromium's
    /// clang against the build's sysroot.
    pub(crate) clang: Option<&'static str>,
}

/// GN arguments for a statically linked musl build, as naiveproxy's
/// `-static` OpenWrt builds use: Rust links musl targets statically.
macro_rules! openwrt_static {
    ($gn:literal) => {
        concat!(
            $gn,
            " build_static=true use_allocator_shim=false use_partition_alloc=false"
        )
    };
}

pub(crate) const TARGETS: &[Target] = &[
    // Linux, against Debian sysroots.
    linux(
        "x86_64-unknown-linux-gnu",
        r#"target_os="linux" target_cpu="x64""#,
        "x86_64-linux-gnu",
    ),
    linux(
        "i686-unknown-linux-gnu",
        r#"target_os="linux" target_cpu="x86""#,
        "i686-linux-gnu",
    ),
    linux(
        "aarch64-unknown-linux-gnu",
        r#"target_os="linux" target_cpu="arm64""#,
        "aarch64-linux-gnu",
    ),
    linux(
        "armv7-unknown-linux-gnueabihf",
        r#"target_os="linux" target_cpu="arm""#,
        "arm-linux-gnueabihf",
    ),
    linux(
        "riscv64gc-unknown-linux-gnu",
        r#"target_os="linux" target_cpu="riscv64""#,
        "riscv64-linux-gnu",
    ),
    linux(
        "loongarch64-unknown-linux-gnu",
        r#"target_os="linux" target_cpu="loong64""#,
        "loongarch64-linux-gnu",
    ),
    linux(
        "mipsel-unknown-linux-gnu",
        r#"target_os="linux" target_cpu="mipsel""#,
        "mipsel-linux-gnu",
    ),
    linux(
        "mips64el-unknown-linux-gnuabi64",
        r#"target_os="linux" target_cpu="mips64el""#,
        "mips64el-linux-gnuabi64",
    ),
    // Linux with musl, against OpenWrt SDKs.
    Target {
        triple: "x86_64-unknown-linux-musl",
        gn: openwrt_static!(r#"target_os="openwrt" target_cpu="x64""#),
        openwrt: Some("arch=x86_64 release=24.10.0 gcc_ver=13.3.0 target=x86 subtarget=64"),
        clang: Some("x86_64-openwrt-linux-musl"),
    },
    Target {
        triple: "i686-unknown-linux-musl",
        gn: openwrt_static!(r#"target_os="openwrt" target_cpu="x86""#),
        openwrt: Some("arch=x86 release=24.10.0 gcc_ver=13.3.0 target=x86 subtarget=geode"),
        clang: Some("i486-openwrt-linux-musl"),
    },
    Target {
        triple: "aarch64-unknown-linux-musl",
        gn: openwrt_static!(r#"target_os="openwrt" target_cpu="arm64""#),
        openwrt: Some("arch=aarch64_generic release=24.10.0 gcc_ver=13.3.0 target=layerscape subtarget=armv8_64b"),
        clang: Some("aarch64-openwrt-linux-musl"),
    },
    Target {
        triple: "armv7-unknown-linux-musleabihf",
        gn: openwrt_static!(
            r#"target_os="openwrt" target_cpu="arm" arm_version=0 arm_cpu="cortex-a7" arm_fpu="neon-vfpv4" arm_float_abi="hard" arm_use_neon=true"#
        ),
        openwrt: Some("arch=arm_cortex-a7_neon-vfpv4 release=24.10.0 gcc_ver=13.3.0 target=sunxi subtarget=cortexa7"),
        clang: Some("arm-openwrt-linux-musleabi"),
    },
    Target {
        triple: "mipsel-unknown-linux-musl",
        gn: openwrt_static!(r#"target_os="openwrt" target_cpu="mipsel" mips_arch_variant="r2" mips_float_abi="soft""#),
        openwrt: Some("arch=mipsel_24kc release=24.10.0 gcc_ver=13.3.0 target=ramips subtarget=rt305x"),
        clang: Some("mipsel-openwrt-linux-musl"),
    },
    Target {
        triple: "riscv64gc-unknown-linux-musl",
        gn: openwrt_static!(r#"target_os="openwrt" target_cpu="riscv64""#),
        openwrt: Some("arch=riscv64 release=23.05.0 gcc_ver=12.3.0 target=sifiveu subtarget=generic"),
        clang: Some("riscv64-openwrt-linux-musl"),
    },
    Target {
        triple: "loongarch64-unknown-linux-musl",
        gn: openwrt_static!(r#"target_os="openwrt" target_cpu="loong64""#),
        openwrt: Some("arch=loongarch64 release=24.10.0 gcc_ver=13.3.0 target=loongarch64 subtarget=generic"),
        clang: Some("loongarch64-openwrt-linux-musl"),
    },
    // Windows.
    other("x86_64-pc-windows-msvc", r#"target_os="win" target_cpu="x64""#),
    other("i686-pc-windows-msvc", r#"target_os="win" target_cpu="x86""#),
    other("aarch64-pc-windows-msvc", r#"target_os="win" target_cpu="arm64""#),
    // macOS.
    other("x86_64-apple-darwin", r#"target_os="mac" target_cpu="x64""#),
    other("aarch64-apple-darwin", r#"target_os="mac" target_cpu="arm64""#),
    // Android.
    other("aarch64-linux-android", r#"target_os="android" target_cpu="arm64""#),
    other("x86_64-linux-android", r#"target_os="android" target_cpu="x64""#),
    other("armv7-linux-androideabi", r#"target_os="android" target_cpu="arm""#),
    other("i686-linux-android", r#"target_os="android" target_cpu="x86""#),
    // iOS and tvOS.
    other(
        "aarch64-apple-ios",
        r#"target_os="ios" target_cpu="arm64" target_environment="device""#,
    ),
    other(
        "aarch64-apple-ios-sim",
        r#"target_os="ios" target_cpu="arm64" target_environment="simulator""#,
    ),
    other(
        "x86_64-apple-ios",
        r#"target_os="ios" target_cpu="x64" target_environment="simulator""#,
    ),
    other(
        "aarch64-apple-tvos",
        r#"target_os="ios" target_platform="tvos" target_cpu="arm64" target_environment="device""#,
    ),
    other(
        "aarch64-apple-tvos-sim",
        r#"target_os="ios" target_platform="tvos" target_cpu="arm64" target_environment="simulator""#,
    ),
    other(
        "x86_64-apple-tvos",
        r#"target_os="ios" target_platform="tvos" target_cpu="x64" target_environment="simulator""#,
    ),
];

const fn linux(triple: &'static str, gn: &'static str, clang: &'static str) -> Target {
    Target {
        triple,
        gn,
        openwrt: None,
        clang: Some(clang),
    }
}

const fn other(triple: &'static str, gn: &'static str) -> Target {
    Target {
        triple,
        gn,
        openwrt: None,
        clang: None,
    }
}

/// What a target's build produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Output {
    /// `cronet.dll` and its import library: Windows.
    Dll,
    /// `libcronet.a`, and `libcronet.so` alongside: Linux with glibc.
    StaticAndShared,
    /// `libcronet.a` alone.
    Static,
}

impl Target {
    /// The target's value for a GN argument such as `target_os`.
    pub(crate) fn gn_arg(&self, name: &str) -> Option<&'static str> {
        let prefix = format!("{name}=\"");
        self.gn
            .split(' ')
            .find_map(|argument| argument.strip_prefix(prefix.as_str())?.strip_suffix('"'))
    }

    /// Whether its objects are ELF: Linux's, OpenWrt's and Android's.
    pub(crate) fn elf(&self) -> bool {
        matches!(self.gn_arg("target_os"), Some("linux" | "openwrt" | "android"))
    }

    /// What its build produces: Chromium's `cronet` shared library exists for
    /// Windows and Linux only, and a static musl build cannot make one.
    pub(crate) fn output(&self) -> Output {
        match self.gn_arg("target_os") {
            Some("win") => Output::Dll,
            Some("linux") => Output::StaticAndShared,
            _ => Output::Static,
        }
    }

    /// The target, by triple.
    pub(crate) fn find(triple: &str) -> Result<&'static Self> {
        match TARGETS.iter().find(|target| target.triple == triple) {
            Some(target) => Ok(target),
            None => bail!(
                "no libcronet build for {triple}; known targets: {}",
                TARGETS
                    .iter()
                    .map(|target| target.triple)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// The target this machine runs: what a build without `--target` makes.
    pub(crate) fn host() -> Result<&'static Self> {
        let triple = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", arch) => format!("{}-unknown-linux-gnu", arch),
            ("windows", arch) => format!("{arch}-pc-windows-msvc"),
            ("macos", arch) => format!("{arch}-apple-darwin"),
            (os, arch) => bail!("no libcronet build for {arch} {os} hosts"),
        };
        let triple = triple.replace("x86-", "i686-").replace("riscv64-", "riscv64gc-");
        Self::find(&triple)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.triple)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triples_are_unique_and_parse() {
        for (index, target) in TARGETS.iter().enumerate() {
            assert!(
                TARGETS[..index].iter().all(|other| other.triple != target.triple),
                "{target}"
            );
            assert!(target.gn_arg("target_os").is_some(), "{target}");
            assert!(target.gn_arg("target_cpu").is_some(), "{target}");
            assert_eq!(
                target.openwrt.is_some(),
                target.gn_arg("target_os") == Some("openwrt"),
                "{target}"
            );
        }
    }

    #[test]
    fn outputs() {
        assert_eq!(Target::find("x86_64-pc-windows-msvc").unwrap().output(), Output::Dll);
        assert_eq!(
            Target::find("aarch64-unknown-linux-gnu").unwrap().output(),
            Output::StaticAndShared
        );
        assert_eq!(
            Target::find("aarch64-unknown-linux-musl").unwrap().output(),
            Output::Static
        );
        assert_eq!(
            Target::find("aarch64-apple-ios-sim")
                .unwrap()
                .gn_arg("target_environment"),
            Some("simulator")
        );
        assert!(Target::find("sparc-sun-solaris").is_err());
    }

    #[test]
    fn elf() {
        for (triple, elf) in [
            ("x86_64-unknown-linux-gnu", true),
            ("aarch64-unknown-linux-musl", true),
            ("aarch64-linux-android", true),
            ("aarch64-apple-darwin", false),
            ("x86_64-pc-windows-msvc", false),
        ] {
            assert_eq!(Target::find(triple).unwrap().elf(), elf, "{triple}");
        }
    }

    #[test]
    fn host_is_known() {
        assert!(Target::host().is_ok());
    }
}
