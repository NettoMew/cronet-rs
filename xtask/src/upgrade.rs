//! `cargo xtask upgrade`: moves the naiveproxy pin to a newer commit, and
//! everything derived from it along: the headers and Chromium version in
//! `cronet-sys`, its bindings, the network error table, and the crates'
//! version.
//!
//! Which commit? By default, the one SagerNet's cronet-go pins: it builds,
//! tests and releases each naiveproxy commit it moves to, so following it
//! means following commits known to work. `--branch` takes the head of a
//! branch of the naiveproxy fork instead, such as a newer
//! `cronet-go-dev-v<major>`; `--to` takes a given commit.
//!
//! The files come straight from GitHub at the new commit, so naiveproxy, a
//! large part of Chromium, never has to be checked out; the new commit goes
//! into `naiveproxy.lock`.

use std::{env, fs, io::Write as _, path::Path, process::Command, sync::LazyLock};

use anyhow::{Context, Result, bail};
use regex::Regex;

use crate::{Workspace, bindgen, libcronet, lock::Lock, net_errors, output};

/// The project whose naiveproxy pin is followed by default.
const REFERENCE: &str = "SagerNet/cronet-go";

static VERSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^version = "(\d+)\.(\d+)\.(\d+)"$"#).unwrap());

/// Where to move to.
pub(crate) enum Source {
    /// The commit [`REFERENCE`] pins.
    Reference,
    /// The head of a branch of the naiveproxy fork.
    Branch(String),
    /// A given commit.
    Commit(String),
}

pub(crate) fn run(workspace: &Workspace, source: Source) -> Result<()> {
    let mut lock = Lock::read(workspace)?;
    let (url, current) = (lock.repository.clone(), lock.commit.clone());
    let target = match &source {
        Source::Reference => reference_pin()?,
        Source::Branch(branch) => branch_head(&url, branch)?,
        Source::Commit(commit) => commit.clone(),
    };
    if target == current {
        eprintln!("[xtask] naiveproxy is already at {}", short(&current));
        return report(&[("changed", "false")]);
    }

    let raw = raw_base(&url, &target)?;
    let fetch = |path: &str| output(Command::new("curl").args(["-fsSL", &format!("{raw}/{path}")]));
    let chromium = fetch("CHROMIUM_VERSION")?.trim().to_owned();
    let installed = fs::read_to_string(workspace.sys_include().join("CHROMIUM_VERSION"))?;
    if chromium_order(&chromium) < chromium_order(installed.trim()) && !matches!(source, Source::Commit(_)) {
        eprintln!(
            "[xtask] {} has Chromium {chromium}, older than {}; staying at {}",
            short(&target),
            installed.trim(),
            short(&current)
        );
        return report(&[("changed", "false")]);
    }
    eprintln!(
        "[xtask] upgrading naiveproxy from {} to {} (Chromium {chromium})",
        short(&current),
        short(&target)
    );

    let bindings = workspace.root().join("crates/cronet-sys/src/bindings.rs");
    let before = fs::read_to_string(&bindings)?;
    for header in libcronet::HEADERS {
        let name = Path::new(header).file_name().expect("headers are files");
        fs::write(workspace.sys_include().join(name), fetch(&format!("src/{header}"))?)?;
    }
    fs::write(
        workspace.sys_include().join("CHROMIUM_VERSION"),
        format!("{chromium}\n"),
    )?;
    bindgen::run(workspace)?;

    let scratch = workspace.root().join("target/xtask");
    fs::create_dir_all(&scratch)?;
    let net_error_list = scratch.join("net_error_list.h");
    fs::write(&net_error_list, fetch("src/net/base/net_error_list.h")?)?;
    net_errors::run(workspace, Some(net_error_list))?;

    lock.commit.clone_from(&target);
    lock.write(workspace)?;

    // A changed C API may change what the crates offer: a breaking version.
    // Otherwise only the library moved: a patch.
    let api_changed = fs::read_to_string(&bindings)? != before;
    let version = bump(&workspace.root().join("Cargo.toml"), api_changed)?;
    eprintln!(
        "[xtask] crates now {version}{}",
        if api_changed { "; the C API changed" } else { "" }
    );
    report(&[
        ("changed", "true"),
        ("commit", &target),
        ("chromium", &chromium),
        ("version", &version),
        ("api_changed", if api_changed { "true" } else { "false" }),
    ])
}

fn short(commit: &str) -> &str {
    &commit[..commit.len().min(12)]
}

/// `150.0.7871.63` as numbers, to compare versions.
fn chromium_order(version: &str) -> Vec<u64> {
    version.split('.').map(|part| part.parse().unwrap_or(0)).collect()
}

/// The commit [`REFERENCE`]'s default branch pins its `naiveproxy` at, through
/// GitHub's API (with `GITHUB_TOKEN`, when set, for its higher rate limit).
fn reference_pin() -> Result<String> {
    let mut curl = Command::new("curl");
    curl.args(["-fsSL", "-H", "Accept: application/vnd.github+json"]);
    if let Ok(token) = env::var("GITHUB_TOKEN") {
        curl.args(["-H", &format!("Authorization: Bearer {token}")]);
    }
    let response = output(curl.arg(format!("https://api.github.com/repos/{REFERENCE}/contents/naiveproxy")))?;
    let entry: serde_json::Value = serde_json::from_str(&response)?;
    match (entry["type"].as_str(), entry["sha"].as_str()) {
        (Some("submodule"), Some(commit)) => Ok(commit.to_owned()),
        _ => bail!("{REFERENCE} has no naiveproxy submodule: {response}"),
    }
}

/// The newest commit of `branch` at `url`.
fn branch_head(url: &str, branch: &str) -> Result<String> {
    let line = output(Command::new("git").args(["ls-remote", url, &format!("refs/heads/{branch}")]))?;
    line.split_whitespace()
        .next()
        .map(str::to_owned)
        .with_context(|| format!("{url} has no branch {branch}"))
}

/// Where GitHub serves a repository's files at `commit`.
fn raw_base(url: &str, commit: &str) -> Result<String> {
    let repository = url
        .strip_prefix("https://github.com/")
        .map(|path| path.trim_end_matches(".git"))
        .with_context(|| format!("not a GitHub repository: {url}"))?;
    Ok(format!("https://raw.githubusercontent.com/{repository}/{commit}"))
}

/// Raises the workspace version, and the version the crates depend on each
/// other by; returns the new one.
fn bump(manifest: &Path, breaking: bool) -> Result<String> {
    let text = fs::read_to_string(manifest)?;
    let captures = VERSION.captures(&text).context("no workspace version")?;
    let [major, minor, patch] = [1, 2, 3].map(|index| captures[index].parse::<u64>().expect("digits"));
    let old = format!("{major}.{minor}.{patch}");
    let new = next_version((major, minor, patch), breaking);
    let text = VERSION.replace(&text, format!(r#"version = "{new}""#));
    let dependency = format!(r#"path = "crates/cronet-sys", version = "{old}""#);
    if !text.contains(&dependency) {
        bail!("{} does not depend on cronet-sys {old}", manifest.display());
    }
    fs::write(
        manifest,
        text.replace(
            &dependency,
            &format!(r#"path = "crates/cronet-sys", version = "{new}""#),
        ),
    )?;
    Ok(new)
}

/// Below 1.0 the minor version is the one that breaks, as Cargo reads it.
fn next_version((major, minor, patch): (u64, u64, u64), breaking: bool) -> String {
    match (major, breaking) {
        (0, true) => format!("0.{}.0", minor + 1),
        (0, false) => format!("0.{minor}.{}", patch + 1),
        (major, true) => format!("{}.0.0", major + 1),
        (major, false) => format!("{major}.{minor}.{}", patch + 1),
    }
}

/// Prints the outcome, and hands it to GitHub Actions when running there.
fn report(pairs: &[(&str, &str)]) -> Result<()> {
    for (key, value) in pairs {
        println!("{key}={value}");
    }
    if let Some(path) = env::var_os("GITHUB_OUTPUT") {
        let mut file = fs::OpenOptions::new().append(true).open(path)?;
        for (key, value) in pairs {
            writeln!(file, "{key}={value}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_move_by_what_changed() {
        assert_eq!(next_version((0, 1, 0), false), "0.1.1");
        assert_eq!(next_version((0, 1, 4), true), "0.2.0");
        assert_eq!(next_version((1, 2, 3), false), "1.2.4");
        assert_eq!(next_version((1, 2, 3), true), "2.0.0");
    }

    #[test]
    fn chromium_versions_compare_as_numbers() {
        assert!(chromium_order("154.0.8037.49") > chromium_order("150.0.7871.63"));
        assert!(chromium_order("150.0.7871.100") > chromium_order("150.0.7871.63"));
        assert!(chromium_order("143.0.7499.109") < chromium_order("150.0.7871.63"));
    }

    #[test]
    fn bumps_the_workspace_and_the_dependency() {
        let directory = env::temp_dir().join(format!("xtask-bump-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let manifest = directory.join("Cargo.toml");
        fs::write(
            &manifest,
            "[workspace.package]\nversion = \"0.1.0\"\nrust-version = \"1.88\"\n\n[workspace.dependencies]\n\
             cronet-sys = { path = \"crates/cronet-sys\", version = \"0.1.0\" }\n",
        )
        .unwrap();
        assert_eq!(bump(&manifest, false).unwrap(), "0.1.1");
        let text = fs::read_to_string(&manifest).unwrap();
        assert!(text.contains("version = \"0.1.1\"\nrust-version = \"1.88\""), "{text}");
        assert!(text.contains("version = \"0.1.1\" }"), "{text}");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn raw_urls() {
        assert_eq!(
            raw_base("https://github.com/SagerNet/naiveproxy.git", "abc").unwrap(),
            "https://raw.githubusercontent.com/SagerNet/naiveproxy/abc"
        );
        assert!(raw_base("git@example.com:x.git", "abc").is_err());
    }
}
