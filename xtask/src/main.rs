//! Maintenance tasks for cronet-rs: `cargo xtask <command>`.
//!
//! `bindgen` and `net-errors` regenerate checked-in sources, and `upgrade`
//! moves to a newer naiveproxy with everything derived from it. `toolchain`,
//! `build`, `package` and `env` build libcronet from the `naiveproxy`
//! submodule with naiveproxy's own scripts, and package it under `lib/`.

mod bindgen;
mod libcronet;
mod net_errors;
mod upgrade;

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cargo xtask", about = "Maintenance tasks for cronet-rs")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Regenerate `cronet-sys`'s bindings from the headers in `crates/cronet-sys/include`.
    Bindgen,
    /// Regenerate `cronet::NetError` from Chromium's `net_error_list.h`.
    NetErrors {
        /// Defaults to the copy in the naiveproxy submodule.
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Fetch clang, GN and the sysroot a build needs, without building.
    Toolchain(libcronet::Targets),
    /// Build libcronet.
    Build(libcronet::Targets),
    /// Copy built libraries into `lib/<triple>/`, and the headers into `cronet-sys`.
    Package(libcronet::Targets),
    /// Move the naiveproxy pin to the commit cronet-go pins, with the headers, bindings,
    /// network errors and crate version that follow from it.
    Upgrade {
        /// The head of this branch of the naiveproxy fork, instead of the
        /// commit cronet-go pins.
        #[arg(long, conflicts_with = "to")]
        branch: Option<String>,
        /// This commit, even if older.
        #[arg(long)]
        to: Option<String>,
    },
    /// Print the environment a Cargo build needs to link a packaged libcronet.
    Env {
        #[command(flatten)]
        targets: libcronet::Targets,
        /// Prefix each line with `export `, for `eval`.
        #[arg(long)]
        export: bool,
    },
}

fn main() -> ExitCode {
    match execute(Cli::parse().command, &Workspace::locate()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("[xtask] {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute(task: Task, workspace: &Workspace) -> Result<()> {
    match task {
        Task::Bindgen => bindgen::run(workspace),
        Task::NetErrors { source } => net_errors::run(workspace, source),
        Task::Toolchain(targets) => libcronet::toolchain(workspace, &targets.resolve()?),
        Task::Build(targets) => libcronet::build(workspace, &targets.resolve()?),
        Task::Package(targets) => libcronet::package(workspace, &targets.resolve()?),
        Task::Upgrade { branch, to } => upgrade::run(
            workspace,
            match (branch, to) {
                (Some(branch), _) => upgrade::Source::Branch(branch),
                (None, Some(commit)) => upgrade::Source::Commit(commit),
                (None, None) => upgrade::Source::Reference,
            },
        ),
        Task::Env { targets, export } => libcronet::env(workspace, targets.resolve_one()?, export),
    }
}

/// Where everything lives, relative to the workspace root.
pub(crate) struct Workspace {
    root: PathBuf,
}

impl Workspace {
    fn locate() -> Self {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        Self {
            root: manifest.parent().expect("xtask lives inside the workspace").to_owned(),
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// The naiveproxy submodule.
    pub(crate) fn naive_root(&self) -> PathBuf {
        self.root.join("naiveproxy")
    }

    /// Chromium's source tree inside the submodule.
    pub(crate) fn src_root(&self) -> PathBuf {
        self.naive_root().join("src")
    }

    /// Packaged libraries, one directory per target.
    pub(crate) fn lib_root(&self) -> PathBuf {
        self.root.join("lib")
    }

    pub(crate) fn sys_include(&self) -> PathBuf {
        self.root.join("crates/cronet-sys/include")
    }
}

/// Formats a generated file with the workspace's `rustfmt.toml`.
pub(crate) fn rustfmt(path: &Path) -> Result<()> {
    run(Command::new("rustfmt").args(["--edition", "2024"]).arg(path))
}

/// Runs a command with inherited output, failing on a non-zero exit.
pub(crate) fn run(command: &mut Command) -> Result<()> {
    let status = command.status().with_context(|| format!("starting {command:?}"))?;
    if !status.success() {
        bail!("{command:?} failed: {status}");
    }
    Ok(())
}

/// Runs a command and returns its standard output.
pub(crate) fn output(command: &mut Command) -> Result<String> {
    let output = command
        .stderr(std::process::Stdio::inherit())
        .output()
        .with_context(|| format!("starting {command:?}"))?;
    if !output.status.success() {
        bail!("{command:?} failed: {}", output.status);
    }
    Ok(String::from_utf8(output.stdout)?)
}
