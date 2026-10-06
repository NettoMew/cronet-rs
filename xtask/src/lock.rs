//! `naiveproxy.lock`: the naiveproxy commit everything comes from, and
//! `cargo xtask fetch`, which checks that commit out.
//!
//! The headers, Chromium version, bindings and network errors in the
//! repository, and every released libcronet, come from the locked commit.
//! Its source, a large part of Chromium, is fetched only to build libcronet,
//! into `naiveproxy/`, which git ignores, so that nothing depending on these
//! crates ever downloads it.

use std::{fs, process::Command, sync::LazyLock};

use anyhow::{Context, Result, bail};
use regex::Regex;

use crate::{Workspace, output, run};

const FILE: &str = "naiveproxy.lock";

static FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^(\w+) = "([^"]*)"$"#).unwrap());

/// The locked naiveproxy: where it lives, and which commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lock {
    pub(crate) repository: String,
    pub(crate) commit: String,
}

impl Lock {
    pub(crate) fn read(workspace: &Workspace) -> Result<Self> {
        let path = workspace.root().join(FILE);
        let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    fn parse(text: &str) -> Result<Self> {
        let field = |name: &str| {
            FIELD
                .captures_iter(text)
                .find(|captures| &captures[1] == name)
                .map(|captures| captures[2].to_owned())
                .with_context(|| format!("no {name}"))
        };
        let lock = Self {
            repository: field("repository")?,
            commit: field("commit")?,
        };
        if lock.commit.len() != 40 || !lock.commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("commit must be a full 40-digit hash, not {:?}", lock.commit);
        }
        Ok(lock)
    }

    pub(crate) fn write(&self, workspace: &Workspace) -> Result<()> {
        fs::write(workspace.root().join(FILE), self.render())?;
        Ok(())
    }

    fn render(&self) -> String {
        format!(
            "# The naiveproxy commit libcronet is built from, and that the headers, Chromium\n\
             # version, bindings and network errors in this repository come from.\n\
             # `cargo xtask upgrade` moves it; `cargo xtask fetch` checks it out.\n\
             repository = \"{}\"\n\
             commit = \"{}\"\n",
            self.repository, self.commit
        )
    }
}

/// Checks the locked commit out into `naiveproxy/`, fetching only that
/// commit. Already there, it does nothing, and so keeps whatever the build
/// left in the tree.
pub(crate) fn fetch(workspace: &Workspace) -> Result<()> {
    let lock = Lock::read(workspace)?;
    let root = workspace.naive_root();
    let git = || {
        let mut command = Command::new("git");
        command.current_dir(&root);
        command
    };
    if !root.join(".git").exists() {
        fs::create_dir_all(&root)?;
        run(git().args(["init", "--quiet"]))?;
    }
    let head = output(git().args(["rev-parse", "--verify", "--quiet", "HEAD"])).unwrap_or_default();
    if head.trim() == lock.commit {
        return Ok(());
    }
    eprintln!(
        "[xtask] fetching naiveproxy {} from {}",
        &lock.commit[..12],
        lock.repository
    );
    run(git().args(["fetch", "--quiet", "--depth", "1", &lock.repository, &lock.commit]))?;
    run(git().args(["checkout", "--quiet", "--detach", &lock.commit]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let lock = Lock {
            repository: "https://github.com/SagerNet/naiveproxy".into(),
            commit: "72a06c9fca0e2d228588c7f3074bf7efff3ff686".into(),
        };
        assert_eq!(Lock::parse(&lock.render()).unwrap(), lock);
        assert!(Lock::parse("repository = \"x\"\n").is_err());
        assert!(Lock::parse("repository = \"x\"\ncommit = \"72a06c9\"\n").is_err());
    }
}
