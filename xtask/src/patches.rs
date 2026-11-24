//! Local Chromium patches (`patches/*.patch`) and source overlays
//! (`patches/src/**`), applied in order after `cargo xtask fetch` checks out
//! the locked naiveproxy commit.
//!
//! A stamp in `naiveproxy/.xtask-patches` records the commit and a SHA-256
//! digest of every patch and overlay file so repeated `fetch`, `build`, and
//! `package` runs leave timestamps untouched unless the locked commit or
//! `patches/` changed.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::{Workspace, run};

const STAMP_FILE: &str = ".xtask-patches";

/// Whether `patches/` holds any `*.patch` or `src/**` files.
pub(crate) fn has_entries(workspace: &Workspace) -> Result<bool> {
    let root = workspace.patches_root();
    Ok(!list_patches(&root)?.is_empty() || !list_overlays(&root.join("src"))?.is_empty())
}

/// Applies `patches/*.patch` in lexical order and copies `patches/src/**`
/// into `naive_root/src/` when the locked `commit` or `patches/` changed.
///
/// Fails immediately on any patch conflict, naming `commit`.
pub(crate) fn apply(workspace: &Workspace, commit: &str) -> Result<()> {
    apply_in(&workspace.patches_root(), &workspace.naive_root(), commit)
}

fn apply_in(patches_root: &Path, naive_root: &Path, commit: &str) -> Result<()> {
    let patches = list_patches(patches_root)?;
    let overlays = list_overlays(&patches_root.join("src"))?;
    let stamp_path = naive_root.join(STAMP_FILE);

    if patches.is_empty() && overlays.is_empty() && !stamp_path.exists() {
        return Ok(());
    }

    let digest = compute_digest(commit, &patches, &overlays)?;
    if let Some((stamped_commit, stamped_digest, _)) = read_stamp(&stamp_path)
        && stamped_commit == commit
        && stamped_digest == digest
    {
        return Ok(());
    }

    if let Some((_, _, previous_overlays)) = read_stamp(&stamp_path) {
        for rel in previous_overlays {
            let _ = fs::remove_file(naive_root.join("src").join(&rel));
        }
        let _ = fs::remove_file(&stamp_path);
    }

    // Reset tracked files to the clean locked commit while keeping untracked
    // toolchains, sysroots, PGO profiles, and Ninja build outputs intact.
    // Override `core.autocrlf` and `core.eol` so Windows hosts with global
    // `core.autocrlf=true` never materialize CRLF working-tree files.
    run(Command::new("git").current_dir(naive_root).args([
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.eol=lf",
        "checkout",
        "--quiet",
        "--force",
        commit,
        "--",
        ".",
    ]))
    .with_context(|| format!("resetting naiveproxy {commit} before applying patches"))?;

    if patches.is_empty() && overlays.is_empty() {
        return Ok(());
    }

    for patch in &patches {
        let name = patch
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| patch.display().to_string());
        if fs::read_to_string(patch)?.trim().is_empty() {
            eprintln!("[xtask] skipping empty patch {name}");
            continue;
        }
        eprintln!("[xtask] applying patch {name}");
        let status = Command::new("git")
            .current_dir(naive_root)
            .args(["-c", "core.autocrlf=false", "apply", "--whitespace=nowarn"])
            .arg(patch)
            .status()
            .with_context(|| format!("starting git apply for {name} on naiveproxy {commit}"))?;
        if !status.success() {
            bail!("patch {name} failed to apply onto naiveproxy {commit} ({status})");
        }
    }

    let mut overlaid_paths = Vec::with_capacity(overlays.len());
    let src_root = naive_root.join("src");
    for (rel, source) in &overlays {
        let destination = src_root.join(rel);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating directory {}", parent.display()))?;
        }
        let bytes = fs::read(source).with_context(|| format!("reading {}", source.display()))?;
        let unchanged = fs::read(&destination).is_ok_and(|existing| existing == bytes);
        if !unchanged {
            fs::write(&destination, &bytes).with_context(|| format!("overlaying {rel} onto naiveproxy {commit}"))?;
        }
        overlaid_paths.push(rel.clone());
    }

    let stamp = json!({
        "commit": commit,
        "digest": digest,
        "overlaid": overlaid_paths,
    });
    fs::write(&stamp_path, format!("{}\n", serde_json::to_string_pretty(&stamp)?))
        .with_context(|| format!("writing {}", stamp_path.display()))?;
    Ok(())
}

fn list_patches(patches_root: &Path) -> Result<Vec<PathBuf>> {
    if !patches_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(patches_root).with_context(|| format!("reading {}", patches_root.display()))? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "patch") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn list_overlays(overlay_src: &Path) -> Result<Vec<(String, PathBuf)>> {
    if !overlay_src.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    collect_overlays(overlay_src, overlay_src, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn collect_overlays(base: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            collect_overlays(base, &path, out)?;
        } else if ty.is_file() {
            let rel = path
                .strip_prefix(base)
                .expect("inside base")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((rel, path));
        }
    }
    Ok(())
}

fn read_stamp(path: &Path) -> Option<(String, String, Vec<String>)> {
    let text = fs::read_to_string(path).ok()?;
    let val: Value = serde_json::from_str(&text).ok()?;
    let commit = val.get("commit")?.as_str()?.to_owned();
    let digest = val.get("digest")?.as_str()?.to_owned();
    let overlaid = val
        .get("overlaid")?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    Some((commit, digest, overlaid))
}

fn compute_digest(commit: &str, patches: &[PathBuf], overlays: &[(String, PathBuf)]) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"commit:");
    hasher.update(commit.as_bytes());
    hasher.update(b"\n");
    for patch in patches {
        let name = patch.file_name().expect("file").to_string_lossy();
        let data = fs::read(patch).with_context(|| format!("reading {}", patch.display()))?;
        hasher.update(b"patch:");
        hasher.update(name.as_bytes());
        hasher.update(b":");
        hasher.update(&(data.len() as u64).to_le_bytes());
        hasher.update(&data);
        hasher.update(b"\n");
    }
    for (rel, path) in overlays {
        let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        hasher.update(b"overlay:");
        hasher.update(rel.as_bytes());
        hasher.update(b":");
        hasher.update(&(data.len() as u64).to_le_bytes());
        hasher.update(&data);
        hasher.update(b"\n");
    }
    Ok(hasher.finish_hex())
}

/// Minimal FIPS 180-4 SHA-256 for deterministic patch stamp digests without
/// extra crate dependencies.
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    total_bits: u64,
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            total_bits: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.total_bits = self.total_bits.wrapping_add((input.len() as u64) * 8);
        while !input.is_empty() {
            let take = (64 - self.buffered).min(input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
    }

    fn finish_hex(mut self) -> String {
        let bits = self.total_bits;
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;
        if self.buffered > 56 {
            self.buffer[self.buffered..64].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffered = 0;
        }
        self.buffer[self.buffered..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bits.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut hex = String::with_capacity(64);
        for word in self.state {
            use std::fmt::Write as _;
            write!(hex, "{word:08x}").unwrap();
        }
        hex
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, slot) in w.iter_mut().take(16).enumerate() {
            *slot = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, delta) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(delta);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output;

    fn make_repo(tag: &str) -> (PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("xtask-patches-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let naive = dir.join("naiveproxy");
        fs::create_dir_all(naive.join("src")).unwrap();
        fs::write(naive.join(".gitattributes"), "* text=auto eol=lf\n").unwrap();
        fs::write(naive.join("src/hello.txt"), "line1\nline2\n").unwrap();
        run(Command::new("git").current_dir(&naive).args(["init", "--quiet"])).unwrap();
        run(Command::new("git")
            .current_dir(&naive)
            .args(["config", "--local", "core.autocrlf", "false"]))
        .unwrap();
        run(Command::new("git")
            .current_dir(&naive)
            .args(["config", "--local", "core.eol", "lf"]))
        .unwrap();
        run(Command::new("git")
            .current_dir(&naive)
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "add", "."]))
        .unwrap();
        run(Command::new("git").current_dir(&naive).args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "--quiet",
            "-m",
            "init",
        ]))
        .unwrap();
        let commit = output(Command::new("git").current_dir(&naive).args(["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();
        (dir, commit)
    }

    #[test]
    fn sha256_matches_nist_vector() {
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(
            h.finish_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn no_patches_leaves_checkout_untouched() {
        let (dir, commit) = make_repo("none");
        let naive = dir.join("naiveproxy");
        let patches = dir.join("patches");
        apply_in(&patches, &naive, &commit).unwrap();
        assert!(!naive.join(STAMP_FILE).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn applies_patches_in_order_overlays_files_and_keeps_untracked_build_outputs() {
        let (dir, commit) = make_repo("order");
        let naive = dir.join("naiveproxy");
        let patches = dir.join("patches");
        fs::create_dir_all(patches.join("src/extra")).unwrap();
        fs::create_dir_all(naive.join("src/out")).unwrap();
        fs::write(naive.join("src/out/keep.bin"), "build-artifact").unwrap();

        fs::write(patches.join("0000-empty.patch"), "   \n").unwrap();
        fs::write(
            patches.join("0001-first.patch"),
            "--- a/src/hello.txt\n+++ b/src/hello.txt\n@@ -1,2 +1,2 @@\n-line1\n+first\n line2\n",
        )
        .unwrap();
        fs::write(
            patches.join("0002-second.patch"),
            "--- a/src/hello.txt\n+++ b/src/hello.txt\n@@ -1,2 +1,2 @@\n first\n-line2\n+second\n",
        )
        .unwrap();
        fs::write(patches.join("src/extra/new.cc"), "int added() { return 1; }\n").unwrap();

        apply_in(&patches, &naive, &commit).unwrap();
        assert_eq!(
            fs::read_to_string(naive.join("src/hello.txt")).unwrap(),
            "first\nsecond\n"
        );
        assert_eq!(
            fs::read_to_string(naive.join("src/extra/new.cc")).unwrap(),
            "int added() { return 1; }\n"
        );
        assert_eq!(
            fs::read_to_string(naive.join("src/out/keep.bin")).unwrap(),
            "build-artifact"
        );

        // Second call is an idempotent no-op.
        apply_in(&patches, &naive, &commit).unwrap();

        // Editing a patch and removing an overlay file re-resets cleanly.
        fs::remove_file(patches.join("0002-second.patch")).unwrap();
        fs::remove_file(patches.join("src/extra/new.cc")).unwrap();
        apply_in(&patches, &naive, &commit).unwrap();
        assert_eq!(
            fs::read_to_string(naive.join("src/hello.txt")).unwrap(),
            "first\nline2\n"
        );
        assert!(!naive.join("src/extra/new.cc").exists());
        assert_eq!(
            fs::read_to_string(naive.join("src/out/keep.bin")).unwrap(),
            "build-artifact"
        );

        // Removing all remaining patches resets tracked files and drops the stamp.
        fs::remove_file(patches.join("0000-empty.patch")).unwrap();
        fs::remove_file(patches.join("0001-first.patch")).unwrap();
        apply_in(&patches, &naive, &commit).unwrap();
        assert_eq!(
            fs::read_to_string(naive.join("src/hello.txt")).unwrap(),
            "line1\nline2\n"
        );
        assert!(!naive.join(STAMP_FILE).exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn failing_patch_stops_and_names_locked_commit() {
        let (dir, commit) = make_repo("fail");
        let naive = dir.join("naiveproxy");
        let patches = dir.join("patches");
        fs::create_dir_all(&patches).unwrap();
        fs::write(
            patches.join("0001-broken.patch"),
            "--- a/src/hello.txt\n+++ b/src/hello.txt\n@@ -1,2 +1,2 @@\n-does_not_exist\n+boom\n line2\n",
        )
        .unwrap();

        let err = apply_in(&patches, &naive, &commit).unwrap_err().to_string();
        assert!(
            err.contains(&commit),
            "error must include locked commit {commit}: {err}"
        );
        assert!(err.contains("0001-broken.patch"), "{err}");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn applies_patches_with_lf_even_when_repo_config_requests_crlf() {
        let dir = std::env::temp_dir().join(format!("xtask-patches-crlf-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let naive = dir.join("naiveproxy");
        let patches = dir.join("patches");
        fs::create_dir_all(naive.join("src")).unwrap();
        fs::create_dir_all(&patches).unwrap();

        run(Command::new("git").current_dir(&naive).args(["init", "--quiet"])).unwrap();
        // Simulate a Windows runner with `core.autocrlf=true` and `core.eol=crlf`
        // and no `.gitattributes` in the upstream checkout.
        run(Command::new("git")
            .current_dir(&naive)
            .args(["config", "--local", "core.autocrlf", "true"]))
        .unwrap();
        run(Command::new("git")
            .current_dir(&naive)
            .args(["config", "--local", "core.eol", "crlf"]))
        .unwrap();
        fs::write(naive.join("src/hello.txt"), "line1\nline2\n").unwrap();
        run(Command::new("git")
            .current_dir(&naive)
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "add", "."]))
        .unwrap();
        run(Command::new("git").current_dir(&naive).args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "--quiet",
            "-m",
            "init",
        ]))
        .unwrap();
        let commit = output(Command::new("git").current_dir(&naive).args(["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();
        // Remove the working-tree file so `git checkout --force` must materialize
        // it from the object database.
        fs::remove_file(naive.join("src/hello.txt")).unwrap();

        fs::write(
            patches.join("0001-first.patch"),
            "--- a/src/hello.txt\n+++ b/src/hello.txt\n@@ -1,2 +1,2 @@\n-line1\n+first\n line2\n",
        )
        .unwrap();
        apply_in(&patches, &naive, &commit).unwrap();
        assert_eq!(fs::read(naive.join("src/hello.txt")).unwrap(), b"first\nline2\n");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn workspace_patches_and_overlays_use_lf_line_endings() {
        let root = Workspace::locate().patches_root();
        for patch in list_patches(&root).unwrap() {
            let bytes = fs::read(&patch).unwrap();
            assert!(
                !bytes.contains(&b'\r'),
                "{} contains CR bytes; patches must use LF line endings",
                patch.display()
            );
        }
        for (_, overlay) in list_overlays(&root.join("src")).unwrap() {
            let bytes = fs::read(&overlay).unwrap();
            assert!(
                !bytes.contains(&b'\r'),
                "{} contains CR bytes; overlay sources must use LF line endings",
                overlay.display()
            );
        }
    }
}
