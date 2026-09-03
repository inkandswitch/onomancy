//! Embed the source revision so a built module can identify itself.
//!
//! Two builds of the same version are indistinguishable by anything
//! else: workspace path dependencies carry no version strings into the
//! binary, so a published artifact and a later tree build both answer
//! "0.3.0" and nothing more. `buildInfo()` reports the revision this
//! build was made from, taken from `ONOMANCY_GIT_REV` when the builder
//! sets it (Nix, where `.git` is absent) and from `git` otherwise.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=ONOMANCY_GIT_REV");
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");

    let rev = std::env::var("ONOMANCY_GIT_REV")
        .ok()
        .filter(|rev| !rev.is_empty())
        .or_else(git_describe)
        .unwrap_or_else(|| String::from("unknown"));

    println!("cargo:rustc-env=ONOMANCY_GIT_REV={rev}");
}

/// The short commit hash, suffixed `-dirty` when the tree has
/// uncommitted changes — a dirty build must not pass for the commit
/// it names.
fn git_describe() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--always", "--dirty", "--exclude=*"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let rev = String::from_utf8(output.stdout).ok()?.trim().to_owned();

    (!rev.is_empty()).then_some(rev)
}
