#![allow(missing_docs, reason = "build script")]

//! Build script: embed the short git commit hash as the `GIT_HASH` env var so the
//! binary can report it from `--version`. Falls back to an empty string when the
//! source is built outside a git checkout (e.g. from a packaged tarball).

use std::process::Command;

fn main() {
    let hash = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    println!("cargo:rustc-env=GIT_HASH={}", hash.trim());
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");
}
