//! Embeds the git rev this build was made from, so integrators can report
//! the exact oscirs build they run via [`crate::VERSION`]. Trees without
//! git (crates.io packages, vendored snapshots) report `unknown`.
//!
//! NB: the env is only re-evaluated when this crate rebuilds — a HEAD move
//! alone does not retrigger the build script.
use std::process::Command;

fn main() {
    let rev = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|rev| !rev.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=OSCIRS_GIT_REV={rev}");
}
