//! Record the compiler this run was built with, so a report carries it.

use std::process::Command;

fn main() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=CT_TIMING_RUSTC={}", version.trim());
    println!("cargo:rerun-if-changed=build.rs");
}
