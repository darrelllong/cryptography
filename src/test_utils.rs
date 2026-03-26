//! Test helpers for cross-validating implementations against OpenSSL.
//!
//! These functions spawn an `openssl` subprocess and compare its output against
//! our native implementation.  Tests that use them are skipped (via `return`)
//! when OpenSSL is not installed, so CI without OpenSSL still passes.

use std::io::Write;
use std::process::{Command, Stdio};

/// Run `openssl` with the given arguments, piping `stdin` to its standard
/// input, and return its standard output on success.
///
/// Returns `None` if OpenSSL is not found, fails to spawn, exits non-zero, or
/// writes to stdin fail.  Callers should skip the test gracefully on `None`.
pub(crate) fn run_openssl(args: &[&str], stdin: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new("openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.as_mut()?.write_all(stdin).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout)
}

/// Encrypt `input` with `openssl enc`.  Flags `-nopad -nosalt -e` are always
/// set.  Returns `None` on any failure (OpenSSL absent, non-zero exit, etc.).
pub(crate) fn run_openssl_enc(
    cipher_name: &str,
    key_hex: &str,
    iv_hex: Option<&str>,
    input: &[u8],
) -> Option<Vec<u8>> {
    let mut args = vec!["enc", cipher_name, "-nopad", "-nosalt", "-K", key_hex];
    if let Some(iv) = iv_hex {
        args.extend(["-iv", iv]);
    }
    args.push("-e");
    run_openssl(&args, input)
}
