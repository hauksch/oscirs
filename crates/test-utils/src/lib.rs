//! Shared test utilities for the workspace's integration tests.
//!
//! Dev-dependency only - never published, never linked into the library
//! targets. Provides the corpus locator and the cert/keystore helpers so
//! the per-crate copies stay in sync.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Corpus root (overridable via `OSCI_CORPUS` for CI layouts).
pub fn corpus() -> PathBuf {
    std::env::var_os("OSCI_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(2)
                .unwrap()
                .join("testcorpus")
        })
}

/// Workspace root (parent of the corpus).
pub fn workspace_root() -> PathBuf {
    corpus()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn messages_dir() -> PathBuf {
    corpus().join("messages")
}

pub fn message(name: &str) -> PathBuf {
    messages_dir().join(name)
}

/// First DER certificate from a PEM bundle in the corpus certs directory.
pub fn cert_der(pem_name: &str) -> Vec<u8> {
    let dump = std::fs::read_to_string(corpus().join("certs").join(pem_name))
        .unwrap_or_else(|e| panic!("cert pem {pem_name}: {e}"));
    pem_first_certificate_der(&dump).unwrap_or_else(|| panic!("no cert in {pem_name}"))
}

/// Extract the first `BEGIN CERTIFICATE` block of a PEM string as DER.
pub fn pem_first_certificate_der(pem: &str) -> Option<Vec<u8>> {
    let start = pem.find("-----BEGIN CERTIFICATE-----")?;
    let after = &pem[start + "-----BEGIN CERTIFICATE-----".len()..];
    let end = after.find("-----END CERTIFICATE-----")?;
    let b64: String = after[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    b64_decode(&b64)
}

/// Extract the first `BEGIN PRIVATE KEY` block of a PEM string.
pub fn pem_first_private_key_pem(pem: &str) -> Option<String> {
    let start = pem.find("-----BEGIN PRIVATE KEY-----")?;
    let end_marker = "-----END PRIVATE KEY-----";
    let end = pem[start..].find(end_marker)? + start + end_marker.len();
    Some(pem[start..end].to_string())
}

/// Self-contained base64 decode (no dependency edge into the library
/// under test).
pub fn b64_decode(data: &str) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    for ch in data.chars().filter(|c| !c.is_whitespace()) {
        let v = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            '=' => break,
            _ => return None,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Whether the Java oracle harness is compiled (`make oracle`).
pub fn oracle_available() -> bool {
    workspace_root().join("oracle/build/classpath.txt").exists()
}
