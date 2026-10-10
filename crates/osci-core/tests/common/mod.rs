//! Shared helpers for osci-core integration tests.

use std::path::PathBuf;

pub fn corpus() -> PathBuf {
    std::env::var_os("OSCI_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.pop();
            p.pop();
            p.join("testcorpus")
        })
}

pub fn message(name: &str) -> PathBuf {
    corpus().join("messages").join(name)
}
