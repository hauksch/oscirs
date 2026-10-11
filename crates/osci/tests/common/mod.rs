//! Shared helpers for osci integration tests.
#![allow(dead_code)]
use std::path::PathBuf;

pub fn corpus() -> PathBuf {
    std::env::var_os("OSCI_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(2)
                .unwrap()
                .join("testcorpus")
        })
}
