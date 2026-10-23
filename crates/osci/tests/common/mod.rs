//! Shared helpers for osci integration tests. Compiled per test binary,
//! so not every export is used by every binary.
#![allow(unknown_lints)]
#![allow(unused_imports, dead_code)]

pub use test_utils::{cert_der, corpus, message, messages_dir, workspace_root};
