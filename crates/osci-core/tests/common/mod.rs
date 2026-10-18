//! Shared helpers for osci-core integration tests. Compiled per test
//! binary, so not every export is used by every binary.
#![allow(unknown_lints)]
#![allow(unused_imports, dead_code)]

pub use test_utils::{corpus, message, messages_dir, workspace_root};
