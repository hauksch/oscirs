#![no_main]
//! Canonicalization of parseable documents is deterministic and
//! idempotent, or errors cleanly.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    if let Ok(doc) = osci_core::xml::parser::parse(data) {
        if let Ok(canonical) = osci_core::xml::c14n::canonicalize(&doc) {
            if let Ok(text) = std::str::from_utf8(&canonical.bytes) {
                if let Ok(doc2) = osci_core::xml::parser::parse(text) {
                    if let Ok(canonical2) = osci_core::xml::c14n::canonicalize(&doc2) {
                        assert_eq!(canonical.bytes, canonical2.bytes, "c14n not idempotent");
                    }
                }
            }
        }
    }
});
