#![no_main]
//! The XML parser is total: no panics on arbitrary input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = osci_core::xml::parser::parse(data);
});
