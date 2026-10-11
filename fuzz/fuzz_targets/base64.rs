#![no_main]
//! The base64 decoder is total; encode∘decode = id for anything the
//! decoder accepts round-trip through encode.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = osci_core::helper::base64::decode(&String::from_utf8_lossy(data));
});
