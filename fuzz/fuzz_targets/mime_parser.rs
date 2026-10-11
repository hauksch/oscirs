#![no_main]
//! The MIME parser must be total: arbitrary input either parses or
//! errors cleanly, never panics and never loops forever.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut parser) = osci_core::helper::mime::MimeParser::new(data) {
        let _ = parser.next_part();
    }
});
