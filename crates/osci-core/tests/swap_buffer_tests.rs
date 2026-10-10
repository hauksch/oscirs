//! Port of `de.osci.osci12.common.TestSwapBuffer`.

use std::io::{Read, Write};

use osci_core::helper::swap_buffer::SwapBuffer;

fn write(sb: &mut SwapBuffer, data: &[u8]) {
    sb.output().unwrap().write_all(data).unwrap();
}

fn read_all(sb: &mut SwapBuffer) -> Vec<u8> {
    let mut out = Vec::new();
    sb.input().unwrap().read_to_end(&mut out).unwrap();
    out
}

fn parameterized_write_read(max_buffer_size: u64, confidential: bool, expect_file: bool) {
    let mut sb = SwapBuffer::with_limit(max_buffer_size);
    sb.set_confidential(confidential);
    let data = b"Enter your data here.";
    write(&mut sb, data);
    assert_eq!(sb.length(), data.len() as u64);
    assert_eq!(read_all(&mut sb), data);
    // after a full read, the stream is at EOF (Java: in.read() == -1)
    let mut one = [0u8; 1];
    assert_eq!(sb.input().unwrap().read(&mut one).unwrap(), 0);
    assert_eq!(expect_file, sb.spill_path().is_some());
}

/// Port of `testConfidentialWriteReadToFile`.
#[test]
fn confidential_write_read_to_file() {
    parameterized_write_read(0, true, true);
}

/// Port of `testNoneConfidentialWriteReadToFile`.
#[test]
fn none_confidential_write_read_to_file() {
    parameterized_write_read(0, false, true);
}

/// Port of `testConfidentialWriteReadInMemory`.
#[test]
fn confidential_write_read_in_memory() {
    parameterized_write_read(100, true, false);
}

/// Port of `testNoneConfidentialWriteReadInMemory`.
#[test]
fn none_confidential_write_read_in_memory() {
    parameterized_write_read(1000, false, false);
}

/// The OSCIDataSource contract allows repeated reads after `reset()`.
#[test]
fn reset_rereads_from_the_beginning() {
    let mut sb = SwapBuffer::with_limit(0);
    write(&mut sb, b"once more");
    assert_eq!(read_all(&mut sb), b"once more");
    sb.reset().unwrap();
    assert_eq!(read_all(&mut sb), b"once more");
}

/// Java throws IllegalStateException when writing after switching to read
/// mode.
#[test]
fn write_after_read_is_rejected() {
    let mut sb = SwapBuffer::new();
    write(&mut sb, b"data");
    let _ = read_all(&mut sb);
    assert!(sb.output().is_err());
}

/// Confidential spill files must not contain the plaintext.
#[test]
fn confidential_spill_is_encrypted_on_disk() {
    let mut sb = SwapBuffer::with_limit(0);
    sb.set_confidential(true);
    write(&mut sb, b"top-secret-payload-123456");
    let path = sb.spill_path().expect("must have spilled").to_path_buf();
    let raw = std::fs::read(&path).unwrap();
    assert!(
        !raw.windows(4).any(|w| w == b"top-"),
        "plaintext leaked into the spill file"
    );
    assert_eq!(read_all(&mut sb), b"top-secret-payload-123456");
}

/// Multi-frame confidential spill (64 KiB frames) round-trips.
#[test]
fn large_confidential_spill_roundtrip() {
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut sb = SwapBuffer::with_limit(0);
    sb.set_confidential(true);
    for chunk in data.chunks(7000) {
        write(&mut sb, chunk);
    }
    assert_eq!(sb.length(), data.len() as u64);
    assert_eq!(read_all(&mut sb), data);
}

/// Crossing the threshold mid-stream keeps earlier in-memory bytes.
#[test]
fn spill_preserves_earlier_bytes() {
    let mut sb = SwapBuffer::with_limit(10);
    write(&mut sb, b"first-six");
    write(&mut sb, b"second-six");
    assert!(sb.spill_path().is_some());
    assert_eq!(read_all(&mut sb), b"first-sixsecond-six");
}

/// Exactly reaching the limit stays in memory (Java spills only when the
/// limit would be *exceeded*).
#[test]
fn exactly_at_limit_stays_in_memory() {
    let mut sb = SwapBuffer::with_limit(6);
    write(&mut sb, b"123456");
    assert!(sb.spill_path().is_none());
    assert_eq!(read_all(&mut sb), b"123456");
}

#[test]
fn empty_buffer_reads_eof() {
    let mut sb = SwapBuffer::new();
    assert_eq!(read_all(&mut sb), b"");
    assert_eq!(sb.length(), 0);
}

/// Port of `testFinalize`: the temp file disappears when the buffer is
/// dropped.
#[test]
fn temp_file_deleted_on_drop() {
    let path;
    {
        let mut sb = SwapBuffer::with_limit(0);
        write(&mut sb, b"vanishing act");
        path = sb.spill_path().expect("spilled").to_path_buf();
        assert_eq!(read_all(&mut sb), b"vanishing act");
    }
    assert!(!path.exists(), "temp file survived the drop");
}
