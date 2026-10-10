//! Port of `de.osci.helper.TestBase64` and `TestBase64InputStream`.

use std::io::{Read, Write};

use osci_core::helper::base64::{self, Base64Decoder, Base64Encoder};

const CORRECT_INPUT: &str = "123/1234123412==";
const CORRECT_INPUT_WITH_BLANKS: &str = "12 3/1234    12341w==";
const LONGER_CORRECT_INPUT_WITH_BLANKS: &str =
    "63945871235    63182794692 123456 123456 123456 18738712908 19371486124";
const ILLEGAL_PADDING: &str = "12341=+";
const ADDITIONAL_BLANKS: &str = "123    412== \n";

fn get_test_data(length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| (900i32 - i as i32).rem_euclid(256) as u8)
        .collect()
}

fn encode_streaming(data: &[u8]) -> String {
    let mut out = Vec::new();
    let mut enc = Base64Encoder::new(&mut out);
    enc.write_all(data).unwrap();
    enc.finish().unwrap();
    String::from_utf8(out).unwrap()
}

fn decode_streaming(input: &str) -> Vec<u8> {
    let mut out = Vec::new();
    Base64Decoder::new(input.as_bytes())
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// Port of `testCalcB64Length`.
#[test]
fn calc_length_matches_actual_output() {
    for len in 0..200usize {
        let encoded = base64::encode(&get_test_data(len));
        assert_eq!(
            encoded.len() as u64,
            base64::calc_b64_length(len as u64),
            "calculated length wrong for {len} bytes"
        );
    }
}

/// Port of `testPositiveCase` (all lengths, both directions).
#[test]
fn positive_cases() {
    for len in [1, 3, 5, 300, 301, 302, 50000, 50001, 50002, 50003] {
        let data = get_test_data(len);
        let encoded = base64::encode(&data);
        assert_eq!(
            decode_streaming(&encoded),
            data,
            "array encode -> streaming decode corrupts data at len {len}"
        );
        let encoded = encode_streaming(&data);
        assert_eq!(
            base64::decode(&encoded).unwrap(),
            data,
            "streaming encode -> array decode corrupts data at len {len}"
        );
    }
}

/// Port of `testNegativeCase`: illegal padding rejected, blanks ignored.
#[test]
fn negative_parsing_cases() {
    assert!(
        base64::decode(ILLEGAL_PADDING).is_err(),
        "illegal padding char not detected"
    );
    let expected = base64::decode("123412==").unwrap();
    assert_eq!(base64::decode(ADDITIONAL_BLANKS).unwrap(), expected);
    assert_eq!(decode_streaming(ADDITIONAL_BLANKS), expected);
}

/// Input delivering random-sized chunks (port of `testStreamingInput` /
/// `StutterInputStream`), with a deterministic LCG instead of `Random`.
struct Stutter<R: Read> {
    inner: R,
    state: u64,
}

impl<R: Read> Read for Stutter<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let cap = ((self.state >> 33) as usize).max(1) % buf.len().max(1);
        let cap = cap.max(1).min(buf.len());
        self.inner.read(&mut buf[..cap])
    }
}

#[test]
fn stuttering_input() {
    let expected = base64::decode(LONGER_CORRECT_INPUT_WITH_BLANKS).unwrap();
    for iteration in 0..10u64 {
        let source = Stutter {
            inner: LONGER_CORRECT_INPUT_WITH_BLANKS.as_bytes(),
            state: 0x9E3779B97F4A7C15 ^ iteration,
        };
        let mut out = Vec::new();
        Base64Decoder::new(source)
            .read_to_end(&mut out)
            .unwrap_or_else(|e| panic!("iteration {iteration}: {e}"));
        assert_eq!(out, expected, "incorrect result, iteration {iteration}");
    }
}

/// Port of `testByteWiseReading`: the blank-riddled variant decodes to the
/// same bytes (the `w` only changes discarded bits), reading byte-wise.
#[test]
fn byte_wise_reading() {
    let expected = base64::decode(CORRECT_INPUT).unwrap();

    let mut dec = Base64Decoder::new(CORRECT_INPUT_WITH_BLANKS.as_bytes());
    let mut output = [0u8; 24];
    for i in 0..8 {
        let n = dec.read(&mut output[i..i + 1]).unwrap();
        assert_eq!(n, 1, "unexpected end of stream at byte {i}");
    }
    assert_eq!(dec.read(&mut output[8..]).unwrap(), 2);
    assert_eq!(dec.read(&mut output[10..]).unwrap(), 0);
    assert_eq!(
        &output[..expected.len()],
        &expected[..],
        "wrong decoded array"
    );

    // Longer input: byte-wise reads produce no zero bytes (data property).
    let mut dec = Base64Decoder::new(LONGER_CORRECT_INPUT_WITH_BLANKS.as_bytes());
    let mut single = [0u8; 1];
    while dec.read(&mut single).unwrap() == 1 {
        assert_ne!(single[0], 0, "0 found in data");
    }
}

/// Port of `testStreamEncoding`: split writes equal one whole write.
#[test]
fn split_writes_equal_whole_write() {
    let my_bytes = b"12345678";
    let mut out = Vec::new();
    let mut enc = Base64Encoder::new(&mut out);
    enc.write_all(&my_bytes[..5]).unwrap();
    enc.write_all(&my_bytes[5..]).unwrap();
    enc.finish().unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), base64::encode(my_bytes));
}

/// Port of `testByteWiseReadingLongData`.
#[test]
fn byte_wise_roundtrip_long_data() {
    for len in 0..=2051usize {
        let data = vec![b'x'; len];
        let encoded = base64::encode(&data);
        let mut got = Vec::with_capacity(len);
        let mut dec = Base64Decoder::new(encoded.as_bytes());
        let mut one = [0u8; 1];
        while dec.read(&mut one).unwrap() == 1 {
            got.push(one[0]);
        }
        assert_eq!(got, data, "wrong array read at len {len}");
    }
}

/// Port of `testBlockWiseReadingLongData` (upper end trimmed from 1030 to
/// 300 to keep the O(n^2) matrix fast in debug-mode CI).
#[test]
fn block_wise_roundtrip_long_data() {
    for len in 0..=300usize {
        let data = vec![b'x'; len];
        let encoded = base64::encode(&data);
        for cap in 1..=((len * 6 / 5) + 1).max(1) {
            let mut dec = Base64Decoder::new(encoded.as_bytes());
            let mut got = Vec::with_capacity(len);
            let mut buf = vec![0u8; cap];
            loop {
                let n = dec.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, data, "wrong array read at len {len}, cap {cap}");
        }
    }
}

/// Port of `runPerformanceTest`, asserted for correctness.
#[test]
fn five_megabyte_roundtrip() {
    let data = get_test_data(5_000_000);
    let encoded = base64::encode(&data);
    assert_eq!(base64::decode(&encoded).unwrap(), data);
    assert_eq!(decode_streaming(&encode_streaming(&data)), data);
}

/// The encoder's 76-char line-break layout cross-checked against the
/// `base64` crate (independent raw encoding) plus the documented chunking
/// rule: LF after every 76 characters, including a trailing one when the
/// output ends exactly on a boundary.
#[test]
fn line_break_layout_matches_reference() {
    use ::base64::Engine;
    for len in [0, 1, 3, 56, 57, 58, 60, 114, 115, 116, 171, 172, 5003] {
        let data = get_test_data(len);
        let plain = ::base64::engine::general_purpose::STANDARD.encode(&data);
        let mut expected = String::new();
        for (i, chunk) in plain.as_bytes().chunks(76).enumerate() {
            if i > 0 {
                expected.push('\n');
            }
            expected.push_str(std::str::from_utf8(chunk).unwrap());
        }
        if !plain.is_empty() && plain.len().is_multiple_of(76) {
            expected.push('\n');
        }
        assert_eq!(
            base64::encode(&data),
            expected,
            "layout differs at len {len}"
        );
    }
}

/// The trailing line break at exact 76-character boundaries is part of the
/// OSCI wire format (`calcB64Length` counts it).
#[test]
fn trailing_line_break_on_exact_boundaries() {
    assert_eq!(base64::calc_b64_length(57), 77);
    assert!(base64::encode(&get_test_data(57)).ends_with('\n'));
    assert_eq!(base64::calc_b64_length(56), 77);
    assert!(base64::encode(&get_test_data(56)).ends_with('\n'));
    assert_eq!(base64::calc_b64_length(55), 77);
    assert!(base64::encode(&get_test_data(55)).ends_with('\n'));
    assert_eq!(base64::calc_b64_length(54), 72);
    assert!(!base64::encode(&get_test_data(54)).ends_with('\n'));
}
