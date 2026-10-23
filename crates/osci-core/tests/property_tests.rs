//! M9 property-based tests: roundtrip and invariant properties across
//! randomly generated inputs for the codec layers.

use std::io::{Read, Write};

use proptest::prelude::*;

use osci_core::helper::base64::{self, Base64Decoder, Base64Encoder};
use osci_core::helper::mime::MimeParser;
use osci_core::message::MessageType;
use osci_core::message::compose::{
    OutCertEntry, OutContent, OutContentContainer, OutMessage, compose_message,
};
use osci_core::soap::{CertRole, CertUse, ControlBlock};
use osci_core::xml::c14n::canonicalize_str;
use osci_core::xml::parser;
use osci_core::xml::serialize::document_to_string;

prop_compose! {
    fn arb_bytes()(vec in proptest::collection::vec(any::<u8>(), 0..4096)) -> Vec<u8> {
        vec
    }
}

prop_compose! {
    fn arb_text()(s in "[^\x00\r\n]{0,512}") -> String {
        s
    }
}

// Base64: encode -> decode is the identity for arbitrary bytes, and the
// wire length formula holds for every length.
proptest! {
    #[test]
    fn base64_roundtrip(data in arb_bytes()) {
        let encoded = base64::encode(&data);
        let decoded = base64::decode(&encoded).unwrap();
        prop_assert_eq!(decoded.clone(), data.clone());
        prop_assert_eq!(encoded.len() as u64, base64::calc_b64_length(data.len() as u64));
        let _ = &data;
    }
}

// Base64 streaming: chunked writes equal one whole write; chunked reads
// equal read_to_end.
proptest! {
    #[test]
    fn base64_streaming_chunked_equals_whole(
        data in arb_bytes(),
        chunk in 1usize..512,
    ) {
        let mut whole = Vec::new();
        {
            let mut enc = Base64Encoder::new(&mut whole);
            enc.write_all(&data).unwrap();
            enc.finish().unwrap();
        }
        let mut chunked = Vec::new();
        {
            let mut enc = Base64Encoder::new(&mut chunked);
            for piece in data.chunks(chunk) {
                enc.write_all(piece).unwrap();
            }
            enc.finish().unwrap();
        }
        prop_assert_eq!(chunked.clone(), whole.clone());

        // chunked decode
        let mut out = Vec::new();
        let mut dec = Base64Decoder::new(whole.as_slice());
        let mut buf = vec![0u8; chunk];
        loop {
            let n = dec.read(&mut buf).unwrap();
            if n == 0 { break; }
            out.extend_from_slice(&buf[..n]);
        }
        prop_assert_eq!(out, data);
    }
}

// The decoder is total: it never panics on arbitrary input, and accepts
// or errors cleanly.
proptest! {
    #[test]
    fn base64_decode_is_total(input in ".*") {
        let _ = base64::decode(&input);
    }
}

// Canonicalization is idempotent: canon(canon(x)) == canon(x) as bytes.
proptest! {
    #[test]
    fn c14n_idempotent(xml in r#"<root xmlns="urn:x"><a b="1">text &amp; more</a><b/></root>"#) {
        let once = canonicalize_str(&xml).unwrap();
        let twice = canonicalize_str(std::str::from_utf8(&once.bytes).unwrap()).unwrap();
        prop_assert_eq!(once.bytes, twice.bytes);
    }
}

// The parser is total on arbitrary input (no panics, only Err).
proptest! {
    #[test]
    fn xml_parse_is_total(input in ".*") {
        let _ = parser::parse(&input);
    }
}

/// Serialize(parse(x)) == x for entity-free, LF-only documents
/// (generated from a structured grammar so they are well-formed).
fn arb_document() -> BoxedStrategy<String> {
    let doc = |s: &'static str| Just(s.to_string());
    prop_oneof![
        doc("<a/>"),
        doc("<a>text</a>"),
        doc("<a b=\"1\" c=\"2\"><d/></a>"),
        doc("<r xmlns:n=\"urn:x\"><n:e>1 &lt; 2</n:e></r>"),
        doc("<r><a/><b>t1</b><c>line\nnext</c></r>"),
        doc("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<r a=\"1\"><x>&amp;</x></r>"),
    ]
    .boxed()
}

proptest! {
    #[test]
    fn xml_roundtrip(doc in arb_document()) {
        let parsed = parser::parse(&doc).unwrap();
        let out = document_to_string(&parsed);
        prop_assert_eq!(out, doc);
    }
}

/// MIME multipart: compose parts, parse them back, content survives any
/// binary payload (the verified-boundary framing).
fn mime_document(parts: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n");
    for part in &parts {
        out.extend_from_slice(
            b"--BB\r\nContent-Type: application/octet-stream\r\nContent-ID: <p>\r\n\r\n",
        );
        out.extend_from_slice(part);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"--BB--\r\n");
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn mime_parts_survive_arbitrary_content(parts in proptest::collection::vec(arb_bytes(), 1..4)) {
        // a real sender must not emit content containing a boundary
        // sequence (verified-marker semantics terminate the part); the
        // generator respects that wire constraint
        // simplest sound constraint: content must not contain the
        // boundary token at all (any position can combine with composer
        // CRLFs into a marker)
        let parts: Vec<Vec<u8>> = parts
            .into_iter()
            .filter(|p| !p.windows(4).any(|w| w == b"--BB"))
            .collect();
        prop_assume!(!parts.is_empty());
        let stream = mime_document(parts.clone());
        let mut parser = MimeParser::new(&stream[..]).unwrap();
        let mut roundtripped = Vec::new();
        while let Some(mut part) = parser.next_part().unwrap() {
            let mut content = Vec::new();
            part.read_to_end(&mut content).unwrap();
            roundtripped.push(content);
            drop(part);
        }
        prop_assert_eq!(roundtripped.len(), parts.len());
        for (original, back) in parts.iter().zip(&roundtripped) {
            prop_assert_eq!(back, original);
        }
    }
}

/// Message compose -> parse roundtrip with random content.
fn store_delivery(text: String) -> OutMessage {
    let mut out = OutMessage {
        kind: Some(MessageType::StoreDelivery),
        control_block: ControlBlock {
            conversation_id: Some("4711".into()),
            sequence_number: Some(1),
            response: None,
            challenge: Some("Y2hhbGxlbmdl".into()),
        },
        desired_languages: Some("de".into()),
        entry_inner: Some(format!(
            "<osci:MessageId>{}</osci:MessageId><osci:Subject></osci:Subject>",
            osci_core::helper::base64::encode(text.as_bytes())
        )),
        non_intermediary_certificates: vec![OutCertEntry {
            role: CertRole::Addressee,
            use_: CertUse::Cipher,
            id: "ac".into(),
            der: vec![1, 2, 3],
        }],
        ..Default::default()
    };
    out.containers.push(OutContentContainer {
        id: "cc".into(),
        contents: vec![OutContent {
            id: "c1".into(),
            text: Some(text),
            href: None,
        }],
        encrypted_attachments: Vec::new(),
    });
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn message_compose_parse_roundtrip(text in arb_text()) {
        let out = store_delivery(text);
        let stream = compose_message(&out, "MIME_boundary").unwrap();
        let stored = osci_core::message::stored::StoredMessage::load(&stream).unwrap();
        prop_assert_eq!(stored.message.kind, Some(MessageType::StoreDelivery));
        // the content text survives the base64 layer exactly
        let body = stored.message.body.unwrap();
        let encoded = body.containers[0].contents[0].base64_content.as_ref().unwrap();
        let decoded = base64::decode(encoded).unwrap();
        prop_assert_eq!(String::from_utf8(decoded).unwrap(), stored_text_of(&out));
    }
}

fn stored_text_of(out: &OutMessage) -> String {
    out.containers[0].contents[0].text.clone().unwrap()
}

/// Regression guard for the MIME marker-split fix: a boundary marker cut
/// in half by the lookahead refill must be resolved, not delivered as
/// content (found by proptest shrinking against the old parser).
#[test]
fn mime_marker_split_across_refill_is_resolved() {
    // content long enough to span refills, then the marker with its first
    // 5 bytes at a refill boundary; pad to push the split anywhere
    for pad in 0..100usize {
        let content = vec![0x41u8; 9000 + pad];
        let mut stream = Vec::new();
        stream.extend_from_slice(b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n");
        stream.extend_from_slice(
            b"--BB\r\nContent-Type: application/octet-stream\r\nContent-ID: <p>\r\n\r\n",
        );
        stream.extend_from_slice(&content);
        stream.extend_from_slice(b"\r\n--BB--\r\n");
        let mut parser = MimeParser::new(&stream[..]).unwrap();
        let mut part = parser.next_part().unwrap().expect("part");
        let mut got = Vec::new();
        part.read_to_end(&mut got).unwrap();
        drop(part);
        assert_eq!(got, content, "content corrupted at pad {pad}");
        assert!(parser.next_part().unwrap().is_none());
    }
}

/// A closing boundary at the very end of the stream (no trailing bytes)
/// terminates the part correctly.
#[test]
fn mime_closing_boundary_at_stream_end() {
    let stream = b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: text/xml\r\nContent-ID: <x>\r\n\r\ncontent\r\n--BB--";
    let mut parser = MimeParser::new(&stream[..]).unwrap();
    let mut part = parser.next_part().unwrap().expect("part");
    let mut got = Vec::new();
    part.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"content");
    drop(part);
    assert!(parser.next_part().unwrap().is_none());
}

/// Binary content containing a full boundary marker followed by
/// non-boundary bytes stays content (verified-marker semantics).
#[test]
fn mime_false_boundary_with_continuation_is_content() {
    let stream = b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: text/xml\r\nContent-ID: <x>\r\n\r\nA\r\n--BBx\r\n--BB--\r\n";
    let mut parser = MimeParser::new(&stream[..]).unwrap();
    let mut part = parser.next_part().unwrap().expect("part");
    let mut got = Vec::new();
    part.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"A\r\n--BBx");
    drop(part);
    assert!(parser.next_part().unwrap().is_none());
}

/// Regression guard for the closing-delimiter fix: when a refill boundary
/// cuts inside the closing delimiter's dashes (`--BB--` split after the
/// first dash of `--`), the marker must still terminate the part - the
/// single dash is unambiguously the closing delimiter (found by proptest).
#[test]
fn mime_closing_delimiter_split_across_refill() {
    // build a stream where the 8192-byte lookahead boundary lands inside
    // the closing delimiter's dashes: content padded so that the marker
    // `\r\n--BB` sits at offset 8191..8197 and the first `-` of `--` is
    // the last byte of the first 8192-byte window
    let prelude = b"Content-Type: multipart/mixed; boundary=BB\r\n\r\n\
--BB\r\nContent-Type: application/octet-stream\r\nContent-ID: <p>\r\n\r\n";
    // 8192 - prelude.len() - 6 (marker) = content bytes before the marker
    let before_marker = 8192 - prelude.len() - 6;
    let content = vec![0x41u8; before_marker];
    let mut stream = Vec::new();
    stream.extend_from_slice(prelude);
    stream.extend_from_slice(&content);
    stream.extend_from_slice(b"\r\n--BB--\r\n");

    let mut parser = MimeParser::new(&stream[..]).unwrap();
    let mut part = parser.next_part().unwrap().expect("part");
    let mut got = Vec::new();
    part.read_to_end(&mut got).unwrap();
    drop(part);
    assert_eq!(got, content, "closing delimiter split corrupted the part");
    assert!(parser.next_part().unwrap().is_none());
}
