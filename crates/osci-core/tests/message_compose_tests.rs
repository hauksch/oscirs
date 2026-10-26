//! M5b gate: composed messages re-parse into the same model, validate
//! against the XSD corpus through the Java oracle, and produce correct
//! MIME structure readable by our own parser.

mod common;

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use chrono::TimeZone as _;
use osci_core::helper::base64;
use osci_core::helper::mime::MimeParser;
use osci_core::message::compose::{
    OutAttachment, OutCertEntry, OutContent, OutContentContainer, OutFeedback, OutMessage,
    OutProcessCard, OutProcessCardBundle, compose_message,
};
use osci_core::message::{MessageType, parse_message};
use osci_core::soap::{CertEntry, CertRole, CertUse, ControlBlock};
use osci_core::xml::parser;

/// Extract the first CERTIFICATE block of a PEM dump as DER (the test
/// only needs bytes for the wire; parsing lives in osci-crypto).
fn first_cert_der(pem_name: &str) -> Vec<u8> {
    let dump = std::fs::read_to_string(common::corpus().join("certs").join(pem_name)).unwrap();
    let start = dump.find("-----BEGIN CERTIFICATE-----").unwrap();
    let after = &dump[start + "-----BEGIN CERTIFICATE-----".len()..];
    let end = after.find("-----END CERTIFICATE-----").unwrap();
    let b64: String = after[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64::decode(&b64).unwrap()
}

fn alice_cipher_cert() -> CertEntry {
    CertEntry {
        id: "originator_cipher_test".into(),
        der: first_cert_der("alice_cipher_4096.pem"),
    }
}

fn store_delivery_out() -> OutMessage {
    let cert = alice_cipher_cert();
    let mut msg = OutMessage {
        kind: Some(MessageType::StoreDelivery),
        control_block: ControlBlock {
            conversation_id: Some("42".into()),
            sequence_number: Some(1),
            response: None,
            challenge: Some("Y2hhbGxlbmdl".into()),
        },
        desired_languages: Some("de".into()),
        quality_creation: Some(false),
        quality_reception: Some(true),
        entry_inner: Some(
            "<osci:MessageId>bXNnLWlkLTEyMw==</osci:MessageId><osci:Subject>Hello</osci:Subject>"
                .into(),
        ),
        // schema order: cipher certificates precede signature ones, and
        // the addressee cipher certificate is mandatory (minOccurs=1)
        non_intermediary_certificates: vec![
            OutCertEntry {
                role: CertRole::Originator,
                use_: CertUse::Cipher,
                id: cert.id.clone(),
                der: cert.der.clone(),
            },
            OutCertEntry {
                role: CertRole::Addressee,
                use_: CertUse::Cipher,
                id: "addressee_cipher_test".into(),
                der: first_cert_der("bob_cipher_4096.pem"),
            },
        ],
        ..Default::default()
    };
    msg.containers.push(OutContentContainer {
        id: "contentcontainer".into(),
        contents: vec![
            OutContent {
                id: "content1".into(),
                text: Some("clear text content".into()),
                href: None,
            },
            OutContent {
                id: "content2".into(),
                text: None,
                href: Some("cid:test.txt".into()),
            },
        ],
        encrypted_attachments: Vec::new(),
    });
    msg.attachments.push(OutAttachment {
        content_id: "test.txt".into(),
        content_type: "application/octet-stream".into(),
        base64_encoding: false,
        data: b"attached data".to_vec(),
    });
    msg
}

/// The composed stream is well-formed for our own MIME + XML + message
/// parsers, and the parsed model matches what we composed.
#[test]
fn store_delivery_compose_parse_roundtrip() {
    let out = store_delivery_out();
    let stream = compose_message(&out, "MIME_boundary").unwrap();

    let mut mime = MimeParser::new(&stream[..]).unwrap();
    let mut part = mime.next_part().unwrap().expect("xml part");
    assert_eq!(part.content_id(), "osci@message");
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();

    let doc = parser::parse(&String::from_utf8(xml).unwrap()).unwrap();
    let parsed = parse_message(&doc).unwrap();
    assert_eq!(parsed.kind, Some(MessageType::StoreDelivery));
    let request = parsed.request.as_ref().unwrap();
    assert_eq!(request.message_id.as_deref(), Some("bXNnLWlkLTEyMw=="));
    assert_eq!(request.subject.as_deref(), Some("Hello"));
    let body = parsed.body.as_ref().expect("body");
    assert_eq!(body.containers.len(), 1);
    assert_eq!(body.containers[0].contents.len(), 2);
    assert_eq!(
        body.containers[0].contents[1].href.as_deref(),
        Some("cid:test.txt")
    );

    // attachment part
    drop(part);
    let mut att = mime.next_part().unwrap().expect("attachment part");
    assert_eq!(att.content_id(), "test.txt");
    let mut data = Vec::new();
    att.read_to_end(&mut data).unwrap();
    drop(att);
    assert_eq!(data, b"attached data");
    assert!(mime.next_part().unwrap().is_none(), "closing boundary");
}

/// The XML part validates against the XSD corpus through the Java oracle.
#[test]
fn composed_messages_validate_against_xsd() {
    if !oracle_available() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    // the NonIntermediaryCertificates content is restricted per message
    // type: StoreDelivery wants cipher certs (addressee's mandatory),
    // FetchDelivery ONLY the signature certificate of the originator,
    // InitDialog the originator's cipher certificate
    let cases = vec![
        (store_delivery_out(), "StoreDelivery"),
        (
            OutMessage {
                kind: Some(MessageType::FetchDelivery),
                control_block: ControlBlock {
                    sequence_number: Some(0),
                    response: Some("cmVzcG9uc2U=".to_string()),
                    // fetch deliveries run inside an established dialog
                    conversation_id: Some("42".to_string()),
                    challenge: Some("Y2hhbGxlbmdl".to_string()),
                },
                desired_languages: Some("de".into()),
                selection_rule: Some("bXNn".into()),
                entry_inner: Some("bXNnLW91dA==".into()),
                non_intermediary_certificates: vec![OutCertEntry {
                    role: CertRole::Originator,
                    use_: CertUse::Signature,
                    id: "originator_signature_test".into(),
                    der: first_cert_der("alice_signature_4096.pem"),
                }],
                ..Default::default()
            },
            "FetchDelivery",
        ),
        (
            OutMessage {
                kind: Some(MessageType::InitDialog),
                control_block: ControlBlock {
                    // no SequenceNumber: the dialog is not established yet
                    sequence_number: None,
                    challenge: Some("Y2hhbGxlbmdl".to_string()),
                    conversation_id: None,
                    response: None,
                },
                desired_languages: Some("de".into()),
                non_intermediary_certificates: vec![OutCertEntry {
                    role: CertRole::Originator,
                    use_: CertUse::Cipher,
                    id: "originator_cipher_test".into(),
                    der: first_cert_der("alice_cipher_4096.pem"),
                }],
                ..Default::default()
            },
            "InitDialog",
        ),
    ];
    for (out, label) in cases {
        let stream = compose_message(&out, "MIME_boundary").unwrap();
        let mut mime = MimeParser::new(&stream[..]).unwrap();
        let mut part = mime.next_part().unwrap().expect("xml part");
        let mut xml = Vec::new();
        part.read_to_end(&mut xml).unwrap();
        let verdict = oracle_validate(&xml);
        if verdict.0 != "VALID" {
            std::fs::write("/tmp/composed_failed.xml", &xml).unwrap();
            panic!("{label}: XSD validation failed: {:?}", verdict.1);
        }
    }
}

fn workspace_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn oracle_available() -> bool {
    workspace_root().join("oracle/build/classpath.txt").exists()
}

fn oracle_validate(xml: &[u8]) -> (String, Option<String>) {
    let root = workspace_root();
    let classpath = std::fs::read_to_string(root.join("oracle/build/classpath.txt"))
        .expect("oracle not built - run scripts/build-oracle.sh");
    let classpath = format!(
        "{}:{}",
        root.join("oracle/build").display(),
        classpath.trim()
    );
    let java = std::env::var_os("OSCI_JAVA")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("tools/jdk11/bin/java"));
    let corpus = std::env::var_os("OSCI_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("testcorpus"));
    let mut child = Command::new(&java)
        .arg("-cp")
        .arg(&classpath)
        .arg("osci.oracle.CryptoSpike")
        .arg("validate")
        .arg(corpus.join("xsd"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn java");
    child.stdin.take().unwrap().write_all(xml).unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let detail = stdout
        .lines()
        .next()
        .map(str::to_string)
        .filter(|l| !l.starts_with("VALID"));
    (
        if stdout.starts_with("VALID") {
            "VALID".into()
        } else {
            "INVALID".into()
        },
        detail,
    )
}

use std::io::Write;

/// Responses with feedback and process cards compose and re-parse.
#[test]
fn response_compose_roundtrip() {
    let mut bundle = OutProcessCardBundle {
        message_id: Some("cHJvY2Vzcy1pZA==".into()),
        ..Default::default()
    };
    bundle.process_cards.push(OutProcessCard {
        creation: Some(
            chrono::Utc
                .with_ymd_and_hms(2026, 10, 11, 10, 0, 0)
                .unwrap(),
        ),
        forwarding: None,
        reception: None,
        subject: Some("Subject".into()),
    });
    let out = OutMessage {
        kind: Some(MessageType::ResponseToStoreDelivery),
        control_block: ControlBlock {
            conversation_id: Some("42".into()),
            sequence_number: Some(2),
            response: Some("cmVzcG9uc2U=".into()),
            ..Default::default()
        },
        feedback: vec![OutFeedback {
            language: Some("de".into()),
            code: "0801".into(),
            text: "Auftrag ausgeführt, Dialog weiterhin geöffnet".into(),
        }],
        process_card_bundles: vec![bundle],
        ..Default::default()
    };
    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let mut mime = MimeParser::new(&stream[..]).unwrap();
    let mut part = mime.next_part().unwrap().expect("xml part");
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();

    let doc = parser::parse(&String::from_utf8(xml).unwrap()).unwrap();
    let parsed = parse_message(&doc).unwrap();
    assert_eq!(parsed.kind, Some(MessageType::ResponseToStoreDelivery));
    assert_eq!(parsed.feedback.len(), 1);
    assert_eq!(parsed.feedback[0].code, "0801");
    assert_eq!(parsed.feedback[0].language.as_deref(), Some("de"));
    let parsed_bundle = &parsed.process_card_bundles[0];
    assert_eq!(
        parsed_bundle.message_id.as_deref(),
        Some("cHJvY2Vzcy1pZA==")
    );
    assert_eq!(
        parsed_bundle.process_cards[0].subject.as_deref(),
        Some("Subject")
    );
    assert!(parsed_bundle.process_cards[0].creation.is_some());
}

/// The Base64Content of composed contents decodes back to the source text
/// (the OSCI base64 line layout is whitespace-tolerant on parse).
#[test]
fn composed_base64_content_roundtrips() {
    let out = store_delivery_out();
    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let mut mime = MimeParser::new(&stream[..]).unwrap();
    let mut part = mime.next_part().unwrap().expect("xml part");
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    let doc = parser::parse(&String::from_utf8(xml).unwrap()).unwrap();
    let parsed = parse_message(&doc).unwrap();
    let body = parsed.body.as_ref().unwrap();
    let content = &body.containers[0].contents[0];
    let encoded = content.base64_content.as_ref().unwrap();
    assert_eq!(base64::decode(encoded).unwrap(), b"clear text content");
}

/// The MIME boundary is honored end-to-end and the closing boundary
/// terminates the stream (binary attachment content with CR/LF bytes
/// cannot corrupt the framing).
#[test]
fn binary_attachment_survives_mime_framing() {
    let mut out = store_delivery_out();
    out.attachments[0].data = (0..=255u8)
        .chain(b"\r\n--MIME_boundaryX".iter().copied())
        .collect();
    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let mut mime2 = MimeParser::new(&stream[..]).unwrap();
    let mut xml_seen = false;
    let mut att_data = Vec::new();
    while let Some(mut part) = mime2.next_part().unwrap() {
        if part.content_id() == "osci@message" {
            xml_seen = true;
        } else {
            part.read_to_end(&mut att_data).unwrap();
        }
    }
    assert!(xml_seen);
    assert_eq!(att_data, out.attachments[0].data);
}

/// Issue #4 gap 1: a rule-less fetch delivery (the "ALL" selection)
/// composes WITHOUT a SelectionRule element - an empty MessageId would
/// be parsed as a selection and rejected with 9803 by the intermediary.
#[test]
fn rule_less_fetch_delivery_omits_selection_rule() {
    let out = OutMessage {
        kind: Some(MessageType::FetchDelivery),
        control_block: ControlBlock {
            sequence_number: Some(1),
            conversation_id: Some("42".into()),
            response: Some("cmVzcG9uc2U=".into()),
            challenge: Some("Y2hhbGxlbmdl".into()),
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: vec![OutCertEntry {
            role: CertRole::Originator,
            use_: CertUse::Signature,
            id: "originator_signature_test".into(),
            der: first_cert_der("alice_signature_4096.pem"),
        }],
        // no selection rule: fetch everything
        ..Default::default()
    };
    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let mut mime = MimeParser::new(&stream[..]).unwrap();
    let mut part = mime.next_part().unwrap().expect("xml part");
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    let xml = String::from_utf8(xml).unwrap();

    assert!(
        !xml.contains("SelectionRule"),
        "rule-less fetch must not carry a SelectionRule: {xml}"
    );
    // the entry element itself is still there and empty
    assert!(xml.contains("<osci:fetchDelivery"), "entry present");
    assert!(xml.contains("</osci:fetchDelivery>"), "entry closed");

    // re-parses cleanly (no selection)
    let doc = parser::parse(&xml).unwrap();
    let parsed = parse_message(&doc).unwrap();
    assert_eq!(parsed.kind, Some(MessageType::FetchDelivery));
    assert!(parsed.request.as_ref().unwrap().message_id.is_none());
}

/// Rule-carrying composition stays byte-compatible (issue #4 gap 1).
#[test]
fn rule_carrying_fetch_delivery_keeps_selection_rule() {
    let build = |rule: Option<&str>| OutMessage {
        kind: Some(MessageType::FetchDelivery),
        control_block: ControlBlock {
            sequence_number: Some(1),
            conversation_id: Some("42".into()),
            response: Some("cmVzcG9uc2U=".into()),
            challenge: Some("Y2hhbGxlbmdl".into()),
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: vec![OutCertEntry {
            role: CertRole::Originator,
            use_: CertUse::Signature,
            id: "originator_signature_test".into(),
            der: first_cert_der("alice_signature_4096.pem"),
        }],
        selection_rule: rule.map(str::to_string),
        ..Default::default()
    };
    let stream = compose_message(&build(Some("bXNn")), "MIME_boundary").unwrap();
    let mut mime = MimeParser::new(&stream[..]).unwrap();
    let mut part = mime.next_part().unwrap().expect("xml part");
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    let xml = String::from_utf8(xml).unwrap();
    assert!(
        xml.contains(
            "<osci:SelectionRule><osci:MessageId>bXNn</osci:MessageId></osci:SelectionRule>"
        ),
        "rule form unchanged: {xml}"
    );
}

/// Issue #6 part 2: PartialStoreDelivery compose fidelity for the live
/// intermediary - the creation QualityOfTimestamp header is always
/// present (plain when unset), the entry rides under the osci2017
/// namespace with the chunk attributes, and the body is one
/// ContentContainer whose Content references the chunk blob.
#[test]
fn partial_store_delivery_live_shape() {
    let out = OutMessage {
        kind: Some(MessageType::PartialStoreDelivery),
        control_block: ControlBlock {
            sequence_number: Some(1),
            conversation_id: Some("42".into()),
            response: Some("cmVzcG9uc2U=".into()),
            challenge: Some("Y2hhbGxlbmdl".into()),
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: vec![
            OutCertEntry {
                role: CertRole::Originator,
                use_: CertUse::Cipher,
                id: "originator_cipher_test".into(),
                der: first_cert_der("alice_cipher_4096.pem"),
            },
            OutCertEntry {
                role: CertRole::Addressee,
                use_: CertUse::Cipher,
                id: "addressee_cipher_test".into(),
                der: first_cert_der("bob_cipher_4096.pem"),
            },
        ],
        // quality flags unset: the creation header must STILL be emitted
        // (plain), like the reference composer's unconditional
        // qualityOfTimestampTypeCreation
        entry_inner: Some("<osci:MessageId>bXNn</osci:MessageId>".into()),
        chunk_information: Some(osci_core::message::ChunkInformation {
            chunk_number: 1,
            chunk_size: Some(64),
            total_chunk_numbers: Some(2),
            total_message_size: Some(128),
            received_chunks: Vec::new(),
        }),
        feature_description: Some(osci_core::soap::FeatureDescription {
            chunk_message_timeout: Some(60),
            max_chunk_size: Some(1024),
            max_message_size: Some(4096),
            min_chunk_size: Some(128),
            features: vec![("DisableBase64".into(), "1.0.0".into())],
        }),
        containers: vec![OutContentContainer {
            id: "ChunkContentContainer".into(),
            contents: vec![OutContent {
                id: "ChunkContent".into(),
                text: None,
                href: Some("cid:chunk-1".into()),
            }],
            encrypted_attachments: Vec::new(),
        }],
        attachments: vec![osci_core::message::compose::OutAttachment {
            content_id: "chunk-1".into(),
            content_type: "text".into(),
            base64_encoding: false,
            data: vec![0x41; 64],
        }],
        ..Default::default()
    };
    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let mut mime = MimeParser::new(&stream[..]).unwrap();
    let mut part = mime.next_part().unwrap().expect("xml part");
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    let xml = String::from_utf8(xml).unwrap();

    // creation QoT present even with the flag unset, no reception QoT
    assert!(
        xml.contains("Id=\"qualityoftimestamp_creation\" Quality=\"plain\" Service=\"creation\""),
        "creation QoT header (plain) required: {xml}"
    );
    assert!(!xml.contains("qualityoftimestamp_reception"));

    // the entry rides under the osci2017 namespace
    assert!(
        xml.contains("<osci2017:partialStoreDelivery"),
        "entry namespace osci2017: {xml}"
    );
    assert!(
        xml.contains("xmlns:osci2017=\"http://xoev.de/transport/osci12/7\""),
        "osci2017 binding present"
    );

    // chunk attributes on the entry's ChunkInformation
    assert!(xml.contains("ChunkNumber=\"1\""));
    assert!(xml.contains("ChunkSize=\"64\""));
    assert!(xml.contains("TotalChunkNumbers=\"2\""));
    assert!(xml.contains("TotalMessageSize=\"128\""));
    assert!(
        !xml.contains("ReceivedChunks="),
        "prohibited on the store side"
    );

    // body: ContentPackage with one container whose Content references
    // the chunk blob
    let body = &xml[xml.find("<soap:Body").unwrap()..];
    assert!(body.contains("<osci:ContentPackage>"));
    assert!(body.contains("<osci:ContentContainer"));
    assert!(body.contains("href=\"cid:chunk-1\""));
    assert_eq!(
        body.matches("<osci:ContentContainer").count(),
        1,
        "exactly one container"
    );

    // control block: challenge + sequence mandatory on partial requests
    // (the reference client throws without them)
    assert!(xml.contains("SequenceNumber=\"1\""));
    assert!(xml.contains("<osci:Challenge>"), "challenge child present");

    // the chunk-blob MIME part carries the reference writer's headers:
    // Content-Transfer-Encoding 8-bit (not binary) and Content-Length
    let stream_headers = xml.clone(); // xml part only; the parts are below
    let _ = stream_headers;
    let full = {
        let mut s = Vec::new();
        s.extend_from_slice(&stream);
        compose_message(&out, "MIME_boundary").unwrap()
    };
    let full = String::from_utf8(full).unwrap();
    let blob_pos = full.find("Content-ID: <chunk-1>").expect("blob part");
    let part_start = full[..blob_pos]
        .rfind("\r\n--MIME_boundary")
        .expect("blob part boundary");
    let headers_end = full[blob_pos..]
        .find("\r\n\r\n")
        .map(|p| blob_pos + p)
        .expect("header block end");
    let headers = &full[part_start..headers_end];
    assert!(
        headers.contains("Content-Type: text\r\n"),
        "caller-controlled content type: {headers}"
    );
    assert!(
        headers.contains("Content-Transfer-Encoding: 8-bit\r\n"),
        "reference CTE token: {headers}"
    );
    assert!(
        headers.ends_with("Content-Length: 64"),
        "Content-Length = raw data length: {headers}"
    );
}
