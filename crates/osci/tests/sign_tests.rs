//! M6b gate: composed messages carry transport signatures that verify
//! BOTH in our own pipeline and in the Java reference library's parser.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use osci::security::verify_message;
use osci::sign::{SignParams, sign_message_xml};
use osci_core::message::compose::{
    OutAttachment, OutCertEntry, OutContent, OutContentContainer, OutMessage, compose_message,
};
use osci_core::message::{MessageType, parse_message};
use osci_core::soap::{CertRole, CertUse, ControlBlock};
use osci_core::xml::parser;
use osci_crypto::software::RsaSigner;

/// unsigned, XSD-valid StoreDelivery with inline content + attachment
mod common;

use common::{cert_der as first_cert_der, corpus};

fn unsigned_store_delivery() -> (OutMessage, Vec<(String, Vec<u8>)>) {
    let mut out = OutMessage {
        kind: Some(osci_core::message::MessageType::StoreDelivery),
        control_block: ControlBlock {
            conversation_id: Some("4711".into()),
            sequence_number: Some(1),
            response: None,
            challenge: Some("Y2hhbGxlbmdl".into()),
        },
        desired_languages: Some("de".into()),
        quality_creation: Some(false),
        quality_reception: Some(true),
        entry_inner: Some(
            "<osci:MessageId>bXNnLWlk</osci:MessageId><osci:Subject>Hello</osci:Subject>".into(),
        ),
        non_intermediary_certificates: vec![
            OutCertEntry {
                role: CertRole::Originator,
                use_: CertUse::Cipher,
                id: "originator_cipher".into(),
                der: first_cert_der("alice_cipher_4096.pem"),
            },
            OutCertEntry {
                role: CertRole::Originator,
                use_: CertUse::Signature,
                id: "originator_signature".into(),
                der: first_cert_der("alice_signature_4096.pem"),
            },
            OutCertEntry {
                role: CertRole::Addressee,
                use_: CertUse::Cipher,
                id: "addressee_cipher".into(),
                der: first_cert_der("bob_cipher_4096.pem"),
            },
        ],
        ..Default::default()
    };
    out.containers.push(OutContentContainer {
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
    out.attachments.push(OutAttachment {
        content_id: "test.txt".into(),
        content_type: "application/octet-stream".into(),
        base64_encoding: false,
        data: b"attached data".to_vec(),
    });
    let attachments = vec![("test.txt".to_string(), b"attached data".to_vec())];
    (out, attachments)
}

fn xml_part(stream: &[u8]) -> String {
    let mut mime = osci_core::helper::mime::MimeParser::new(stream).unwrap();
    let mut part = mime.next_part().unwrap().unwrap();
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    String::from_utf8(xml).unwrap()
}

fn alice_signer() -> RsaSigner {
    RsaSigner::from_pem_dump(
        corpus()
            .join("certs")
            .join("alice_signature_4096.pem")
            .to_str()
            .unwrap(),
        None,
    )
    .unwrap()
}

/// Feed `stream` to the Java oracle's `loadverify` mode; the caller
/// asserts on the verdict line. Requires `make oracle` (guarded by the
/// classpath check in the tests).
fn oracle_loadverify(stream: &[u8]) -> String {
    let root = corpus().parent().unwrap().to_path_buf();
    let classpath = std::fs::read_to_string(root.join("oracle/build/classpath.txt")).unwrap();
    let classpath = format!(
        "{}:{}",
        root.join("oracle/build").display(),
        classpath.trim()
    );
    let java = root.join("tools/jdk11/bin/java");
    let mut child = Command::new(&java)
        .arg("-cp")
        .arg(&classpath)
        .arg("osci.oracle.CryptoSpike")
        .arg("loadverify")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stream).unwrap();
    String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).into_owned()
}

/// Sign a composed message and verify it with our own pipeline.
#[test]
fn signed_message_verifies_locally() {
    let (out, attachments) = unsigned_store_delivery();
    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let xml = xml_part(&stream);

    let signer = alice_signer();
    let signed = sign_message_xml(
        &xml,
        &SignParams {
            signer: &signer,
            method: None,
            digest: None,
            certificate_id: "originator_signature".into(),
            attachments: &attachments,
            header_element: None,
        },
    )
    .unwrap();

    let report = verify_message(&signed, &attachments).unwrap();
    assert!(report.all_valid(), "own verification failed: {report:#?}");
    let signature = &report.signatures[0];
    assert_eq!(
        signature.certificate_id.as_deref(),
        Some("originator_signature")
    );
    assert!(
        signature.references.iter().all(|r| r.checked == Some(true)),
        "all references resolved and checked: {:?}",
        signature.references
    );

    // the signed message still parses as the same message type
    let doc = parser::parse(&signed).unwrap();
    let parsed = parse_message(&doc).unwrap();
    assert_eq!(parsed.kind, Some(MessageType::StoreDelivery));
}

/// The Java reference loads our signed message and sees the signature.
#[test]
fn signed_message_verifies_in_java_reference() {
    let root = corpus().parent().unwrap().to_path_buf();
    if !root.join("oracle/build/classpath.txt").exists() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    let (out, attachments) = unsigned_store_delivery();
    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let xml = xml_part(&stream);

    let signer = alice_signer();
    let signed = sign_message_xml(
        &xml,
        &SignParams {
            signer: &signer,
            method: None,
            digest: None,
            certificate_id: "originator_signature".into(),
            attachments: &attachments,
            header_element: None,
        },
    )
    .unwrap();

    // rebuild the full MIME stream around the signed XML: reuse the
    // composer's attachment framing by swapping the XML part
    let mut signed_stream = Vec::new();
    signed_stream.extend_from_slice(
        b"MIME-Version: 1.0\r\nContent-Type: Multipart/Related; boundary=MIME_boundary; type=text/xml\r\n\r\n--MIME_boundary\r\nContent-Type: text/xml; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <osci@message>\r\n\r\n",
    );
    signed_stream.extend_from_slice(signed.as_bytes());
    signed_stream.extend_from_slice(b"\r\n--MIME_boundary\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\nContent-ID: <test.txt>\r\n\r\nattached data");
    signed_stream.extend_from_slice(b"\r\n--MIME_boundary--\r\n");

    let stdout = oracle_loadverify(&signed_stream);
    assert!(
        stdout.starts_with("LOADED"),
        "java reference rejected our signed message: {stdout}"
    );
    assert!(
        stdout.contains("signed=true"),
        "message seen as unsigned: {stdout}"
    );
}

/// Tampering with the signed message is detected by the Java reference.
#[test]
fn tampered_signature_rejected_by_java_reference() {
    let root = corpus().parent().unwrap().to_path_buf();
    if !root.join("oracle/build/classpath.txt").exists() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    let (out, attachments) = unsigned_store_delivery();
    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let xml = xml_part(&stream);

    let signer = alice_signer();
    let mut signed = sign_message_xml(
        &xml,
        &SignParams {
            signer: &signer,
            method: None,
            digest: None,
            certificate_id: "originator_signature".into(),
            attachments: &attachments,
            header_element: None,
        },
    )
    .unwrap();

    // flip a byte in the ControlBlock challenge (signed region)
    let tampered = signed.replace("Y2hhbGxlbmdl", "Y2hhbGxlbmRn");
    assert_ne!(tampered, signed, "tampering applied");
    signed = tampered;

    // our pipeline rejects it
    let report = verify_message(&signed, &attachments).unwrap();
    assert!(!report.all_valid(), "own verification accepted tampering");

    // ... and so does the Java reference (digest of the control block no
    // longer matches the signed reference)
    let mut signed_stream = Vec::new();
    signed_stream.extend_from_slice(
        b"MIME-Version: 1.0\r\nContent-Type: Multipart/Related; boundary=MIME_boundary; type=text/xml\r\n\r\n--MIME_boundary\r\nContent-Type: text/xml; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <osci@message>\r\n\r\n",
    );
    signed_stream.extend_from_slice(signed.as_bytes());
    signed_stream.extend_from_slice(b"\r\n--MIME_boundary--\r\n");

    let stdout = oracle_loadverify(&signed_stream);
    assert!(
        stdout.starts_with("REJECTED"),
        "java reference accepted tampering: {stdout}"
    );
}

/// Custom (vendor extension) headers become transport-signature
/// references: sign a StoreDelivery carrying the corpus MessageMetaData
/// fragment and verify through our own pipeline.
#[test]
fn signed_custom_header_verifies_with_reference() {
    use osci_core::message::compose::{OutContent, OutContentContainer, OutCustomHeader};

    let mut out = OutMessage {
        kind: Some(MessageType::StoreDelivery),
        control_block: ControlBlock {
            sequence_number: Some(1),
            challenge: Some("Y2hhbGxlbmdl".into()),
            conversation_id: Some("4711".into()),
            response: None,
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: vec![
            OutCertEntry {
                role: CertRole::Originator,
                use_: CertUse::Signature,
                id: "originator_signature".into(),
                der: first_cert_der("alice_signature_4096.pem"),
            },
            OutCertEntry {
                role: CertRole::Addressee,
                use_: CertUse::Cipher,
                id: "addressee_cipher".into(),
                der: first_cert_der("bob_cipher_4096.pem"),
            },
        ],
        entry_inner: Some(
            "<osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into(),
        ),
        custom_headers: vec![OutCustomHeader {
            id: "MetaData".into(),
            xml: std::fs::read_to_string(corpus().join("extension").join("xtaMmdOsci.xml"))
                .unwrap(),
        }],
        ..Default::default()
    };
    out.containers.push(OutContentContainer {
        id: "contentcontainer".into(),
        contents: vec![OutContent {
            id: "content1".into(),
            text: Some("payload".into()),
            href: None,
        }],
        encrypted_attachments: Vec::new(),
    });
    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let xml = xml_part(&stream);
    let signer = alice_signer();
    let signed = sign_message_xml(
        &xml,
        &SignParams {
            signer: &signer,
            method: None,
            digest: None,
            certificate_id: "originator_signature".into(),
            attachments: &[],
            header_element: None,
        },
    )
    .unwrap();

    let report = osci::security::verify_message(&signed, &[]).unwrap();
    assert!(report.all_valid(), "signed with custom header: {report:#?}");
    let signed_info_refs: Vec<&str> = signed
        .match_indices("<ds:Reference URI=\"")
        .map(|(pos, _)| {
            let start = pos + "<ds:Reference URI=\"".len();
            &signed[start..start + 12]
        })
        .collect();
    assert!(
        signed_info_refs.iter().any(|r| r.starts_with("#MetaData")),
        "custom header signed as a reference: {signed_info_refs:?}"
    );
}
