//! Issue #1 gates: outbound content + transport encryption. Every test
//! composes with oscirs and decrypts/verifies through our own pipeline.

mod common;

use std::io::Read;

use base64::Engine as _;
use osci::security::{
    EncRecipient, EncryptConfig, decrypt_all_encrypted_data, decrypt_transport_message,
    encrypt_container, encrypt_message_for,
};
use osci_core::message::MessageType;
use osci_core::message::compose::{OutCertEntry, OutContent, OutContentContainer, OutMessage};
use osci_core::soap::{CertRole, CertUse, ControlBlock};
use osci_crypto::software::{Decrypter, RsaDecrypter};

fn corpus() -> std::path::PathBuf {
    common::corpus()
}

fn cert_der(pem: &str) -> Vec<u8> {
    let dump = std::fs::read_to_string(corpus().join("certs").join(pem)).unwrap();
    let start = dump.find("-----BEGIN CERTIFICATE-----").unwrap();
    let after = &dump[start + 27..];
    let end = after.find("-----END CERTIFICATE-----").unwrap();
    let b64: String = after[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    osci_core::helper::base64::decode(&b64).unwrap()
}

fn inner_container() -> OutContentContainer {
    OutContentContainer {
        id: "contentcontainer_inner".into(),
        contents: vec![OutContent {
            id: "content_inner".into(),
            text: Some("encrypted payload data".into()),
            href: None,
        }],
    }
}

/// Roundtrip: encrypt_container -> compose -> parse -> decrypt through
/// the corpus reader keys, for every cipher x key-transport combination.
#[test]
fn content_encryption_roundtrips_all_combinations() {
    let reader =
        RsaDecrypter::from_pem_dump(corpus().join("certs/bob_cipher_4096.pem").to_str().unwrap())
            .unwrap();
    let decrypters: Vec<&dyn Decrypter> = vec![&reader];
    let recipients = vec![EncRecipient {
        cert: osci_crypto::Certificate::from_der(&cert_der("bob_cipher_4096.pem")).unwrap(),
        cert_element_id: "addressee_cipher".into(),
    }];

    let cipher_cases = [
        (osci_crypto::algorithms::CIPHER_AES256_GCM, 12usize),
        (osci_crypto::algorithms::CIPHER_AES128_CBC, 16),
        (osci_crypto::algorithms::CIPHER_TRIPLEDES_CBC, 8),
    ];
    let transport_cases = [
        (
            osci_crypto::algorithms::KEY_TRANSPORT_RSA_OAEP,
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ),
        (osci_crypto::algorithms::KEY_TRANSPORT_RSA_1_5, ""),
    ];

    for (cipher_uri, iv_len) in cipher_cases {
        for (kt_uri, digest) in transport_cases {
            let config = EncryptConfig {
                content_cipher: cipher_uri.into(),
                key_transport: osci_core::message::compose::KeyTransportParams {
                    algorithm: kt_uri.into(),
                    mgf: (!digest.is_empty())
                        .then(|| "http://www.w3.org/2009/xmlenc11#mgf1sha256".into()),
                    digest: (!digest.is_empty()).then(|| digest.into()),
                },
            };
            let enc = encrypt_container(
                &inner_container(),
                &recipients,
                &config,
                Some("encdata_0".into()),
                None,
            )
            .unwrap_or_else(|e| panic!("{cipher_uri}/{kt_uri}: encrypt failed: {e}"));
            assert_eq!(enc.iv_len, iv_len, "{cipher_uri} IV length");

            let out = OutMessage {
                kind: Some(MessageType::StoreDelivery),
                control_block: ControlBlock {
                    sequence_number: Some(1),
                    challenge: Some("Y2hhbGxlbmdl".into()),
                    conversation_id: Some("42".into()),
                    response: None,
                },
                encrypted_data: vec![enc],
                ..Default::default()
            };
            let stream =
                osci_core::message::compose::compose_message(&out, "MIME_boundary").unwrap();
            let stored = osci_core::message::stored::StoredMessage::load(&stream)
                .unwrap_or_else(|e| panic!("{cipher_uri}/{kt_uri}: load: {e}"));
            let xml = String::from_utf8(stored.xml.clone()).unwrap();
            let decrypted = decrypt_all_encrypted_data(&xml, &decrypters)
                .unwrap_or_else(|e| panic!("{cipher_uri}/{kt_uri}: decrypt: {e}"));
            assert_eq!(decrypted.len(), 1, "{cipher_uri}/{kt_uri}");
            let plain = String::from_utf8(decrypted[0].plaintext.clone()).unwrap();
            // the container writer base64-encodes the text
            let expected_b64 =
                base64::engine::general_purpose::STANDARD.encode("encrypted payload data");
            assert!(
                plain.contains(&expected_b64),
                "{cipher_uri}/{kt_uri}: plaintext mismatch: {plain}"
            );
        }
    }
    drop(decrypters);
}

/// Signed-AND-encrypted: the transport signature covers the body
/// including the EncryptedData; tampering the ciphertext breaks the
/// #body digest.
#[test]
fn signed_and_encrypted_verifies_and_tamper_detected() {
    let signer = osci_crypto::software::RsaSigner::from_pem_dump(
        corpus()
            .join("certs/alice_signature_4096.pem")
            .to_str()
            .unwrap(),
        None,
    )
    .unwrap();

    let mut out = OutMessage {
        kind: Some(MessageType::StoreDelivery),
        control_block: ControlBlock {
            conversation_id: Some("42".into()),
            sequence_number: Some(1),
            response: None,
            challenge: Some("Y2hhbGxlbmdl".into()),
        },
        non_intermediary_certificates: vec![
            OutCertEntry {
                role: CertRole::Originator,
                use_: CertUse::Signature,
                id: "originator_signature".into(),
                der: cert_der("alice_signature_4096.pem"),
            },
            OutCertEntry {
                role: CertRole::Addressee,
                use_: CertUse::Cipher,
                id: "addressee_cipher".into(),
                der: cert_der("bob_cipher_4096.pem"),
            },
        ],
        ..Default::default()
    };
    let enc = osci::security::encrypt_container(
        &inner_container(),
        &[EncRecipient {
            cert: osci_crypto::Certificate::from_der(&cert_der("bob_cipher_4096.pem")).unwrap(),
            cert_element_id: "addressee_cipher".into(),
        }],
        &EncryptConfig::default(),
        Some("encdata_0".into()),
        None,
    )
    .unwrap();
    out.encrypted_data.push(enc);

    let stream = osci_core::message::compose::compose_message(&out, "MIME_boundary").unwrap();
    let mut mime = osci_core::helper::mime::MimeParser::new(&stream[..]).unwrap();
    let mut part = mime.next_part().unwrap().unwrap();
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    let xml = String::from_utf8(xml).unwrap();

    let signed = osci::sign::sign_message_xml(
        &xml,
        &osci::sign::SignParams {
            signer: &signer,
            method: None,
            digest: None,
            certificate_id: "originator_signature".into(),
            attachments: &[],
        },
    )
    .unwrap();

    let report = osci::security::verify_message(&signed, &[]).unwrap();
    assert!(report.all_valid(), "signed encrypted message: {report:#?}");

    // tamper the ciphertext: flip two characters inside the LAST
    // CipherValue (the content ciphertext, not the wrapped key)
    let marker = "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>";
    let pos = signed.find(marker).unwrap();
    let tampered = format!("{}ZZ{}", &signed[..pos - 42], &signed[pos - 40..]);
    let report2 = osci::security::verify_message(&tampered, &[]).unwrap();
    assert!(!report2.all_valid(), "tampered ciphertext passed");
}

/// Transport envelope: shape (Body = single EncryptedData with
/// CipherReference cid:osci_enc, inline cert) and roundtrip — decrypt
/// with the intermediary key recovers the exact inner stream.
#[test]
fn transport_envelope_shape_and_roundtrip() {
    let out = OutMessage {
        kind: Some(MessageType::GetMessageId),
        control_block: ControlBlock {
            challenge: Some("Y2hhbGxlbmdl".into()),
            conversation_id: Some("4711".into()),
            response: None,
            sequence_number: None,
        },
        ..Default::default()
    };
    let signed_stream =
        osci_core::message::compose::compose_message(&out, "MIME_boundary").unwrap();

    let recipient =
        osci_crypto::Certificate::from_der(&cert_der("osci_manager_cipher_4096.pem")).unwrap();
    let outer = encrypt_message_for(
        &signed_stream,
        &recipient,
        &EncryptConfig::default(),
        "MIME_boundary",
    )
    .unwrap();

    let outer_str = String::from_utf8_lossy(&outer).into_owned();
    assert!(outer_str.contains("MimeType=\"Multipart/Related\""));
    assert!(outer_str.contains("URI=\"cid:osci_enc\""));
    assert!(outer_str.contains("soapMessageEncrypted.xsd"));
    assert!(!outer_str.contains("<osci:GetMessageId"), "inner leaked");

    let stored = osci_core::message::stored::StoredMessage::load(&outer).unwrap();
    assert!(stored.message.kind.is_none(), "inner message is opaque");
    assert_eq!(
        stored.message.body.as_ref().unwrap().encrypted_data.len(),
        1
    );

    let manager = RsaDecrypter::from_pem_dump(
        corpus()
            .join("certs/osci_manager_cipher_4096.pem")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let mgr_ref = &manager as &dyn Decrypter;
    let attachments: Vec<osci_core::message::stored::LoadedAttachment> = stored
        .attachments
        .iter()
        .map(|a| osci_core::message::stored::LoadedAttachment {
            content_id: a.content_id.clone(),
            content_type: a.content_type.clone(),
            encoding: a.encoding.clone(),
            data: a.data.clone(),
        })
        .collect();
    let view = osci::security::StoredMessageLike {
        xml: &stored.xml,
        attachments: &attachments,
    };
    let inner = decrypt_transport_message(&view, &[mgr_ref]).unwrap();

    assert_eq!(inner, signed_stream, "inner stream recovered byte-exact");
}

/// The composed EncryptedData decrypts to a ContentContainer whose XML
/// matches the plain writeContainerXml shape (the same bytes Java's
/// container writer produces).
#[test]
fn encrypted_plaintext_matches_container_writer() {
    let reader =
        RsaDecrypter::from_pem_dump(corpus().join("certs/bob_cipher_4096.pem").to_str().unwrap())
            .unwrap();
    let decrypters: Vec<&dyn Decrypter> = vec![&reader];

    let inner = inner_container();
    let mut expected = Vec::new();
    osci_core::message::compose::write_container_xml(
        &inner,
        &mut osci_core::xml::writer::XmlWriter::new(&mut expected),
    );

    let enc = encrypt_container(
        &inner,
        &[EncRecipient {
            cert: osci_crypto::Certificate::from_der(&cert_der("bob_cipher_4096.pem")).unwrap(),
            cert_element_id: "addressee_cipher".into(),
        }],
        &EncryptConfig {
            content_cipher: osci_crypto::algorithms::CIPHER_AES128_CBC.into(),
            ..Default::default()
        },
        Some("encdata_0".into()),
        None,
    )
    .unwrap();

    let out = OutMessage {
        kind: Some(MessageType::StoreDelivery),
        control_block: ControlBlock::default(),
        encrypted_data: vec![enc],
        ..Default::default()
    };
    let stream = osci_core::message::compose::compose_message(&out, "MIME_boundary").unwrap();
    let stored = osci_core::message::stored::StoredMessage::load(&stream).unwrap();
    let xml = String::from_utf8(stored.xml.clone()).unwrap();
    let decrypted = decrypt_all_encrypted_data(&xml, &decrypters).unwrap();
    assert_eq!(decrypted[0].plaintext, expected, "container XML shape");
}

/// Issue #2: the transport cipher part is written as RAW binary (Java
/// 2.6.1 dialect) — CTE binary, octets of IV || ciphertext || tag, no
/// base64 and no line breaking.
#[test]
fn transport_cipher_part_is_binary_dialect() {
    let out = OutMessage {
        kind: Some(MessageType::GetMessageId),
        control_block: ControlBlock {
            challenge: Some("Y2hhbGxlbmdl".into()),
            conversation_id: Some("4711".into()),
            response: None,
            sequence_number: None,
        },
        ..Default::default()
    };
    let signed_stream =
        osci_core::message::compose::compose_message(&out, "MIME_boundary").unwrap();
    let recipient =
        osci_crypto::Certificate::from_der(&cert_der("osci_manager_cipher_4096.pem")).unwrap();
    let outer = encrypt_message_for(
        &signed_stream,
        &recipient,
        &EncryptConfig::default(),
        "MIME_boundary",
    )
    .unwrap();

    let stored = osci_core::message::stored::StoredMessage::load(&outer).unwrap();
    let part = &stored.attachments[0];
    assert_eq!(part.content_id, "osci_enc");
    assert_eq!(part.content_type, "application/octet-stream");
    assert_eq!(part.encoding.as_deref(), Some("binary"));
    // raw bytes kept: the framed length is the inner message + IV + tag
    assert_eq!(
        part.data.len(),
        signed_stream.len() + 12 + 16,
        "raw IV||ct||tag octets, not base64 text"
    );
    // and the first 12 bytes ARE the IV (byte-exact recovery below in
    // transport_envelope_shape_and_roundtrip)
}

/// Issue #2 acceptance: oscirs decrypts a Java-written transport
/// envelope. StrDel_Encrypted_cbc.osci is the reference stack's output
/// (aes256-cbc + rsa-1_5, legacy base64-text dialect, inline
/// test_osci-manager cert); the fixture is LF-only so both parts are
/// extracted by byte surgery.
#[test]
fn java_written_transport_envelope_decrypts() {
    let bytes = std::fs::read(common::message("StrDel_Encrypted_cbc.osci")).unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();

    // XML part: from the first part's blank line to the next boundary
    let xml_start = text.find("<?xml").expect("xml decl");
    let xml_end = text[xml_start..].find("\n--").unwrap() + xml_start;
    let xml = text[xml_start..xml_end].to_string();

    // osci_enc part: base64 text between its blank line and the next
    // boundary
    let enc_marker = "Content-ID: <osci_enc>";
    let enc_pos = text.find(enc_marker).expect("osci_enc part");
    let enc_body_start = text[enc_pos..].find("\n\n").unwrap() + enc_pos + 2;
    let enc_end = text[enc_body_start..].find("\n--").unwrap() + enc_body_start;
    let b64_text = text[enc_body_start..enc_end].to_string();

    // parse sanity check; build the view with the raw base64 TEXT kept
    // (the legacy dialect) — decrypt_transport_message decodes it
    let doc = osci_core::xml::parser::parse(&xml).unwrap();
    assert!(doc.root.elements().count() > 0);
    let b64_bytes = b64_text.into_bytes();
    let attachments = vec![osci_core::message::stored::LoadedAttachment {
        content_id: "osci_enc".into(),
        content_type: "text/base64".into(),
        encoding: Some("7bit".into()),
        data: b64_bytes,
    }];
    let view = osci::security::StoredMessageLike {
        xml: xml.as_bytes(),
        attachments: &attachments,
    };

    // the fixture's inline cert is the alt/test_osci-manager key pair
    let manager = RsaDecrypter::from_pem_dump(
        corpus()
            .join("certs/alt/test_osci-manager_cypher.pem")
            .to_str()
            .unwrap(),
    )
    .unwrap();

    let inner = decrypt_transport_message(&view, &[&manager]).unwrap();
    // the inner message is a complete signed StoreDelivery
    assert!(inner.starts_with(b"MIME-Version"), "inner MIME stream");
    let stored = osci_core::message::stored::StoredMessage::load(&inner).unwrap();
    assert_eq!(stored.message.kind, Some(MessageType::StoreDelivery));
    assert!(
        !stored.attachments.is_empty(),
        "inner attachments recovered"
    );
}

/// Dialect-compat: a legacy base64-text cipher part (CTE 7bit +
/// text/base64, the pre-2.6.1 fixture dialect) decrypts as well as the
/// binary dialect — the whole transport envelope is re-framed, then
/// loaded and decrypted through the normal path.
#[test]
fn legacy_base64_text_dialect_accepted() {
    let inner_signed = b"MIME-Version: 1.0\r\nContent-Type: text/xml\r\n\r\n<xml/>";
    let recipient =
        osci_crypto::Certificate::from_der(&cert_der("osci_manager_cipher_4096.pem")).unwrap();
    let outer = encrypt_message_for(
        inner_signed,
        &recipient,
        &EncryptConfig::default(),
        "MIME_boundary",
    )
    .unwrap();

    // extract the binary part content from the outer stream...
    let marker = b"Content-ID: <osci_enc>\r\n\r\n";
    let content_start = outer
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap()
        + marker.len();
    eprintln!(
        "DBG content_start={} outer_len={}",
        content_start,
        outer.len()
    );
    let content_end = outer[content_start..]
        .windows(4)
        .position(|w| w == b"\r\n--")
        .map(|i| content_start + i)
        .unwrap_or_else(|| {
            eprintln!(
                "DBG not found; outer tail: {:?}",
                String::from_utf8_lossy(&outer[outer.len().saturating_sub(60)..])
            );
            panic!("no closing boundary after content_start");
        });
    let framed = outer[content_start..content_end].to_vec();

    // ...and re-frame the whole envelope with a legacy dialect part:
    // base64 TEXT with CTE 7bit and Content-Type text/base64
    let mut legacy = Vec::new();
    legacy.extend_from_slice(
        format!(
            "MIME-Version: 1.0\r\nContent-Type: Multipart/Related; boundary={boundary}; type=text/xml\r\n",
            boundary = "MIME_boundary"
        )
        .as_bytes(),
    );
    legacy.extend_from_slice(
        b"\r\n--MIME_boundary\r\nContent-Type: text/xml; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <osci@message>\r\n\r\n",
    );
    // reuse the outer XML part (up to its Content-Length framing)
    let xml_marker = b"Content-ID: <osci@message>\r\nContent-Length: ";
    let hdr_pos = outer
        .windows(xml_marker.len())
        .position(|w| w == xml_marker)
        .expect("xml part header");
    let body_start = hdr_pos
        + xml_marker.len()
        + outer[hdr_pos + xml_marker.len()..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header end")
        + 4;
    let xml_end = outer[body_start..]
        .windows(4)
        .position(|w| w == b"\r\n--")
        .map(|i| body_start + i)
        .unwrap();
    legacy.extend_from_slice(&outer[body_start..xml_end]);
    legacy.extend_from_slice(
        b"\r\n--MIME_boundary\r\nContent-Type: text/base64\r\nContent-Transfer-Encoding: 7bit\r\nContent-ID: <osci_enc>\r\n\r\n",
    );
    legacy.extend_from_slice(
        &base64::engine::general_purpose::STANDARD
            .encode(&framed)
            .into_bytes(),
    );
    legacy.extend_from_slice(b"\r\n--MIME_boundary--\r\n");

    let stored = osci_core::message::stored::StoredMessage::load(&legacy).unwrap();
    let attachments: Vec<osci_core::message::stored::LoadedAttachment> = stored
        .attachments
        .iter()
        .map(|a| osci_core::message::stored::LoadedAttachment {
            content_id: a.content_id.clone(),
            content_type: a.content_type.clone(),
            encoding: a.encoding.clone(),
            data: a.data.clone(),
        })
        .collect();
    // legacy CTE 7bit keeps the base64 TEXT raw
    assert_eq!(attachments[0].encoding.as_deref(), Some("7bit"));
    assert!(String::from_utf8(attachments[0].data.clone()).is_ok());

    let manager = RsaDecrypter::from_pem_dump(
        corpus()
            .join("certs/osci_manager_cipher_4096.pem")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let view = osci::security::StoredMessageLike {
        xml: &stored.xml,
        attachments: &attachments,
    };
    let inner = match decrypt_transport_message(&view, &[&manager]) {
        Ok(inner) => inner,
        Err(e) => panic!(
            "legacy dialect decrypt failed: {e}; attachments: {:?}",
            attachments
                .iter()
                .map(|a| (a.content_id.clone(), a.encoding.clone(), a.data.len()))
                .collect::<Vec<_>>()
        ),
    };
    assert_eq!(
        &inner[..],
        inner_signed,
        "inner recovered via legacy dialect"
    );
}
