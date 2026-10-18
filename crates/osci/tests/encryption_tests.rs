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
