//! M11: response-side security - the Dialog processes transport-encrypted
//! responses, verifies response signatures per policy (with the
//! weak-key/algorithm verdicts in the report), and verifies ECDSA-signed
//! documents (P-384) end to end.

mod common;

use std::io::Read;
use std::sync::Mutex;

use osci::dialog::{Dialog, DialogError, SignaturePolicy, first_feedback};
use osci::security::{SignatureResult, VerificationReport, verify_message};
use osci_core::message::MessageType;
use osci_core::message::compose::{OutCertEntry, OutMessage, compose_message};
use osci_core::message::stored::StoredMessage;
use osci_core::soap::{CertRole, CertUse, ControlBlock};
use osci_crypto::algorithms::SIGNATURE_ECDSA_SHA384;
use osci_crypto::software::{RsaDecrypter, RsaSigner, Signer};
use osci_transport::{LoopbackTransport, MockIntermediary, TransportError};

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

/// DER bytes of the PKCS#8 private key in a keystore dump.
fn private_key_der(pem_name: &str) -> Vec<u8> {
    let dump = std::fs::read_to_string(corpus().join("certs").join(pem_name)).unwrap();
    let marker = "-----BEGIN PRIVATE KEY-----";
    let start = dump.find(marker).expect("pkcs8 private key in dump") + marker.len();
    let end = dump[start..]
        .find("-----END PRIVATE KEY-----")
        .expect("private key end")
        + start;
    let b64: String = dump[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    osci_core::helper::base64::decode(&b64).unwrap()
}

/// EC P-384 signer over the `Signer` SPI (the verification pipeline is
/// key-kind agnostic; the signing side composes the method URI itself).
struct EcP384Signer {
    key: p384::ecdsa::SigningKey,
    certificate: osci_crypto::Certificate,
}

impl Signer for EcP384Signer {
    fn certificate(&self) -> &osci_crypto::Certificate {
        &self.certificate
    }

    fn sign(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, osci_crypto::CryptoError> {
        osci_crypto::software::sign_ec_p384(&self.key, data, algorithm)
    }
}

/// An intermediary that signs its responses (SupplierSignature over the
/// NIC signature certificate) and can transport-encrypt them and corrupt
/// the signature.
struct SigningIntermediary {
    signer: RsaSigner,
    /// corrupt the SignatureValue of the response
    corrupt_once: Mutex<bool>,
    /// wrap the response into a transport envelope for this client cert
    encrypt_for: Option<osci_crypto::Certificate>,
}

impl SigningIntermediary {
    fn new() -> Self {
        Self {
            signer: RsaSigner::from_pem_dump(
                corpus()
                    .join("certs")
                    .join("alice_signature_4096.pem")
                    .to_str()
                    .unwrap(),
                None,
            )
            .unwrap(),
            corrupt_once: Mutex::new(false),
            encrypt_for: None,
        }
    }
}

impl MockIntermediary for SigningIntermediary {
    fn handle(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        let stored = StoredMessage::load(message).map_err(|e| TransportError(e.to_string()))?;
        let request_xml = String::from_utf8_lossy(&stored.xml).into_owned();
        let doc = osci_core::xml::parser::parse(&request_xml)
            .map_err(|e| TransportError(e.to_string()))?;
        let header =
            osci_core::soap::find_header(&doc).ok_or_else(|| TransportError("no header".into()))?;
        let cb = header
            .elements()
            .find(|e| e.local == "ControlBlock")
            .ok_or_else(|| TransportError("no control block".into()))?;
        let request_block = ControlBlock {
            conversation_id: cb.attr("ConversationId").map(str::to_string),
            sequence_number: cb.attr("SequenceNumber").and_then(|v| v.parse().ok()),
            response: cb
                .elements()
                .find(|e| e.local == "Response")
                .map(|e| e.text()),
            challenge: cb
                .elements()
                .find(|e| e.local == "Challenge")
                .map(|e| e.text()),
        };

        let response_kind = match request_entry_kind(&doc) {
            MessageType::InitDialog => MessageType::ResponseToInitDialog,
            _ => MessageType::ResponseToFetchDelivery,
        };

        // ResponseToFetchDelivery: the one response kind with an NIC slot
        // (template) for the SupplierSignature's certificate reference
        let mut out = OutMessage {
            kind: Some(response_kind),
            control_block: ControlBlock {
                conversation_id: request_block.conversation_id.clone(),
                sequence_number: request_block.sequence_number,
                response: request_block.challenge.clone(),
                challenge: Some(osci_core::helper::base64::encode(b"intermediary-challenge")),
            },
            non_intermediary_certificates: if response_kind == MessageType::ResponseToFetchDelivery
            {
                vec![OutCertEntry {
                    role: CertRole::Originator,
                    use_: CertUse::Signature,
                    id: "originator_signature".into(),
                    der: cert_der("alice_signature_4096.pem"),
                }]
            } else {
                Vec::new()
            },
            feedback: vec![osci_core::message::compose::OutFeedback {
                language: Some("de".into()),
                code: "0800".into(),
                text: "Auftrag ausgeführt".into(),
            }],
            entry_inner: (response_kind == MessageType::ResponseToFetchDelivery).then(|| {
                "<osci:fetchDelivery><osci:SelectionRule><osci:MessageId>bXNn</osci:MessageId>\
                 </osci:SelectionRule></osci:fetchDelivery>"
                    .to_string()
            }),
            ..Default::default()
        };
        // the intermediary assigns the conversation id with the init
        // response; fields the response kind prohibits are masked
        out.control_block.conversation_id = out
            .control_block
            .conversation_id
            .or_else(|| Some("4711".into()));
        if !osci_core::message::compose::control_block_allows_conversation(response_kind) {
            out.control_block.conversation_id = None;
        }
        if !osci_core::message::compose::control_block_allows_sequence(response_kind) {
            out.control_block.sequence_number = None;
        }
        let stream =
            compose_message(&out, "MIME_boundary").map_err(|e| TransportError(e.to_string()))?;

        if response_kind != MessageType::ResponseToFetchDelivery {
            return Ok(stream);
        }
        // sign: SupplierSignature, injected after the ControlBlock
        let marker = "Content-ID: <osci@message>\r\n\r\n";
        let xml_start = stream
            .windows(marker.len())
            .position(|w| w == marker.as_bytes())
            .ok_or_else(|| TransportError("no xml part".into()))?
            + marker.len();
        let xml_end = stream[xml_start..]
            .windows(4)
            .position(|w| w == b"\r\n--")
            .map(|p| xml_start + p)
            .unwrap_or(stream.len());
        let xml = String::from_utf8(stream[xml_start..xml_end].to_vec())
            .map_err(|e| TransportError(e.to_string()))?;
        let mut signed = osci::sign::sign_message_xml(
            &xml,
            &osci::sign::SignParams {
                signer: &self.signer,
                method: None,
                digest: None,
                certificate_id: "originator_signature".into(),
                attachments: &[],
                header_element: Some("SupplierSignature"),
            },
        )
        .map_err(|e| TransportError(e.to_string()))?;
        if *self.corrupt_once.lock().unwrap() {
            // flip the signature value: replace the base64 payload
            let pos = signed.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
            let flipped: String = signed[pos..]
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() && c != 'A' {
                        'A'
                    } else {
                        'B'
                    }
                })
                .take(8)
                .collect();
            signed.replace_range(pos..pos + 8, &flipped);
            *self.corrupt_once.lock().unwrap() = false;
        }
        let mut response = stream[..xml_start].to_vec();
        response.extend_from_slice(signed.as_bytes());
        response.extend_from_slice(&stream[xml_end..]);

        if let Some(client_cert) = &self.encrypt_for {
            return osci::security::encrypt_message_for(
                &response,
                client_cert,
                &osci::security::EncryptConfig::default(),
                "MIME_boundary",
            )
            .map_err(|e| TransportError(e.to_string()));
        }
        Ok(response)
    }
}

/// The request's message kind via the message parser.
fn request_entry_kind(doc: &osci_core::xml::Document) -> MessageType {
    osci_core::message::parse_message(doc)
        .ok()
        .and_then(|m| m.kind)
        .unwrap_or(MessageType::InitDialog)
}

fn extract_xml(stream: &[u8]) -> String {
    let mut mime = osci_core::helper::mime::MimeParser::new(stream).unwrap();
    let mut part = mime.next_part().unwrap().unwrap();
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    String::from_utf8(xml).unwrap()
}

fn init_request() -> OutMessage {
    OutMessage {
        kind: Some(MessageType::InitDialog),
        control_block: ControlBlock {
            challenge: Some("Y2xpZW50LWNoYWxsZW5nZQ==".into()),
            ..Default::default()
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: vec![OutCertEntry {
            role: CertRole::Originator,
            use_: CertUse::Cipher,
            id: "originator_cipher".into(),
            der: cert_der("alice_cipher_4096.pem"),
        }],
        ..Default::default()
    }
}

fn fetch_request() -> OutMessage {
    OutMessage {
        kind: Some(MessageType::FetchDelivery),
        control_block: ControlBlock {
            sequence_number: Some(1),
            conversation_id: Some("4711".into()),
            response: Some("cmVzcG9uc2U=".into()),
            challenge: Some("Y2xpZW50LWNoYWxsZW5nZQ==".into()),
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: vec![OutCertEntry {
            role: CertRole::Originator,
            use_: CertUse::Signature,
            id: "originator_signature".into(),
            der: cert_der("alice_signature_4096.pem"),
        }],
        selection_rule: Some("bXNn".into()),
        ..Default::default()
    }
}

/// The signed response verifies; the report carries the key facts and
/// weak verdicts (RSA-4096, PSS SHA-256: strong).
#[test]
fn signed_response_verifies_under_require_policy() {
    let intermediary = SigningIntermediary::new();
    let mut dialog = Dialog::new(Box::new(LoopbackTransport::new(Box::new(intermediary))));

    // init round (unsigned response), then require signatures
    let mut init = init_request();
    dialog.send(&mut init, &[], "MIME_boundary").unwrap();
    dialog.set_signature_policy(SignaturePolicy::Require);

    let mut out = fetch_request();
    let response = dialog.send(&mut out, &[], "MIME_boundary").unwrap();
    assert_eq!(response.kind, Some(MessageType::ResponseToFetchDelivery));
    assert_eq!(first_feedback(&response).unwrap().code, "0800");

    let report = dialog.last_response_report().expect("report stored");
    assert_eq!(report.signatures.len(), 1);
    let sig = &report.signatures[0];
    assert!(sig.all_valid(), "signature valid: {sig:#?}");
    assert_eq!(sig.key_algorithm.as_deref(), Some("RSA"));
    assert_eq!(sig.key_size_bits, Some(4096));
    assert_eq!(sig.key_weak, Some(false));
    assert_eq!(sig.algorithm_outdated, Some(false));
    assert!(sig.strong_and_valid());
}

/// An invalid response signature is rejected under every verifying
/// policy; the report records the failure.
#[test]
fn corrupted_response_signature_rejected() {
    let intermediary = SigningIntermediary::new();
    *intermediary.corrupt_once.lock().unwrap() = true;
    let mut dialog = Dialog::new(Box::new(LoopbackTransport::new(Box::new(intermediary))));
    dialog
        .send(&mut init_request(), &[], "MIME_boundary")
        .unwrap();
    dialog.set_signature_policy(SignaturePolicy::VerifyIfPresent);

    let mut out = fetch_request();
    let error = dialog.send(&mut out, &[], "MIME_boundary").unwrap_err();
    assert!(
        matches!(error, DialogError::Verification(_)),
        "expected verification error, got {error:?}"
    );
    assert!(dialog.last_response_report().is_none());
}

/// An unsigned response passes VerifyIfPresent (interop default) but is
/// rejected under Require.
#[test]
fn unsigned_response_per_policy() {
    let make_dialog = |policy: SignaturePolicy| {
        let intermediary = UnsignedIntermediary;
        let mut dialog = Dialog::new(Box::new(LoopbackTransport::new(Box::new(intermediary))));
        dialog
            .send(&mut init_request(), &[], "MIME_boundary")
            .unwrap();
        dialog.set_signature_policy(policy);
        dialog
    };

    let mut dialog = make_dialog(SignaturePolicy::VerifyIfPresent);
    let mut out = fetch_request();
    let response = dialog.send(&mut out, &[], "MIME_boundary").unwrap();
    assert_eq!(response.kind, Some(MessageType::ResponseToFetchDelivery));
    assert!(dialog.last_response_report().is_none());

    let mut dialog = make_dialog(SignaturePolicy::Require);
    let mut out = fetch_request();
    let error = dialog.send(&mut out, &[], "MIME_boundary").unwrap_err();
    assert!(
        matches!(error, DialogError::Verification(_)),
        "expected verification error, got {error:?}"
    );

    // Ignore: no verification pass at all
    let mut dialog = make_dialog(SignaturePolicy::Ignore);
    let mut out = fetch_request();
    let response = dialog.send(&mut out, &[], "MIME_boundary").unwrap();
    assert_eq!(response.kind, Some(MessageType::ResponseToFetchDelivery));
    assert!(dialog.last_response_report().is_none());
}

/// An unsigned-response intermediary (the pre-M11 shape).
struct UnsignedIntermediary;

impl MockIntermediary for UnsignedIntermediary {
    fn handle(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        let stored = StoredMessage::load(message).map_err(|e| TransportError(e.to_string()))?;
        let doc = osci_core::xml::parser::parse(&String::from_utf8_lossy(&stored.xml))
            .map_err(|e| TransportError(e.to_string()))?;
        let kind = request_entry_kind(&doc);
        let response_kind = match kind {
            MessageType::InitDialog => MessageType::ResponseToInitDialog,
            _ => MessageType::ResponseToFetchDelivery,
        };
        let cb = osci_core::soap::find_header(&doc)
            .unwrap()
            .elements()
            .find(|e| e.local == "ControlBlock")
            .unwrap();
        let mut block = ControlBlock {
            conversation_id: cb
                .attr("ConversationId")
                .map(str::to_string)
                .or_else(|| Some("4711".into())),
            sequence_number: cb.attr("SequenceNumber").and_then(|v| v.parse().ok()),
            // answer the request's challenge (the request's own
            // Response answers OUR previous challenge)
            response: cb
                .elements()
                .find(|e| e.local == "Challenge")
                .map(|e| e.text())
                .or_else(|| {
                    cb.elements()
                        .find(|e| e.local == "Response")
                        .map(|e| e.text())
                }),
            challenge: Some(osci_core::helper::base64::encode(b"unsigned-challenge")),
        };
        if !osci_core::message::compose::control_block_allows_conversation(response_kind) {
            block.conversation_id = None;
        }
        if !osci_core::message::compose::control_block_allows_sequence(response_kind) {
            block.sequence_number = None;
        }
        let out = OutMessage {
            kind: Some(response_kind),
            control_block: block,
            feedback: vec![osci_core::message::compose::OutFeedback {
                language: Some("de".into()),
                code: "0800".into(),
                text: "Auftrag ausgeführt".into(),
            }],
            entry_inner: (response_kind == MessageType::ResponseToFetchDelivery).then(|| {
                "<osci:fetchDelivery><osci:SelectionRule><osci:MessageId>bXNn</osci:MessageId>\
                 </osci:SelectionRule></osci:fetchDelivery>"
                    .to_string()
            }),
            ..Default::default()
        };
        compose_message(&out, "MIME_boundary").map_err(|e| TransportError(e.to_string()))
    }
}

/// A transport-encrypted response is unwrapped with the configured
/// response decrypters before the control block and signature checks.
#[test]
fn transport_encrypted_response_opens_with_response_decrypters() {
    let client_cipher =
        osci_crypto::Certificate::from_der(&cert_der("bob_cipher_4096.pem")).unwrap();
    let mut intermediary = SigningIntermediary::new();
    intermediary.encrypt_for = Some(client_cipher);
    let decrypter =
        RsaDecrypter::from_pem_dump(corpus().join("certs/bob_cipher_4096.pem").to_str().unwrap())
            .unwrap();
    let mut dialog = Dialog::new(Box::new(LoopbackTransport::new(Box::new(intermediary))))
        .with_response_decrypters(vec![decrypter]);
    dialog
        .send(&mut init_request(), &[], "MIME_boundary")
        .unwrap();
    dialog.set_signature_policy(SignaturePolicy::Require);

    let mut out = fetch_request();
    let response = dialog.send(&mut out, &[], "MIME_boundary").unwrap();
    assert_eq!(response.kind, Some(MessageType::ResponseToFetchDelivery));
    assert!(dialog.last_response_report().unwrap().all_valid());
}

/// Without response decrypters a transport-encrypted response is a
/// decryption error, not a parse error.
#[test]
fn encrypted_response_without_decrypters_is_decryption_error() {
    let client_cipher =
        osci_crypto::Certificate::from_der(&cert_der("bob_cipher_4096.pem")).unwrap();
    let mut intermediary = SigningIntermediary::new();
    intermediary.encrypt_for = Some(client_cipher);
    let mut dialog = Dialog::new(Box::new(LoopbackTransport::new(Box::new(intermediary))));
    dialog
        .send(&mut init_request(), &[], "MIME_boundary")
        .unwrap();

    let mut out = fetch_request();
    let error = dialog.send(&mut out, &[], "MIME_boundary").unwrap_err();
    assert!(
        matches!(error, DialogError::Decryption(_)),
        "expected decryption error, got {error:?}"
    );
}

/// ECDSA (P-384) end to end: an EC-signed message verifies through the
/// document pipeline, with the EC key facts and a strong verdict.
#[test]
fn ecdsa_p384_message_verifies() {
    let key_der = private_key_der("ECDSA_NIST_p384.pem");
    use p384::pkcs8::DecodePrivateKey as _;
    let signing_key = p384::ecdsa::SigningKey::from_pkcs8_der(&key_der).expect("p384 signing key");
    let certificate = osci_crypto::Certificate::from_der(&cert_der("ECDSA_NIST_p384.pem")).unwrap();
    let signer = EcP384Signer {
        key: signing_key,
        certificate: certificate.clone(),
    };

    let out = OutMessage {
        kind: Some(MessageType::GetMessageId),
        control_block: ControlBlock {
            challenge: Some("Y2hhbGxlbmdl".into()),
            sequence_number: Some(0),
            ..Default::default()
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: vec![OutCertEntry {
            role: CertRole::Originator,
            use_: CertUse::Signature,
            id: "originator_signature".into(),
            der: cert_der("ECDSA_NIST_p384.pem"),
        }],
        ..Default::default()
    };
    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let xml = extract_xml(&stream);
    let signed = osci::sign::sign_message_xml(
        &xml,
        &osci::sign::SignParams {
            signer: &signer,
            method: Some(SIGNATURE_ECDSA_SHA384.into()),
            digest: Some(osci_crypto::algorithms::DIGEST_SHA384.into()),
            certificate_id: "originator_signature".into(),
            attachments: &[],
            header_element: None,
        },
    )
    .unwrap();

    let report: VerificationReport = verify_message(&signed, &[]).unwrap();
    assert_eq!(report.signatures.len(), 1);
    let sig: &SignatureResult = &report.signatures[0];
    assert!(sig.all_valid(), "EC signature must verify: {sig:#?}");
    assert_eq!(sig.key_algorithm.as_deref(), Some("EC"));
    assert_eq!(sig.key_size_bits, Some(384));
    assert_eq!(sig.key_weak, Some(false));
    assert_eq!(sig.algorithm_outdated, Some(false));
    assert!(sig.strong_and_valid());
}

/// Legacy algorithm dating: a 2005-era rsa-sha1 fixture reports the
/// outdated algorithm (and a verified signature).
#[test]
fn legacy_fixture_reports_outdated_algorithm() {
    let bytes = std::fs::read(corpus().join("messages/ResponseToStoreDelivery.osci")).unwrap();
    let stored = StoredMessage::load(&bytes).unwrap();
    let report = verify_message(&String::from_utf8_lossy(&stored.xml), &[]).unwrap();
    assert!(!report.signatures.is_empty(), "fixture has signatures");
    for sig in &report.signatures {
        assert_eq!(sig.method, "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        assert_eq!(sig.algorithm_outdated, Some(true));
        assert!(!sig.strong_and_valid(), "rsa-sha1 is not strong");
    }
}
