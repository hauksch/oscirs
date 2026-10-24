//! Issue #3 gate: composed wire traffic validates against the normative
//! OSCI schemas vendored from osci-bib-java 2.6.1 ("the schemas are the
//! contract"). Composes a representative message per kind - plain,
//! signed, and (for the issue's acceptance set) content- and
//! transport-encrypted - and runs scripts/xsd-validate.sh on the XML
//! part. Skips silently when no validator (xmllint / python+lxml) is
//! available, like the Java-oracle gates.

mod common;

use common::{cert_der, corpus};

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use chrono::TimeZone as _;

use osci_core::message::MessageType;
use osci_core::message::compose::{
    OutCertEntry, OutContent, OutContentContainer, OutFeedback, OutMessage, compose_message,
};
use osci_core::soap::{CertRole, CertUse, ControlBlock, FeatureDescription};

fn cert(role: CertRole, use_: CertUse, id: &str, pem: &str) -> OutCertEntry {
    OutCertEntry {
        role,
        use_,
        id: id.into(),
        der: cert_der(pem),
    }
}

/// A ControlBlock legal for the kind (mirrors the ControlBlockType
/// restrictions: which fields are required/optional/prohibited).
fn control_block_for(kind: MessageType) -> ControlBlock {
    let answer: String = "cmVzcG9uc2U=".into();
    let challenge: String = "Y2hhbGxlbmdl".into();
    use MessageType as M;
    match kind {
        M::InitDialog => ControlBlock {
            challenge: Some(challenge),
            ..Default::default()
        },
        M::GetMessageId | M::ForwardDelivery | M::StoreDelivery => ControlBlock {
            sequence_number: Some(1),
            challenge: Some(challenge),
            ..Default::default()
        },
        M::AcceptDelivery | M::ProcessDelivery => ControlBlock {
            challenge: Some(challenge),
            ..Default::default()
        },
        M::ExitDialog | M::FetchDelivery | M::FetchProcessCard | M::MediateDelivery => {
            ControlBlock {
                conversation_id: Some("4711".into()),
                sequence_number: Some(1),
                response: Some(answer.clone()),
                challenge: Some(challenge),
            }
        }
        M::ResponseToInitDialog => ControlBlock {
            conversation_id: Some("4711".into()),
            response: Some(answer),
            challenge: Some(challenge),
            ..Default::default()
        },
        // ExitDialog responses must hand out the next challenge; the
        // store/getMessageId responses may
        M::ResponseToExitDialog => ControlBlock {
            conversation_id: Some("4711".into()),
            sequence_number: Some(2),
            response: Some(answer.clone()),
            challenge: Some(challenge),
        },
        M::ResponseToGetMessageId | M::ResponseToStoreDelivery => ControlBlock {
            conversation_id: Some("4711".into()),
            sequence_number: Some(2),
            response: Some(answer),
            ..Default::default()
        },
        M::ResponseToFetchDelivery
        | M::ResponseToFetchProcessCard
        | M::ResponseToMediateDelivery => ControlBlock {
            conversation_id: Some("4711".into()),
            sequence_number: Some(2),
            response: Some(answer.clone()),
            challenge: Some(challenge),
        },
        // accept/process responses: no dialog attributes, but the next
        // Challenge is mandatory
        M::ResponseToAcceptDelivery | M::ResponseToProcessDelivery => ControlBlock {
            response: Some(answer),
            challenge: Some(challenge),
            ..Default::default()
        },
        M::ResponseToForwardDelivery => ControlBlock {
            response: Some(answer),
            ..Default::default()
        },
        // 2017 partial messages: unrestricted template
        _ => ControlBlock {
            conversation_id: Some("4711".into()),
            sequence_number: Some(1),
            response: Some(answer),
            challenge: Some(challenge),
        },
    }
}

/// The soap schema document of a kind (the Java writer's convention:
/// "soap" + PascalCase(elementName) + ".xsd").
fn schema_of(kind: MessageType) -> String {
    let element = kind.element_name();
    let mut pascal = String::with_capacity(element.len());
    let mut chars = element.chars();
    if let Some(first) = chars.next() {
        pascal.extend(first.to_uppercase());
        pascal.push_str(chars.as_str());
    }
    format!("soap{pascal}.xsd")
}

/// A schema-legal representative message per kind: per-type certificate
/// sets, DesiredLanguages on requests only, FeatureDescription where the
/// schema demands it, quality-timestamp defaults left to the composer.
fn legal_message(kind: MessageType) -> OutMessage {
    let cipher_originator = || {
        cert(
            CertRole::Originator,
            CertUse::Cipher,
            "originator_cipher",
            "alice_cipher_4096.pem",
        )
    };
    let signature_originator = || {
        cert(
            CertRole::Originator,
            CertUse::Signature,
            "originator_signature",
            "alice_signature_4096.pem",
        )
    };
    let cipher_addressee = || {
        cert(
            CertRole::Addressee,
            CertUse::Cipher,
            "addressee_cipher",
            "bob_cipher_4096.pem",
        )
    };
    let signature_addressee = || {
        cert(
            CertRole::Addressee,
            CertUse::Signature,
            "addressee_signature",
            "bob_signature_4096.pem",
        )
    };

    let certs: Vec<OutCertEntry> = match kind {
        MessageType::InitDialog => vec![cipher_originator()],
        MessageType::ExitDialog
        | MessageType::FetchDelivery
        | MessageType::FetchProcessCard
        | MessageType::PartialFetchDelivery => vec![signature_originator()],
        MessageType::GetMessageId => vec![cipher_originator(), signature_originator()],
        // both store flavors require the addressee cipher certificate
        MessageType::StoreDelivery | MessageType::PartialStoreDelivery => {
            vec![
                cipher_originator(),
                signature_originator(),
                cipher_addressee(),
            ]
        }
        MessageType::ResponseToAcceptDelivery => vec![signature_addressee()],
        MessageType::ResponseToInitDialog
        | MessageType::ResponseToExitDialog
        | MessageType::ResponseToGetMessageId
        | MessageType::ResponseToFetchProcessCard
        | MessageType::ResponseToStoreDelivery
        | MessageType::ResponseToForwardDelivery
        | MessageType::ResponseToPartialStoreDelivery
        | MessageType::ResponseToPartialFetchDelivery => vec![],
        _ => vec![cipher_originator()],
    };

    let mut msg = OutMessage {
        kind: Some(kind),
        control_block: control_block_for(kind),
        desired_languages: (!kind.is_response()).then(|| "de".into()),
        non_intermediary_certificates: certs,
        feature_description: matches!(
            kind,
            MessageType::PartialStoreDelivery
                | MessageType::PartialFetchDelivery
                | MessageType::ResponseToPartialStoreDelivery
        )
        .then(|| FeatureDescription {
            chunk_message_timeout: Some(60),
            max_chunk_size: Some(1024),
            max_message_size: Some(4096),
            min_chunk_size: Some(128),
            features: vec![("DisableBase64".into(), "1.0.0".into())],
        }),
        ..Default::default()
    };

    match kind {
        MessageType::StoreDelivery => {
            msg.entry_inner =
                Some("<osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into());
        }
        // forwardDeliveryType/mediateDeliveryType: ContentReceiver is
        // required, before the MessageId/Subject of the base template
        MessageType::ForwardDelivery | MessageType::MediateDelivery => {
            msg.entry_inner = Some(
                "<osci:ContentReceiver URI=\"http://localhost/osci-recipient\"></osci:ContentReceiver>\
                 <osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>"
                    .into(),
            );
        }
        // processDeliveryType: MessageIdResponse + ProcessCardBundle
        MessageType::ProcessDelivery => {
            msg.entry_inner = Some("<osci:MessageIdResponse>bXNn</osci:MessageIdResponse>".into());
        }
        MessageType::FetchDelivery | MessageType::FetchProcessCard => {
            msg.selection_rule = Some("bXNn".into());
        }
        // partialStoreDeliveryType: MessageId, Subject?, then the choice
        // of InfoOnly XOR ChunkInformation (appended by the composer)
        MessageType::PartialStoreDelivery => {
            msg.entry_inner =
                Some("<osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into());
            msg.chunk_information = Some(osci_core::message::ChunkInformation {
                chunk_number: 1,
                chunk_size: Some(16),
                total_chunk_numbers: Some(1),
                total_message_size: Some(16),
                received_chunks: Vec::new(),
            });
        }
        MessageType::PartialFetchDelivery => {
            msg.chunk_information = Some(osci_core::message::ChunkInformation {
                chunk_number: 1,
                chunk_size: Some(16),
                total_chunk_numbers: None,
                total_message_size: None,
                received_chunks: Vec::new(),
            });
        }
        _ if kind.is_response() => {
            msg.feedback = vec![OutFeedback {
                language: Some("de".into()),
                code: "0800".into(),
                text: "Auftrag ausgeführt".into(),
            }];
            // echoed entry content per response type
            msg.entry_inner = match kind {
                MessageType::ResponseToFetchDelivery => Some(
                    "<osci:fetchDelivery><osci:SelectionRule><osci:MessageId>bXNn</osci:MessageId>\
                     </osci:SelectionRule></osci:fetchDelivery>"
                        .into(),
                ),
                MessageType::ResponseToProcessDelivery => Some(
                    "<osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into(),
                ),
                MessageType::ResponseToPartialFetchDelivery => Some(
                    "<osci:fetchDelivery><osci:SelectionRule><osci:MessageId>bXNn</osci:MessageId>\
                     </osci:SelectionRule></osci:fetchDelivery>"
                        .into(),
                ),
                MessageType::ResponseToMediateDelivery => Some(
                    "<osci:RequestProcessCardBundle><osci:MessageId>bXNn</osci:MessageId>                     <osci:ProcessCard RecentModification=\"2026-01-01T12:00:00+01:00\">                     <osci:Creation><osci:Plain>2026-01-01T12:00:00+01:00</osci:Plain></osci:Creation>                     <osci:Forwarding><osci:Plain>2026-01-01T12:05:00+01:00</osci:Plain></osci:Forwarding>                     <osci:Reception><osci:Plain>2026-01-01T12:06:00+01:00</osci:Plain></osci:Reception>                     </osci:ProcessCard><osci:InspectionReport><osci:Inspection>                     <osci:Timestamp><osci:Plain>2026-01-01T12:06:00+01:00</osci:Plain></osci:Timestamp>                     <osci:X509SubjectName>CN=gate</osci:X509SubjectName>                     <osci:X509IssuerName>CN=gate-ca</osci:X509IssuerName>                     <osci:X509SerialNumber>1</osci:X509SerialNumber>                     <osci:CertType Type=\"advanced\"></osci:CertType>                     <osci:MathResult Result=\"ok\"></osci:MathResult>                     <osci:OfflineResult Result=\"valid\"></osci:OfflineResult>                     <osci:OnlineResult Result=\"ok\"></osci:OnlineResult>                     </osci:Inspection></osci:InspectionReport></osci:RequestProcessCardBundle>                     <osci:ReplyProcessCardBundle><osci:MessageId>bXNn</osci:MessageId>                     <osci:ProcessCard RecentModification=\"2026-01-01T12:00:00+01:00\">                     <osci:Creation><osci:Plain>2026-01-01T12:00:00+01:00</osci:Plain></osci:Creation>                     <osci:Forwarding><osci:Plain>2026-01-01T12:05:00+01:00</osci:Plain></osci:Forwarding>                     </osci:ProcessCard><osci:InspectionReport><osci:Inspection>                     <osci:Timestamp><osci:Plain>2026-01-01T12:06:00+01:00</osci:Plain></osci:Timestamp>                     <osci:X509SubjectName>CN=gate</osci:X509SubjectName>                     <osci:X509IssuerName>CN=gate-ca</osci:X509IssuerName>                     <osci:X509SerialNumber>1</osci:X509SerialNumber>                     <osci:CertType Type=\"advanced\"></osci:CertType>                     <osci:MathResult Result=\"ok\"></osci:MathResult>                     <osci:OfflineResult Result=\"valid\"></osci:OfflineResult>                     <osci:OnlineResult Result=\"ok\"></osci:OnlineResult>                     </osci:Inspection></osci:InspectionReport></osci:ReplyProcessCardBundle>"
                        .into(),
                ),
                // responseToInitDialog/ExitDialog carry only Feedback;
                // responseToGetMessageId optionally echoes the MessageId
                MessageType::ResponseToGetMessageId => {
                    Some("<osci:MessageId>aW50ZXJtZWRpYXJ5</osci:MessageId>".into())
                }
                MessageType::ResponseToFetchProcessCard => Some(
                    "<osci:fetchProcessCard><osci:SelectionRule><osci:MessageId>bXNn</osci:MessageId>                     </osci:SelectionRule></osci:fetchProcessCard>"
                        .into(),
                ),
                MessageType::ResponseToInitDialog
                | MessageType::ResponseToExitDialog
                | MessageType::ResponseToAcceptDelivery
                | MessageType::ResponseToForwardDelivery => None,
                _ => None,
            };
            msg.chunk_information = match kind {
                // the response chunk types: ChunkNumber required,
                // ChunkSize/ReceivedChunks prohibited (fetch side keeps
                // the totals optional, store side the chunk count)
                MessageType::ResponseToPartialFetchDelivery => {
                    Some(osci_core::message::ChunkInformation {
                        chunk_number: 1,
                        chunk_size: None,
                        received_chunks: Vec::new(),
                        total_chunk_numbers: Some(3),
                        total_message_size: None,
                    })
                }
                MessageType::ResponseToPartialStoreDelivery => {
                    Some(osci_core::message::ChunkInformation {
                        chunk_number: 1,
                        chunk_size: None,
                        received_chunks: vec![1, 2, 3],
                        total_chunk_numbers: None,
                        total_message_size: None,
                    })
                }
                _ => None,
            };
        }
        _ => {}
    }

    // ProcessCardBundle-bearing entries; the per-kind ProcessCardType
    // restrictions decide which timestamps are required/allowed
    let card = |forwarding: bool| osci_core::message::compose::OutProcessCard {
        creation: Some(chrono::Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()),
        forwarding: forwarding.then(|| chrono::Utc.with_ymd_and_hms(2026, 1, 1, 12, 5, 0).unwrap()),
        reception: None,
        subject: Some("S".into()),
    };
    if matches!(
        kind,
        MessageType::AcceptDelivery | MessageType::ProcessDelivery
    ) {
        msg.process_card_bundles
            .push(osci_core::message::compose::OutProcessCardBundle {
                message_id: Some("bXNn".into()),
                // their ProcessCardType makes Forwarding required, and the
                // bundle requires an InspectionReport entry
                process_cards: vec![card(true)],
                inspections: vec![osci_core::message::Inspection {
                    timestamp: Some("2026-01-01T12:06:00+01:00".into()),
                    x509_subject_name: Some("CN=gate".into()),
                    x509_issuer_name: Some("CN=gate-ca".into()),
                    x509_serial_number: Some("1".into()),
                    cert_type: Some("advanced".into()),
                    math_result: Some("ok".into()),
                    offline_result: Some("valid".into()),
                    online_result: Some("ok".into()),
                }],
            });
    } else if matches!(
        kind,
        MessageType::ResponseToStoreDelivery | MessageType::ResponseToForwardDelivery
    ) {
        msg.process_card_bundles
            .push(osci_core::message::compose::OutProcessCardBundle {
                message_id: Some("bXNn".into()),
                // response ProcessCardTypes: Creation required; Forwarding
                // optional (ResponseToForward) or prohibited
                // (ResponseToStore); the bundle requires InspectionReport
                process_cards: vec![card(matches!(kind, MessageType::ResponseToForwardDelivery))],
                inspections: vec![osci_core::message::Inspection {
                    timestamp: Some("2026-01-01T12:06:00+01:00".into()),
                    x509_subject_name: Some("CN=gate".into()),
                    x509_issuer_name: Some("CN=gate-ca".into()),
                    x509_serial_number: Some("1".into()),
                    cert_type: Some("advanced".into()),
                    math_result: Some("ok".into()),
                    offline_result: Some("valid".into()),
                    online_result: Some("ok".into()),
                }],
            });
    }

    // the delivery kinds require a ContentPackage in the Body
    if matches!(
        kind,
        MessageType::StoreDelivery
            | MessageType::AcceptDelivery
            | MessageType::ProcessDelivery
            | MessageType::ForwardDelivery
            | MessageType::MediateDelivery
            | MessageType::PartialStoreDelivery
    ) {
        msg.containers.push(OutContentContainer {
            id: "contentcontainer".into(),
            contents: vec![OutContent {
                id: "content1".into(),
                text: Some("gate payload".into()),
                href: None,
            }],
            encrypted_attachments: Vec::new(),
        });
    }
    msg
}

fn workspace_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

/// Run the committed validator; Err(()) with the script's exit code 2
/// means no validator is installed (skip the gate).
fn xsd_validate(doc: &std::path::Path, schema: &str) -> Result<(), String> {
    let script = workspace_root().join("scripts/xsd-validate.sh");
    let output = Command::new(&script).arg(doc).arg(schema).output();
    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) if out.status.code() == Some(2) => Err("no-validator".into()),
        Ok(out) => Err(String::from_utf8_lossy(&out.stderr).into_owned()),
        Err(e) => Err(format!("spawn: {e}")),
    }
}

fn xml_part_of(stream: &[u8]) -> Vec<u8> {
    let mut mime = osci_core::helper::mime::MimeParser::new(stream).unwrap();
    let mut part = mime.next_part().unwrap().expect("xml part");
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    xml
}

fn validate_composed(label: &str, msg: &OutMessage) {
    let kind = msg.kind.unwrap();
    let stream = compose_message(msg, "MIME_boundary").unwrap();
    let xml = xml_part_of(&stream);
    let dir = std::env::temp_dir();
    let doc = dir.join(format!("osci-xsd-gate-{label}.xml"));
    std::fs::write(&doc, &xml).unwrap();
    match xsd_validate(&doc, &schema_of(kind)) {
        Ok(()) => {}
        Err(e) if e == "no-validator" => {
            eprintln!("skipping: no XSD validator (xmllint / python3+lxml)");
        }
        Err(e) => panic!("{label}: XSD validation failed: {e}"),
    }
}

#[test]
fn every_composable_kind_is_schema_valid() {
    for kind in [
        MessageType::InitDialog,
        MessageType::ExitDialog,
        MessageType::GetMessageId,
        MessageType::StoreDelivery,
        MessageType::FetchDelivery,
        MessageType::AcceptDelivery,
        MessageType::ProcessDelivery,
        MessageType::ForwardDelivery,
        MessageType::MediateDelivery,
        MessageType::FetchProcessCard,
        MessageType::PartialStoreDelivery,
        MessageType::PartialFetchDelivery,
        MessageType::ResponseToInitDialog,
        MessageType::ResponseToExitDialog,
        MessageType::ResponseToGetMessageId,
        MessageType::ResponseToStoreDelivery,
        MessageType::ResponseToFetchDelivery,
        MessageType::ResponseToAcceptDelivery,
        MessageType::ResponseToProcessDelivery,
        MessageType::ResponseToForwardDelivery,
        MessageType::ResponseToMediateDelivery,
        MessageType::ResponseToFetchProcessCard,
        MessageType::ResponseToPartialStoreDelivery,
        MessageType::ResponseToPartialFetchDelivery,
    ] {
        validate_composed(format!("{kind:?}").as_str(), &legal_message(kind));
    }
}

/// The issue's acceptance set with a transport signature: the signature
/// header lands in the schema's slot (ClientSignature for requests,
/// SupplierSignature for responses).
#[test]
fn signed_traffic_is_schema_valid() {
    use osci_crypto::software::RsaSigner;
    let signer = RsaSigner::from_pem_dump(
        corpus()
            .join("certs")
            .join("alice_signature_4096.pem")
            .to_str()
            .unwrap(),
        None,
    )
    .unwrap();
    // requests only: a response signature is the intermediary's
    // SupplierSignature referencing its IntermediaryCertificates entry,
    // which the composer does not emit yet
    for kind in [MessageType::GetMessageId, MessageType::StoreDelivery] {
        let msg = legal_message(kind);
        let stream = compose_message(&msg, "MIME_boundary").unwrap();
        let xml = String::from_utf8(xml_part_of(&stream)).unwrap();
        let signed = osci::sign::sign_message_xml(
            &xml,
            &osci::sign::SignParams {
                signer: &signer,
                method: None,
                digest: None,
                certificate_id: "originator_signature".into(),
                attachments: &[],
                header_element: Some(osci_core::message::compose::signature_header_name(kind)),
            },
        )
        .unwrap();
        let dir = std::env::temp_dir();
        let doc = dir.join(format!("osci-xsd-gate-signed-{:?}.xml", kind));
        std::fs::write(&doc, signed).unwrap();
        match xsd_validate(&doc, &schema_of(kind)) {
            Ok(()) => {}
            Err(e) if e == "no-validator" => {
                eprintln!("skipping: no XSD validator (xmllint / python3+lxml)");
            }
            Err(e) => panic!("signed {kind:?}: XSD validation failed: {e}"),
        }
    }
}

/// Content-encrypted StoreDelivery (EncryptedData before the containers
/// in the ContentPackage) and the transport-encrypted envelope
/// (soapMessageEncrypted.xsd).
#[test]
fn encrypted_traffic_is_schema_valid() {
    use osci::security::{EncRecipient, EncryptConfig, encrypt_container, encrypt_message_for};
    use osci_crypto::Certificate;

    let recipient = Certificate::from_der(&cert_der("bob_cipher_4096.pem")).unwrap();
    let recipients = [EncRecipient {
        cert: recipient.clone(),
        cert_element_id: "addressee_cipher".into(),
    }];
    let config = EncryptConfig::default();

    let mut msg = legal_message(MessageType::StoreDelivery);
    let encrypted = encrypt_container(
        &OutContentContainer {
            id: "contentcontainer".into(),
            contents: vec![OutContent {
                id: "content1".into(),
                text: Some("gate payload".into()),
                href: None,
            }],
            encrypted_attachments: Vec::new(),
        },
        &recipients,
        &config,
        Some("encdata_0".into()),
        None,
    )
    .unwrap();
    msg.encrypted_data.push(encrypted);
    validate_composed("content-encrypted-StoreDelivery", &msg);

    // content-encrypted WITH an encrypted attachment (Java
    // EncryptedDataOSCI dialect: Attachment<id> EncryptedData inside the
    // encrypted container, ciphertext on the MIME part)
    const ATTACHMENT_ID: &str = "gate-attachment";
    let attachment_contents = vec![OutContent {
        id: "content1".into(),
        text: None,
        href: Some(format!("cid:{ATTACHMENT_ID}")),
    }];
    let enc_attachments = osci_core::message::compose::encrypt_attachments(
        &attachment_contents,
        &[osci_core::message::compose::OutAttachment {
            content_id: ATTACHMENT_ID.into(),
            content_type: "application/octet-stream".into(),
            base64_encoding: false,
            data: b"gate attachment payload".to_vec(),
        }],
        &config.content_cipher,
        None,
    )
    .unwrap();
    let encrypted_container = encrypt_container(
        &OutContentContainer {
            id: "contentcontainer".into(),
            contents: attachment_contents,
            encrypted_attachments: enc_attachments,
        },
        &recipients,
        &config,
        Some("encdata_0".into()),
        None,
    )
    .unwrap();
    let mut msg = legal_message(MessageType::StoreDelivery);
    msg.attachments
        .push(osci_core::message::compose::OutAttachment {
            content_id: ATTACHMENT_ID.into(),
            content_type: "application/octet-stream".into(),
            base64_encoding: false,
            data: vec![0u8; 64],
        });
    msg.encrypted_data.push(encrypted_container);
    validate_composed("content-encrypted-attachment-StoreDelivery", &msg);

    // transport envelope: the signed stream wrapped into a
    // SOAPMessageEncrypted message
    let signed_stream = {
        use osci_crypto::software::RsaSigner;
        let signer = RsaSigner::from_pem_dump(
            corpus()
                .join("certs")
                .join("alice_signature_4096.pem")
                .to_str()
                .unwrap(),
            None,
        )
        .unwrap();
        let plain_stream =
            compose_message(&legal_message(MessageType::StoreDelivery), "MIME_boundary").unwrap();
        let xml = String::from_utf8(xml_part_of(&plain_stream)).unwrap();
        let signed_xml = osci::sign::sign_message_xml(
            &xml,
            &osci::sign::SignParams {
                signer: &signer,
                method: None,
                digest: None,
                certificate_id: "originator_cipher".into(),
                attachments: &[],
                header_element: None,
            },
        )
        .unwrap();
        // splice the signed XML back (same framing the dialog uses)
        let marker = "Content-ID: <osci@message>\r\n\r\n";
        let pos = plain_stream
            .windows(marker.len())
            .position(|w| w == marker.as_bytes())
            .unwrap()
            + marker.len();
        let mut out = plain_stream[..pos].to_vec();
        out.extend_from_slice(signed_xml.as_bytes());
        out.extend_from_slice(&plain_stream[pos..]);
        out
    };
    let envelope =
        encrypt_message_for(&signed_stream, &recipient, &config, "MIME_boundary").unwrap();
    let xml = xml_part_of(&envelope);
    let doc = std::env::temp_dir().join("osci-xsd-gate-transport-encrypted.xml");
    std::fs::write(&doc, &xml).unwrap();
    match xsd_validate(&doc, "soapMessageEncrypted.xsd") {
        Ok(()) => {}
        Err(e) if e == "no-validator" => {
            eprintln!("skipping: no XSD validator (xmllint / python3+lxml)");
        }
        Err(e) => panic!("transport-encrypted: XSD validation failed: {e}"),
    }
}

/// Issue #4 gap 1: the rule-less ("ALL") fetch delivery - no
/// SelectionRule element at all - is schema-valid.
#[test]
fn rule_less_fetch_delivery_is_schema_valid() {
    let mut msg = legal_message(MessageType::FetchDelivery);
    msg.selection_rule = None;
    validate_composed("rule-less-FetchDelivery", &msg);
}
