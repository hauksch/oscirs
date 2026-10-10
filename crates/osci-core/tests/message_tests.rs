//! M5a gate: message recognition and structural parsing across the
//! corpus (essence of `TestStoredMessage`), with pinned per-fixture
//! expectations.

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};

use osci_core::helper::mime::MimeParser;
use osci_core::message::{MessageType, OsciMessage, parse_message};
use osci_core::xml::parser;

fn fixture_xml(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut mime = MimeParser::new(&bytes[..]).ok()?;
    let mut part = mime.next_part().ok()??;
    if part.content_id() != "osci@message" {
        return None;
    }
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).ok()?;
    String::from_utf8(xml).ok()
}

/// Expected message kind per CRLF fixture (file name -> type).
fn expected_kind(name: &str) -> Option<MessageType> {
    use MessageType::*;
    Some(match name {
        "AccDelNestedCocos.osci" | "AcceptDelivery.osci" => AcceptDelivery,
        "FetchDelivery.osci" => FetchDelivery,
        "ForwardDelivery.osci" => ForwardDelivery,
        "MediateDelivery.osci" => MediateDelivery,
        "ProcessDelivery.osci" => ProcessDelivery,
        "StoreDelivery.osci"
        | "StoreDeliverySpezial.osci"
        | "StoreDeliverySpezial2.osci"
        | "StrDel_Encrypted_cbc.osci" => StoreDelivery,
        "MESSAGE_WITH_UNSIGNED_CONTENTS.osci"
        | "ResponseToFetchDelivery.osci"
        | "ResponseToFetchDelivery_corrupt_sig.osci"
        | "Rsp2FetchDelSignedInnerCoco.osci" => ResponseToFetchDelivery,
        "ResponseToAcceptDelivery.osci" | "ResponseToAcceptDeliveryOld.osci" => {
            ResponseToAcceptDelivery
        }
        "ResponseToForwardDelivery.osci" => ResponseToForwardDelivery,
        "ResponseToMediateDelivery.osci" | "RIPEMD160test.osci" => ResponseToMediateDelivery,
        "ResponseToProcessDelivery.osci" => ResponseToProcessDelivery,
        "ResponseToStoreDelivery.osci" => ResponseToStoreDelivery,
        "ResponseToFetchProcessCard.osci" => ResponseToFetchProcessCard,
        "FetchProcessCard.osci" => FetchProcessCard,
        "StoreDelivery_XXE.osci" => StoreDelivery,
        _ => return None,
    })
}

fn messages_dir() -> PathBuf {
    common::corpus().join("messages")
}

fn loadable() -> Vec<(String, String)> {
    let mut entries: Vec<_> = std::fs::read_dir(messages_dir())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "osci"))
        .collect();
    entries.sort();
    entries
        .into_iter()
        .filter_map(|p| {
            fixture_xml(&p).map(|xml| (p.file_name().unwrap().to_string_lossy().into_owned(), xml))
        })
        .collect()
}

fn parse(xml: &str) -> OsciMessage {
    let doc = parser::parse(xml).unwrap();
    parse_message(&doc).unwrap_or_else(|e| panic!("message parse failed: {e}"))
}

/// Every loadable fixture recognizes its message type.
#[test]
fn all_fixtures_recognize_their_type() {
    let mut recognized = 0usize;
    let mut failures = Vec::new();
    for (name, xml) in loadable() {
        if name == "StoreDelivery_XXE.osci" {
            continue; // rejected at the parser gate
        }
        match parser::parse(&xml)
            .map_err(|e| osci_core::message::MessageError::Invalid(e.to_string()))
            .and_then(|doc| parse_message(&doc))
        {
            Ok(message) => {
                if let Some(expected) = expected_kind(&name) {
                    assert_eq!(
                        message.kind,
                        Some(expected),
                        "{name}: wrong message type detected"
                    );
                }
                assert!(
                    !message.feedback.is_empty()
                        || message.request.is_some()
                        || message.body.is_some(),
                    "{name}: nothing parsed"
                );
                recognized += 1;
            }
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }
    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
    assert!(recognized >= 20, "only {recognized} recognized");
}

#[test]
fn store_delivery_fields() {
    let message = parse(&fixture_xml(&messages_dir().join("StoreDelivery.osci")).unwrap());
    assert_eq!(message.kind, Some(MessageType::StoreDelivery));
    let request = message.request.as_ref().unwrap();
    assert_eq!(request.message_id.as_deref(), Some("MTEzMDg1MDcwNjAzMTE="));
    assert_eq!(request.subject.as_deref(), Some("Subject"));
    // body: one signed container with two contents
    let body = message.body.as_ref().expect("body");
    assert_eq!(body.containers.len(), 1);
    assert!(body.containers[0].signed);
    assert_eq!(body.containers[0].contents.len(), 2);
    assert!(body.containers[0].contents.iter().any(|c| c.href.is_some()));
    assert!(
        body.containers[0]
            .contents
            .iter()
            .any(|c| c.base64_content.is_some())
    );
}

#[test]
fn response_to_store_delivery() {
    let message =
        parse(&fixture_xml(&messages_dir().join("ResponseToStoreDelivery.osci")).unwrap());
    assert_eq!(message.kind, Some(MessageType::ResponseToStoreDelivery));
    assert!(!message.feedback.is_empty());
    assert_eq!(message.feedback[0].code, "0801");
    assert_eq!(
        message.feedback[0].text.trim(),
        "Auftrag ausgeführt, Dialog weiterhin geöffnet"
    );
    let bundle = &message.process_card_bundles[0];
    assert!(bundle.message_id.is_some());
    let card = &bundle.process_cards[0];
    assert_eq!(card.subject.as_deref(), Some("Subject"));
    let creation = card.creation.expect("creation timestamp");
    assert_eq!(creation.to_rfc3339(), "2005-11-01T13:44:00+00:00");
}

#[test]
fn response_to_fetch_delivery_echoes_request() {
    let message =
        parse(&fixture_xml(&messages_dir().join("ResponseToFetchDelivery.osci")).unwrap());
    assert_eq!(message.kind, Some(MessageType::ResponseToFetchDelivery));
    assert_eq!(
        message.echoed_request_kind,
        Some(MessageType::FetchDelivery)
    );
    assert!(message.request.as_ref().unwrap().message_id.is_some());
    assert_eq!(message.process_card_bundles.len(), 1);
    assert!(!message.feedback.is_empty());
}

#[test]
fn accept_delivery_process_cards() {
    let message = parse(&fixture_xml(&messages_dir().join("AcceptDelivery.osci")).unwrap());
    assert_eq!(message.kind, Some(MessageType::AcceptDelivery));
    let bundle = &message.process_card_bundles[0];
    assert_eq!(bundle.process_cards.len(), 1);
    assert_eq!(bundle.inspections.len(), 5);
    let inspection = &bundle.inspections[0];
    assert!(
        inspection
            .timestamp
            .as_deref()
            .unwrap()
            .starts_with("2005-11-01")
    );
    assert!(inspection.x509_subject_name.is_some());
    assert!(inspection.online_result.is_some());
}

#[test]
fn fetch_delivery_selection_rule() {
    let message = parse(&fixture_xml(&messages_dir().join("FetchDelivery.osci")).unwrap());
    assert_eq!(message.kind, Some(MessageType::FetchDelivery));
    let request = message.request.as_ref().unwrap();
    assert!(request.selection_rule.is_some(), "selection rule element");
    assert!(request.message_id.is_some());
}

#[test]
fn forward_delivery_content_receiver() {
    let message = parse(&fixture_xml(&messages_dir().join("ForwardDelivery.osci")).unwrap());
    assert_eq!(message.kind, Some(MessageType::ForwardDelivery));
    let request = message.request.as_ref().unwrap();
    assert!(request.content_receiver.is_some());
    assert!(request.subject.is_some());
}

#[test]
fn response_to_mediate_delivery_feedback() {
    // the test.mime-style message with two process card bundles
    let message =
        parse(&fixture_xml(&messages_dir().join("ResponseToMediateDelivery.osci")).unwrap());
    assert_eq!(message.kind, Some(MessageType::ResponseToMediateDelivery));
    assert_eq!(message.feedback[0].code, "0800");
    assert_eq!(message.process_card_bundles.len(), 2);
    // request + reply bundles
    assert!(
        message
            .process_card_bundles
            .iter()
            .all(|b| !b.process_cards.is_empty())
    );
    assert!(message.process_card_bundles[0].inspections.len() >= 4);
}

#[test]
fn encrypted_transport_envelope() {
    // StrDel_Encrypted_cbc: the whole message is encrypted; the envelope
    // carries no header, only the body EncryptedData (kind None until the
    // payload is decrypted in M6)
    let Some(xml) = fixture_xml(&messages_dir().join("StrDel_Encrypted_cbc.osci")) else {
        // LF-only fixture: extract part 1 by byte surgery like the M2 gate
        let bytes = std::fs::read(messages_dir().join("StrDel_Encrypted_cbc.osci")).unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let mut sections = text.split("\n\n");
        let _ = sections.next();
        let _ = sections.next();
        let rest = sections.collect::<Vec<_>>().join("\n\n");
        let end = rest.find("\n--").map(|i| &rest[..i]).unwrap_or(&rest);
        let message = parse(end);
        assert_eq!(message.kind, None);
        let body = message.body.as_ref().expect("body");
        assert_eq!(body.encrypted_data.len(), 1);
        assert!(body.encrypted_data[0].cipher_reference.is_some());
        return;
    };
    let message = parse(&xml);
    assert_eq!(message.kind, None);
    let body = message.body.as_ref().expect("body");
    assert_eq!(body.encrypted_data.len(), 1);
    assert_eq!(
        body.encrypted_data[0].mime_type.as_deref(),
        Some("Multipart/Related")
    );
    assert_eq!(
        body.encrypted_data[0].cipher_reference.as_deref(),
        Some("cid:osci_enc")
    );
}
