//! M13: MessageMetaData / custom-header composition - the vendor
//! extension header slot (Java custom headers): canonicalized fragment
//! with the spliced `Id`, positioned after the FeatureDescription, and
//! re-parseable (parse side maps it to a Custom header entry).

mod common;

use std::io::Read;

use osci_core::message::compose::{
    OutCertEntry, OutContent, OutContentContainer, OutMessage, compose_message,
};
use osci_core::message::{MessageType, parse_message};
use osci_core::soap::{CertRole, CertUse, ControlBlock};
use osci_core::xml::parser;

fn mmd_fragment() -> String {
    std::fs::read_to_string(common::corpus().join("extension").join("xtaMmdOsci.xml")).unwrap()
}

fn store_delivery_with_mmd() -> OutMessage {
    OutMessage {
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
                use_: CertUse::Cipher,
                id: "originator_cipher".into(),
                der: vec![1, 2, 3],
            },
            OutCertEntry {
                role: CertRole::Addressee,
                use_: CertUse::Cipher,
                id: "addressee_cipher".into(),
                der: vec![4, 5, 6],
            },
        ],
        entry_inner: Some(
            "<osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into(),
        ),
        containers: vec![OutContentContainer {
            id: "contentcontainer".into(),
            contents: vec![OutContent {
                id: "content1".into(),
                text: Some("payload".into()),
                href: None,
            }],
            encrypted_attachments: Vec::new(),
        }],
        custom_headers: vec![osci_core::message::compose::OutCustomHeader {
            id: "MetaData".into(),
            xml: mmd_fragment(),
        }],
        ..Default::default()
    }
}

#[test]
fn custom_header_is_canonical_with_spliced_id() {
    let stream = compose_message(&store_delivery_with_mmd(), "MIME_boundary").unwrap();
    let mut mime = osci_core::helper::mime::MimeParser::new(&stream[..]).unwrap();
    let mut part = mime.next_part().unwrap().unwrap();
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    let xml = String::from_utf8(xml).unwrap();

    // the fragment rides canonically with the spliced Id, positioned
    // before </soap:Header>
    let header_end = xml.find("</soap:Header>").unwrap();
    let header = &xml[..header_end];
    let mmd_pos = header.find("MessageMetaData").expect("mmd element present");
    let fragment = &header[mmd_pos..];
    assert!(
        fragment.contains("Id=\"MetaData\""),
        "Id spliced into the root start tag: {}",
        &fragment[..fragment.find('>').unwrap_or(200).min(fragment.len())]
    );
    assert!(
        !fragment.contains("<?xml"),
        "declaration stripped from the fragment"
    );

    // the fragment content survives canonicalization (service quality,
    // identifiers, wsa MessageID)
    assert!(header.contains("ServiceQuality"), "mmd content present");
}

/// The composed custom header re-parses: the MessageMetaData element is
/// found (prefix-independent) and the header entry surfaces as Custom.
#[test]
fn composed_custom_header_reparses() {
    let stream = compose_message(&store_delivery_with_mmd(), "MIME_boundary").unwrap();
    let mut mime = osci_core::helper::mime::MimeParser::new(&stream[..]).unwrap();
    let mut part = mime.next_part().unwrap().unwrap();
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    let doc = parser::parse(&String::from_utf8(xml).unwrap()).unwrap();

    let parsed = parse_message(&doc).unwrap();
    assert_eq!(parsed.kind, Some(MessageType::StoreDelivery));

    // MMD content reachable again through the mmd helpers
    let element = osci_core::message::mmd::find_mmd_element(&doc).expect("mmd found");
    let mmd = osci_core::message::mmd::parse_mmd(element);
    assert_eq!(mmd.service_quality.as_deref(), Some("meldewesen"));
}
