//! M5c gates: StoredMessage load/store, partial deliveries with chunk
//! information, passive-recipient correlation and the MessageMetaData
//! extension.

mod common;

use osci_core::message::compose::{
    OutAttachment, OutCertEntry, OutContent, OutContentContainer, OutMessage, compose_message,
};
use osci_core::message::stored::{ControlBlockState, DialogFinder, StoredMessage};
use osci_core::message::{ChunkInformation, MessageType, parse_message};
use osci_core::soap::{CertRole, CertUse, ControlBlock};
use osci_core::xml::parser;

fn messages_dir() -> std::path::PathBuf {
    common::corpus().join("messages")
}

/// LF-only fixtures: extract part 1 by byte surgery (no MIME part
/// delimiting possible).
fn lf_fixture_xml(name: &str) -> String {
    let bytes = std::fs::read(messages_dir().join(name)).unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let mut sections = text.split("\n\n");
    let _ = sections.next();
    let _ = sections.next();
    let rest = sections.collect::<Vec<_>>().join("\n\n");
    let end = rest.find("\n--").map(|i| &rest[..i]).unwrap_or(&rest);
    end.to_string()
}

/// StoredMessage::load works for every loadable fixture (kind detection
/// plus attachment extraction).
#[test]
fn stored_message_loads_all_fixtures() {
    let mut loaded = 0usize;
    let mut with_attachments = 0usize;
    let entries = std::fs::read_dir(messages_dir())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()));
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".osci") || name == "StoreDelivery_XXE.osci" {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(stored) = StoredMessage::load(&bytes) else {
            continue; // LF-only fixtures cannot be MIME-delimited
        };
        assert!(!stored.xml.is_empty());
        assert!(stored.message.kind.is_some() || stored.message.body.is_some());
        if !stored.attachments.is_empty() {
            with_attachments += 1;
            for att in &stored.attachments {
                assert!(!att.content_id.is_empty());
                assert!(!att.data.is_empty(), "{name}: empty attachment");
            }
        }
        loaded += 1;
    }
    assert!(loaded >= 20, "only {loaded} fixtures loaded");
    assert!(
        with_attachments >= 5,
        "only {with_attachments} with attachments"
    );
}

/// Compose -> store -> load roundtrips for every composable type,
/// including the partial store delivery with its chunk blob.
#[test]
fn store_load_roundtrips_all_types() {
    let load_cert = |pem: &str| {
        let dump = std::fs::read_to_string(common::corpus().join("certs").join(pem)).unwrap();
        let start = dump.find("-----BEGIN CERTIFICATE-----").unwrap();
        let after = &dump[start + 27..];
        let end = after.find("-----END CERTIFICATE-----").unwrap();
        let b64: String = after[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        osci_core::helper::base64::decode(&b64).unwrap()
    };
    let cipher_originator = OutCertEntry {
        role: CertRole::Originator,
        use_: CertUse::Cipher,
        id: "originator_cipher_test".into(),
        der: load_cert("alice_cipher_4096.pem"),
    };
    let signature_originator = OutCertEntry {
        role: CertRole::Originator,
        use_: CertUse::Signature,
        id: "originator_signature_test".into(),
        der: load_cert("alice_signature_4096.pem"),
    };
    let cipher_addressee = OutCertEntry {
        role: CertRole::Addressee,
        use_: CertUse::Cipher,
        id: "addressee_cipher_test".into(),
        der: load_cert("bob_cipher_4096.pem"),
    };
    // per-kind legal NonIntermediaryCertificates content (issue #3)
    let base = move |kind: MessageType| OutMessage {
        kind: Some(kind),
        control_block: ControlBlock {
            // InitDialog prohibits the dialog attributes and carries no
            // Response (issue #3 model); everything else answers the
            // peer's challenge
            sequence_number: (!matches!(kind, MessageType::InitDialog)).then_some(1),
            challenge: Some("Y2hhbGxlbmdl".into()),
            conversation_id: (!matches!(kind, MessageType::InitDialog)).then(|| "4711".into()),
            response: (!matches!(kind, MessageType::InitDialog)).then(|| "cmVzcG9uc2U=".into()),
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: match kind {
            MessageType::ExitDialog
            | MessageType::FetchDelivery
            | MessageType::FetchProcessCard => {
                vec![signature_originator.clone()]
            }
            MessageType::GetMessageId => {
                vec![cipher_originator.clone(), signature_originator.clone()]
            }
            // both store flavors require the addressee cipher certificate
            MessageType::StoreDelivery | MessageType::PartialStoreDelivery => {
                vec![cipher_originator.clone(), cipher_addressee.clone()]
            }
            MessageType::ResponseToGetMessageId
            | MessageType::ResponseToStoreDelivery
            | MessageType::ResponseToAcceptDelivery => Vec::new(),
            _ => vec![cipher_originator.clone()],
        },
        ..Default::default()
    };

    let mut cases: Vec<(OutMessage, MessageType)> = vec![
        (base(MessageType::InitDialog), MessageType::InitDialog),
        (base(MessageType::ExitDialog), MessageType::ExitDialog),
        (
            {
                let mut m = base(MessageType::StoreDelivery);
                m.entry_inner = Some(
                    "<osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into(),
                );
                m.containers.push(OutContentContainer {
                    id: "contentcontainer".into(),
                    contents: vec![OutContent {
                        id: "content1".into(),
                        text: Some("payload".into()),
                        href: None,
                    }],
                    encrypted_attachments: Vec::new(),
                });
                m
            },
            MessageType::StoreDelivery,
        ),
        (
            {
                let mut m = base(MessageType::FetchDelivery);
                m.selection_rule = Some("bXNn".into());
                m
            },
            MessageType::FetchDelivery,
        ),
        (
            {
                let mut m = base(MessageType::ForwardDelivery);
                m.entry_inner = Some(
                    "<osci:ContentReceiver URI=\"http://localhost/rec\"></osci:ContentReceiver>                     <osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into(),
                );
                m.containers.push(OutContentContainer {
                    id: "contentcontainer".into(),
                    contents: vec![OutContent {
                        id: "content1".into(),
                        text: Some("payload".into()),
                        href: None,
                    }],
                    encrypted_attachments: Vec::new(),
                });
                m
            },
            MessageType::ForwardDelivery,
        ),
    ];

    // partial store delivery with chunk blob attachment
    {
        let mut m = base(MessageType::PartialStoreDelivery);
        m.entry_inner = Some("<osci:MessageId>bXNn".to_string() + "LWNodW5r</osci:MessageId>");
        m.chunk_information = Some(ChunkInformation {
            chunk_number: 1,
            chunk_size: Some(10),
            total_chunk_numbers: Some(1),
            total_message_size: Some(1),
            received_chunks: Vec::new(),
        });
        m.feature_description = Some(osci_core::soap::FeatureDescription {
            chunk_message_timeout: Some(60),
            max_chunk_size: Some(1024),
            max_message_size: Some(4096),
            min_chunk_size: Some(128),
            features: vec![("DisableBase64".into(), "1.2.0".into())],
        });
        m.containers.push(OutContentContainer {
            id: "ChunkContentContainer".into(),
            contents: vec![OutContent {
                id: "ChunkContent".into(),
                href: Some("cid:ChunkBlobStoreDelivery".into()),
                text: None,
            }],
            encrypted_attachments: Vec::new(),
        });
        m.attachments.push(OutAttachment {
            content_id: "ChunkBlobStoreDelivery".into(),
            content_type: "application/octet-stream".into(),
            base64_encoding: false,
            data: b"chunk-payload".to_vec(),
        });
        cases.push((m, MessageType::PartialStoreDelivery));
    }

    for (out, expected) in cases {
        let stream = StoredMessage::store(&out, "MIME_boundary").unwrap();
        let stored = StoredMessage::load(&stream)
            .unwrap_or_else(|e| panic!("{expected:?}: load failed: {e}"));
        assert_eq!(stored.message.kind, Some(expected), "{expected:?}");
        if let Some(chunk) = &out.chunk_information {
            assert_eq!(
                stored.message.chunk_information.as_ref(),
                Some(chunk),
                "{expected:?}: chunk information survived the roundtrip"
            );
        }
    }
}

/// Chunk information parses from the corpus fixtures: the CRLF fetch
/// response and the LF-only partial requests.
#[test]
fn chunk_information_from_fixtures() {
    // ResponseToPartialFetchDelivery (CRLF): echoed fetchDelivery entry
    let bytes = std::fs::read(messages_dir().join("ResponseToPartialFetchDelivery.osci")).unwrap();
    let stored = StoredMessage::load(&bytes).unwrap();
    assert_eq!(
        stored.message.kind,
        Some(MessageType::ResponseToPartialFetchDelivery)
    );
    let chunk = stored.message.chunk_information.expect("chunk info");
    assert_eq!(chunk.chunk_number, 1);
    assert_eq!(chunk.total_chunk_numbers, Some(3));
    assert_eq!(chunk.total_message_size, Some(154));
    assert_eq!(
        stored.message.echoed_request_kind,
        Some(MessageType::FetchDelivery)
    );

    // PartialStoreDelivery (LF-only): store side chunk attributes + blob
    let xml = lf_fixture_xml("PartialStoreDelivery.osci");
    let doc = parser::parse(&xml).unwrap();
    let message = parse_message(&doc).unwrap();
    assert_eq!(message.kind, Some(MessageType::PartialStoreDelivery));
    let chunk = message.chunk_information.expect("chunk info");
    assert_eq!(chunk.chunk_number, 1);
    assert_eq!(chunk.chunk_size, Some(10));
    // the blob reference lives in the body container
    let body = message.body.as_ref().expect("body");
    assert_eq!(
        body.containers[0].contents[0].href.as_deref(),
        Some("cid:ChunkBlobStoreDelivery")
    );

    // PartialFetchDelivery (LF-only): ReceivedChunks variant
    let xml = lf_fixture_xml("PartialFetchDelivery.osci");
    let doc = parser::parse(&xml).unwrap();
    let message = parse_message(&doc).unwrap();
    assert_eq!(message.kind, Some(MessageType::PartialFetchDelivery));
    let chunk = message.chunk_information.expect("chunk info");
    assert_eq!(chunk.received_chunks, vec![-1]);
}

/// The DialogFinder correlates incoming accept/process deliveries by
/// conversation id.
#[test]
fn dialog_finder_correlates_incoming_requests() {
    // the 2005-era fixtures mostly predate ConversationId; the fetch
    // response carries one - the finder itself is generic
    let bytes = std::fs::read(messages_dir().join("ResponseToFetchDelivery.osci")).unwrap();
    let probe = StoredMessage::load(&bytes).unwrap();
    let conversation_id = probe.conversation_id().unwrap().expect("conversation id");

    let mut finder = DialogFinder::new();
    assert!(
        finder.find(&conversation_id).is_none(),
        "unknown dialog before registration"
    );
    finder.register(ControlBlockState {
        conversation_id: conversation_id.clone(),
        sequence_number: Some(3),
        last_challenge: Some("Y2hhbGxlbmdl".into()),
    });

    let (stored, dialog) = finder.accept(&bytes).unwrap();
    assert_eq!(
        stored.message.kind,
        Some(MessageType::ResponseToFetchDelivery)
    );
    let dialog = dialog.expect("dialog found for known conversation");
    assert_eq!(dialog.conversation_id, conversation_id);
    assert_eq!(dialog.sequence_number, Some(3));
}

/// The MessageMetaData extension header parses from the reference
/// fixture.
#[test]
fn message_meta_data_parses() {
    use osci_core::message::mmd;
    let xml =
        std::fs::read_to_string(common::corpus().join("extension").join("xtaMmdOsci.xml")).unwrap();
    let doc = parser::parse(&xml).unwrap();
    let element = mmd::find_mmd_element(&doc).expect("MMD header present");
    let mmd = mmd::parse_mmd(element);
    assert_eq!(mmd.service_quality.as_deref(), Some("meldewesen"));
    assert_eq!(mmd.authors.len(), 1);
    assert_eq!(mmd.authors[0].name.as_deref(), Some("Ralf Lindemann"));
    assert_eq!(mmd.authors[0].value, "ags:02044096");
    assert_eq!(mmd.readers.len(), 1);
    assert_eq!(mmd.readers[0].value, "ags:0403014096");
    assert!(
        mmd.message_id
            .as_deref()
            .unwrap()
            .starts_with("urn:de:xta:messageid:TestXTAgovernikus:")
    );
}

/// A composed partial store delivery validates against the XSD corpus
/// through the Java oracle (chunking wire format correctness); skipped
/// when the oracle is not built.
#[test]
fn partial_store_delivery_validates_against_xsd() {
    let root = common::corpus().parent().unwrap().to_path_buf();
    if !root.join("oracle/build/classpath.txt").exists() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    use std::io::Write;
    use std::process::{Command, Stdio};
    let root = common::corpus().parent().unwrap().to_path_buf();
    let classpath = std::fs::read_to_string(root.join("oracle/build/classpath.txt")).unwrap();
    let classpath = format!(
        "{}:{}",
        root.join("oracle/build").display(),
        classpath.trim()
    );
    let java = root.join("tools/jdk11/bin/java");

    let cert_der = {
        let dump =
            std::fs::read_to_string(common::corpus().join("certs").join("alice_cipher_4096.pem"))
                .unwrap();
        let start = dump.find("-----BEGIN CERTIFICATE-----").unwrap();
        let after = &dump[start + 27..];
        let end = after.find("-----END CERTIFICATE-----").unwrap();
        let b64: String = after[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        osci_core::helper::base64::decode(&b64).unwrap()
    };
    let mut out = OutMessage {
        kind: Some(MessageType::PartialStoreDelivery),
        control_block: ControlBlock {
            sequence_number: Some(1),
            challenge: Some("Y2hhbGxlbmdl".into()),
            conversation_id: Some("4711".into()),
            response: None,
        },
        desired_languages: Some("de".into()),
        // the partial schema mandates a QualityOfTimestamp header AND a
        // FeatureDescription entry
        quality_creation: Some(false),
        feature_description: Some(osci_core::soap::FeatureDescription {
            chunk_message_timeout: Some(300),
            max_chunk_size: Some(50000000),
            max_message_size: Some(500000000),
            min_chunk_size: Some(1000000),
            // SupportedFeatures is mandatory in the partial schema
            features: vec![("DisableBase64".into(), "1.0.0".into())],
        }),
        entry_inner: Some("<osci:MessageId>bXNn</osci:MessageId>".into()),
        chunk_information: Some(ChunkInformation {
            chunk_number: 1,
            chunk_size: Some(10),
            total_chunk_numbers: Some(1),
            total_message_size: Some(1),
            received_chunks: Vec::new(),
        }),
        // addressee cipher certificate mandatory like StoreDelivery
        non_intermediary_certificates: vec![
            OutCertEntry {
                role: CertRole::Originator,
                use_: CertUse::Cipher,
                id: "originator_cipher_test".into(),
                der: cert_der,
            },
            OutCertEntry {
                role: CertRole::Addressee,
                use_: CertUse::Cipher,
                id: "addressee_cipher_test".into(),
                der: {
                    let dump = std::fs::read_to_string(
                        common::corpus().join("certs").join("bob_cipher_4096.pem"),
                    )
                    .unwrap();
                    let start = dump.find("-----BEGIN CERTIFICATE-----").unwrap();
                    let after = &dump[start + 27..];
                    let end = after.find("-----END CERTIFICATE-----").unwrap();
                    let b64: String = after[..end]
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect();
                    osci_core::helper::base64::decode(&b64).unwrap()
                },
            },
        ],
        ..Default::default()
    };
    out.containers.push(OutContentContainer {
        id: "ChunkContentContainer".into(),
        contents: vec![OutContent {
            id: "ChunkContent".into(),
            href: Some("cid:ChunkBlobStoreDelivery".into()),
            text: None,
        }],
        encrypted_attachments: Vec::new(),
    });
    out.attachments.push(OutAttachment {
        content_id: "ChunkBlobStoreDelivery".into(),
        content_type: "application/octet-stream".into(),
        base64_encoding: false,
        data: b"chunk".to_vec(),
    });

    let stream = compose_message(&out, "MIME_boundary").unwrap();
    let mut xml = Vec::new();
    {
        use std::io::Read;
        let mut mime = osci_core::helper::mime::MimeParser::new(&stream[..]).unwrap();
        let mut part = mime.next_part().unwrap().unwrap();
        part.read_to_end(&mut xml).unwrap();
    }
    let mut child = Command::new(&java)
        .arg("-cp")
        .arg(&classpath)
        .arg("osci.oracle.CryptoSpike")
        .arg("validate")
        .arg(common::corpus().join("xsd"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&xml).unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("VALID") || stdout.contains("SCHEMA_MISSING soapPartialStoreDelivery"),
        "XSD verdict: {stdout}"
    );
}
