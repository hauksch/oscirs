//! M7: the four reference integration scenarios (Synchronous /
//! Asynchronous / RequestResponse / ParallelSendReceive), offline, over
//! the loopback transport and a scripted mock intermediary.

mod common;

use common::{cert_der, corpus};

use std::io::Read;
use std::sync::{Arc, Mutex};

use chrono::TimeZone as _;
use osci::dialog::{Dialog, DialogError, first_feedback};
use osci_core::message::compose::{
    OutAttachment, OutCertEntry, OutContent, OutContentContainer, OutFeedback, OutMessage,
    compose_message,
};
use osci_core::message::stored::StoredMessage;
use osci_core::message::{MessageType, OsciMessage};
use osci_core::soap::{CertRole, CertUse, ControlBlock};
use osci_crypto::software::RsaSigner;
use osci_transport::{LoopbackTransport, MockIntermediary, TransportError};

/// The mock intermediary: validates the request's control-block protocol
/// and replies with the matching ResponseTo* message (feedback 0800/0801)
/// carrying the next challenge.
struct ScriptedIntermediary {
    /// seen requests (for assertions)
    seen: Arc<Mutex<Vec<(MessageType, ControlBlock)>>>,
    /// break the challenge echo in one reply (negative test)
    break_challenge_once: Mutex<bool>,
    /// respond with a broken challenge from this request count on
    /// (1-based; usize::MAX = never)
    break_from_round: Mutex<usize>,
    /// override the success feedback of the next response (feedback
    /// classification tests)
    feedback_override: Mutex<Option<(String, String)>>,
    /// stored deliveries (the " mailbox", for the async scenario)
    mailbox: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ScriptedIntermediary {
    fn new(seen: Arc<Mutex<Vec<(MessageType, ControlBlock)>>>) -> Self {
        Self {
            seen,
            break_challenge_once: Mutex::new(false),
            break_from_round: Mutex::new(usize::MAX),
            feedback_override: Mutex::new(None),
            mailbox: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn mailbox_handle(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
        self.mailbox.clone()
    }
}

fn control_block_of(xml: &str) -> ControlBlock {
    let doc = osci_core::xml::parser::parse(xml).unwrap();
    let header = osci_core::soap::find_header(&doc).unwrap();
    let child = header
        .elements()
        .find(|e| e.local == "ControlBlock")
        .unwrap();
    ControlBlock {
        conversation_id: child.attr("ConversationId").map(str::to_string),
        sequence_number: child.attr("SequenceNumber").and_then(|v| v.parse().ok()),
        response: child
            .elements()
            .find(|e| e.local == "Response")
            .map(|e| e.text()),
        challenge: child
            .elements()
            .find(|e| e.local == "Challenge")
            .map(|e| e.text()),
    }
}

fn extract_xml(stream: &[u8]) -> String {
    let mut mime = osci_core::helper::mime::MimeParser::new(stream).unwrap();
    let mut part = mime.next_part().unwrap().unwrap();
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    String::from_utf8(xml).unwrap()
}

impl MockIntermediary for ScriptedIntermediary {
    fn handle(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        let stored =
            StoredMessage::load(message).map_err(|e| TransportError::new(e.to_string()))?;
        let kind = stored
            .message
            .kind
            .ok_or_else(|| TransportError::new("no kind"))?;
        let request_block = control_block_of(&String::from_utf8_lossy(&stored.xml));

        // protocol validation on the intermediary side: the request must
        // carry a challenge (our previous one answered)
        if request_block.challenge.is_none() {
            return Err(TransportError::new("request without challenge"));
        }
        self.seen
            .lock()
            .unwrap()
            .push((kind, request_block.clone()));

        // store deliveries into the mailbox for the async scenario
        if kind == MessageType::StoreDelivery {
            self.mailbox.lock().unwrap().push(message.to_vec());
        }

        let response_kind = match kind {
            MessageType::GetMessageId => MessageType::ResponseToGetMessageId,
            MessageType::InitDialog => MessageType::ResponseToInitDialog,
            MessageType::ExitDialog => MessageType::ResponseToExitDialog,
            MessageType::StoreDelivery => MessageType::ResponseToStoreDelivery,
            MessageType::ForwardDelivery => MessageType::ResponseToForwardDelivery,
            MessageType::MediateDelivery => MessageType::ResponseToMediateDelivery,
            MessageType::FetchDelivery => MessageType::ResponseToFetchDelivery,
            MessageType::PartialStoreDelivery => MessageType::ResponseToPartialStoreDelivery,
            other => return Err(TransportError::new(format!("unhandled type {other:?}"))),
        };

        // control-block protocol: response answers the request's
        // challenge, echoes sequence + conversation, provides a new
        // challenge; the intermediary assigns the conversation id with
        // the InitDialog response (the schema requires it there)
        let mut response_block = ControlBlock {
            conversation_id: request_block
                .conversation_id
                .clone()
                .or_else(|| Some("4711".into())),
            sequence_number: request_block.sequence_number,
            response: request_block.challenge.clone(),
            challenge: Some(osci_core::helper::base64::encode(
                b"intermediary-next-challen",
            )),
        };
        if *self.break_challenge_once.lock().unwrap()
            || self.seen.lock().unwrap().len() >= *self.break_from_round.lock().unwrap()
        {
            response_block.response = Some("d3Jvbmc=".into());
            *self.break_challenge_once.lock().unwrap() = false;
        }
        // mask the fields the response kind's ControlBlock schema
        // prohibits (fail-closed compose would reject them)
        if !osci_core::message::compose::control_block_allows_conversation(response_kind) {
            response_block.conversation_id = None;
        }
        if !osci_core::message::compose::control_block_allows_sequence(response_kind) {
            response_block.sequence_number = None;
        }

        let override_feedback = if kind == MessageType::InitDialog {
            None
        } else {
            self.feedback_override.lock().unwrap().take()
        };
        let (feedback_code, feedback_text): (String, String) = match override_feedback {
            Some((code, text)) => (code, text),
            None => match kind {
                MessageType::StoreDelivery | MessageType::PartialStoreDelivery => (
                    "0801".to_string(),
                    "Auftrag ausgeführt, Dialog weiterhin geöffnet".to_string(),
                ),
                _ => ("0800".to_string(), "Auftrag ausgeführt".to_string()),
            },
        };

        // response entry children per type (Feedback is written from
        // msg.feedback; the rest of the entry content per schema)
        let card = |forwarding: bool| osci_core::message::compose::OutProcessCard {
            creation: Some(chrono::Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()),
            forwarding: forwarding
                .then(|| chrono::Utc.with_ymd_and_hms(2026, 1, 1, 12, 5, 0).unwrap()),
            reception: None,
            subject: Some("S".into()),
        };
        let inspection = osci_core::message::Inspection {
            timestamp: Some("2026-01-01T12:06:00+01:00".into()),
            x509_subject_name: Some("CN=intermediary".into()),
            x509_issuer_name: Some("CN=intermediary-ca".into()),
            x509_serial_number: Some("1".into()),
            cert_type: Some("advanced".into()),
            math_result: Some("ok".into()),
            offline_result: Some("valid".into()),
            online_result: Some("ok".into()),
        };
        let bundle = osci_core::message::compose::OutProcessCardBundle {
            message_id: Some("bXNn".into()),
            process_cards: vec![card(false)],
            inspections: vec![inspection],
        };
        let out = OutMessage {
            kind: Some(response_kind),
            control_block: response_block,
            // the response schemas have no DesiredLanguages slot
            feedback: vec![OutFeedback {
                language: Some("de".into()),
                code: feedback_code,
                text: feedback_text,
            }],
            // the partial-store response entry requires ChunkInformation
            // (with ReceivedChunks) and the soap schema the
            // FeatureDescription header
            chunk_information: (response_kind == MessageType::ResponseToPartialStoreDelivery)
                .then(|| osci_core::message::ChunkInformation {
                    chunk_number: 1,
                    chunk_size: None,
                    received_chunks: vec![1, 2],
                    total_chunk_numbers: None,
                    total_message_size: None,
                }),
            feature_description: (response_kind == MessageType::ResponseToPartialStoreDelivery)
                .then(|| osci_core::soap::FeatureDescription {
                    chunk_message_timeout: Some(60),
                    max_chunk_size: Some(1024),
                    max_message_size: Some(4096),
                    min_chunk_size: Some(128),
                    // the six OSCIFeatures the reference client declares
                    features: vec![
                        ("DisableBase64".into(), "1.2.0".into()),
                        ("OAEPEncryption".into(), "1.6.0".into()),
                        ("SHA3HashAlgo".into(), "1.6.3".into()),
                        ("GCMPaddingModus".into(), "1.7.0".into()),
                        ("PartialMessageTransmission".into(), "1.8.0".into()),
                        ("Support96Bit12ByteIV".into(), "1.9.0".into()),
                    ],
                }),
            entry_inner: match response_kind {
                MessageType::ResponseToGetMessageId => {
                    Some("<osci:MessageId>aW50ZXJtZWRpYXJ5LWlk</osci:MessageId>".into())
                }
                MessageType::ResponseToFetchDelivery => Some(
                    "<osci:fetchDelivery><osci:SelectionRule><osci:MessageId>bXNn</osci:MessageId>\
                     </osci:SelectionRule></osci:fetchDelivery>"
                        .into(),
                ),
                MessageType::ResponseToForwardDelivery | MessageType::ResponseToStoreDelivery => {
                    None
                }
                MessageType::ResponseToMediateDelivery => Some(
                    "<osci:RequestProcessCardBundle><osci:MessageId>bXNn</osci:MessageId>\
                     <osci:ProcessCard RecentModification=\"2026-01-01T12:00:00+01:00\">\
                     <osci:Creation><osci:Plain>2026-01-01T12:00:00+01:00</osci:Plain></osci:Creation>\
                     <osci:Forwarding><osci:Plain>2026-01-01T12:05:00+01:00</osci:Plain></osci:Forwarding>\
                     <osci:Reception><osci:Plain>2026-01-01T12:06:00+01:00</osci:Plain></osci:Reception>\
                     </osci:ProcessCard><osci:InspectionReport><osci:Inspection>\
                     <osci:Timestamp><osci:Plain>2026-01-01T12:06:00+01:00</osci:Plain></osci:Timestamp>\
                     <osci:X509SubjectName>CN=intermediary</osci:X509SubjectName>\
                     <osci:X509IssuerName>CN=intermediary-ca</osci:X509IssuerName>\
                     <osci:X509SerialNumber>1</osci:X509SerialNumber>\
                     <osci:CertType Type=\"advanced\"></osci:CertType>\
                     <osci:MathResult Result=\"ok\"></osci:MathResult>\
                     <osci:OfflineResult Result=\"valid\"></osci:OfflineResult>\
                     <osci:OnlineResult Result=\"ok\"></osci:OnlineResult>\
                     </osci:Inspection></osci:InspectionReport></osci:RequestProcessCardBundle>\
                     <osci:ReplyProcessCardBundle><osci:MessageId>bXNn</osci:MessageId>\
                     <osci:ProcessCard RecentModification=\"2026-01-01T12:00:00+01:00\">\
                     <osci:Creation><osci:Plain>2026-01-01T12:00:00+01:00</osci:Plain></osci:Creation>\
                     <osci:Forwarding><osci:Plain>2026-01-01T12:05:00+01:00</osci:Plain></osci:Forwarding>\
                     </osci:ProcessCard><osci:InspectionReport><osci:Inspection>\
                     <osci:Timestamp><osci:Plain>2026-01-01T12:06:00+01:00</osci:Plain></osci:Timestamp>\
                     <osci:X509SubjectName>CN=intermediary</osci:X509SubjectName>\
                     <osci:X509IssuerName>CN=intermediary-ca</osci:X509IssuerName>\
                     <osci:X509SerialNumber>1</osci:X509SerialNumber>\
                     <osci:CertType Type=\"advanced\"></osci:CertType>\
                     <osci:MathResult Result=\"ok\"></osci:MathResult>\
                     <osci:OfflineResult Result=\"valid\"></osci:OfflineResult>\
                     <osci:OnlineResult Result=\"ok\"></osci:OnlineResult>\
                     </osci:Inspection></osci:InspectionReport></osci:ReplyProcessCardBundle>"
                        .into(),
                ),
                _ => None,
            },
            process_card_bundles: matches!(
                response_kind,
                MessageType::ResponseToStoreDelivery | MessageType::ResponseToForwardDelivery
            )
            .then(|| vec![bundle.clone()])
            .unwrap_or_default(),
            ..Default::default()
        };
        compose_message(&out, "MIME_boundary").map_err(|e| TransportError::new(e.to_string()))
    }
}

/// Transport wrapper that mirrors sent bytes into a log (wire assertions).
struct ProbeTransport {
    inner: LoopbackTransport,
    log: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl osci_transport::Transport for ProbeTransport {
    fn send(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.log.lock().unwrap().push(message.to_vec());
        self.inner.send(message)
    }
}

type Seen = Arc<Mutex<Vec<(MessageType, ControlBlock)>>>;
type Mailbox = Arc<Mutex<Vec<Vec<u8>>>>;

fn transport() -> (LoopbackTransport, Seen, Mailbox) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let intermediary = ScriptedIntermediary::new(seen.clone());
    let mailbox = intermediary.mailbox_handle();
    (
        LoopbackTransport::new(Box::new(intermediary)),
        seen,
        mailbox,
    )
}

fn signer() -> RsaSigner {
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

fn unsigned_out(kind: MessageType, sequence: Option<u32>) -> OutMessage {
    // per-kind certificate sets: the NonIntermediaryCertificates content
    // model is restricted per message type (issue #3)
    let cipher_originator = OutCertEntry {
        role: CertRole::Originator,
        use_: CertUse::Cipher,
        id: "originator_cipher".into(),
        der: cert_der("alice_cipher_4096.pem"),
    };
    let signature_originator = OutCertEntry {
        role: CertRole::Originator,
        use_: CertUse::Signature,
        id: "originator_signature".into(),
        der: cert_der("alice_signature_4096.pem"),
    };
    let cipher_addressee = OutCertEntry {
        role: CertRole::Addressee,
        use_: CertUse::Cipher,
        id: "addressee_cipher".into(),
        der: cert_der("bob_cipher_4096.pem"),
    };
    let certificates = match kind {
        // only originator entries (schema: GetMessageId allows the
        // cipher + signature originator, InitDialog requires the cipher
        // one, ExitDialog/FetchDelivery the signature originator only)
        MessageType::GetMessageId | MessageType::InitDialog => {
            vec![cipher_originator, signature_originator]
        }
        MessageType::ExitDialog | MessageType::FetchDelivery => vec![signature_originator],
        // deliveries carry the reader's cipher certificate (the
        // StoreDelivery schema makes it mandatory)
        _ => vec![cipher_originator, signature_originator, cipher_addressee],
    };
    OutMessage {
        kind: Some(kind),
        control_block: ControlBlock {
            sequence_number: sequence,
            challenge: Some("Y2xpZW50LWNoYWxsZW5nZQ==".into()),
            conversation_id: Some("4711".into()),
            response: None,
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: certificates,
        ..Default::default()
    }
}

/// Open the dialog (InitDialog round; the intermediary assigns the
/// conversation id with its response).
fn init_dialog(dialog: &mut Dialog) -> OsciMessage {
    let mut out = unsigned_out(MessageType::InitDialog, None);
    let response = dialog
        .send(&mut out, &[], "MIME_boundary")
        .expect("init round");
    assert_eq!(response.kind, Some(MessageType::ResponseToInitDialog));
    response
}

/// SynchronousUseCaseIT (essence): InitDialog -> GetMessageId ->
/// ForwardDelivery, both signed, with full control-block protocol.
#[test]
fn synchronous_scenario() {
    let (transport, seen, _mailbox) = transport();
    let mut dialog = Dialog::new(Box::new(transport))
        .with_signer(Box::new(signer()), "originator_signature".into());
    init_dialog(&mut dialog);

    // round 2: GetMessageId
    let mut out = unsigned_out(MessageType::GetMessageId, None);
    let response = dialog
        .send(&mut out, &[], "MIME_boundary")
        .expect("get message id round");
    assert_eq!(response.kind, Some(MessageType::ResponseToGetMessageId));
    let feedback = first_feedback(&response).unwrap();
    assert!(feedback.code.starts_with('0'), "feedback {}", feedback.code);

    // round 3: ForwardDelivery with the message id from round 2 - the
    // dialog adopted the intermediary's challenge
    let mut forward = unsigned_out(MessageType::ForwardDelivery, None);
    forward.entry_inner = Some(
        "<osci:ContentReceiver URI=\"http://localhost/rec\"></osci:ContentReceiver>\
         <osci:MessageId>bXNnLWZ3ZA==</osci:MessageId><osci:Subject>Subject</osci:Subject>"
            .into(),
    );
    forward.containers.push(OutContentContainer {
        id: "contentcontainer".into(),
        contents: vec![OutContent {
            id: "content1".into(),
            text: Some("forwarded payload".into()),
            href: None,
        }],
        encrypted_attachments: Vec::new(),
    });
    let response = dialog
        .send(&mut forward, &[], "MIME_boundary")
        .expect("forward round");
    assert_eq!(response.kind, Some(MessageType::ResponseToForwardDelivery));
    let feedback = first_feedback(&response).unwrap();
    assert_eq!(feedback.code, "0800");

    // all requests hit the intermediary with valid protocol
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].0, MessageType::InitDialog);
    assert_eq!(seen[1].0, MessageType::GetMessageId);
    assert_eq!(seen[2].0, MessageType::ForwardDelivery);
}

/// AsynchronousUseCaseIT (essence): InitDialog, StoreDelivery, then
/// FetchDelivery of the stored message from the mailbox.
#[test]
fn asynchronous_scenario() {
    let (transport, _seen, mailbox) = transport();
    let mut dialog = Dialog::new(Box::new(transport));
    init_dialog(&mut dialog);

    let mut store = unsigned_out(MessageType::StoreDelivery, None);
    store.entry_inner =
        Some("<osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into());
    store.containers.push(OutContentContainer {
        id: "contentcontainer".into(),
        contents: vec![OutContent {
            id: "content1".into(),
            text: Some("async payload".into()),
            href: None,
        }],
        encrypted_attachments: Vec::new(),
    });
    let response = dialog.send(&mut store, &[], "MIME_boundary").unwrap();
    assert_eq!(response.kind, Some(MessageType::ResponseToStoreDelivery));
    assert_eq!(first_feedback(&response).unwrap().code, "0801");
    assert_eq!(mailbox.lock().unwrap().len(), 1, "stored in the mailbox");

    // fetch: the request carries the next challenge adopted from round 1
    let mut fetch = unsigned_out(MessageType::FetchDelivery, None);
    fetch.selection_rule = Some("bXNn".into());
    let response = dialog.send(&mut fetch, &[], "MIME_boundary").unwrap();
    assert_eq!(response.kind, Some(MessageType::ResponseToFetchDelivery));
}

/// ParallelSendReceiveIT (essence): several messages in one dialog, the
/// control-block state threading through all rounds.
#[test]
fn parallel_scenario() {
    let (transport, seen, _mailbox) = transport();
    let mut dialog = Dialog::new(Box::new(transport));
    init_dialog(&mut dialog);

    for kind in [
        MessageType::GetMessageId,
        MessageType::GetMessageId,
        MessageType::StoreDelivery,
        MessageType::ExitDialog,
    ] {
        let mut out = unsigned_out(kind, None);
        if matches!(kind, MessageType::StoreDelivery) {
            out.entry_inner =
                Some("<osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into());
            out.containers.push(OutContentContainer {
                id: "contentcontainer".into(),
                contents: vec![OutContent {
                    id: "content1".into(),
                    text: Some("parallel payload".into()),
                    href: None,
                }],
                encrypted_attachments: Vec::new(),
            });
        }
        let response = dialog.send(&mut out, &[], "MIME_boundary").unwrap();
        let code = first_feedback(&response).unwrap().code.clone();
        assert!(code.starts_with('0'), "{kind:?}: feedback {code}");
    }
    assert_eq!(seen.lock().unwrap().len(), 5, "all five rounds processed");
}

/// A response that fails the challenge protocol is rejected
/// (checkControlBlock port).
#[test]
fn broken_challenge_rejected() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let intermediary = ScriptedIntermediary::new(seen.clone());
    // break the SECOND response: the first (InitDialog) must succeed so
    // the dialog state is established
    *intermediary.break_from_round.lock().unwrap() = 2;
    let transport = LoopbackTransport::new(Box::new(intermediary));
    let mut dialog = Dialog::new(Box::new(transport));
    init_dialog(&mut dialog);

    let mut out = unsigned_out(MessageType::GetMessageId, None);
    let error = dialog.send(&mut out, &[], "MIME_boundary").unwrap_err();
    assert!(
        matches!(error, DialogError::WrongControlBlock(_)),
        "expected control-block rejection, got {error:?}"
    );
}

/// Signed round trips: the sent messages carry valid transport
/// signatures (verified through our own pipeline on the wire bytes).
#[test]
fn signed_round_trips_verify_on_the_wire() {
    let (loopback, seen, _mailbox) = transport();
    let log: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let probe = ProbeTransport {
        inner: loopback,
        log: log.clone(),
    };
    let mut dialog =
        Dialog::new(Box::new(probe)).with_signer(Box::new(signer()), "originator_signature".into());
    init_dialog(&mut dialog);

    let mut out = unsigned_out(MessageType::GetMessageId, None);
    dialog.send(&mut out, &[], "MIME_boundary").unwrap();

    let wire = log.lock().unwrap()[1].clone();
    let xml = extract_xml(&wire);
    let report = osci::security::verify_message(&xml, &[]).unwrap();
    assert!(report.all_valid(), "wire signature valid: {report:#?}");
    assert_eq!(seen.lock().unwrap().len(), 2);
}

/// EFFI chunked send (issue #4): the full signed delivery is composed
/// once via `compose_signed_stream` (dialog state advances exactly once),
/// split into chunk blobs, and each blob ships as a PartialStoreDelivery
/// with the blob as its single MIME attachment - the reassembly feedback
/// (0801) comes with the intermediary's chunk echo.
#[test]
fn chunked_send_round() {
    let (transport, seen, _mailbox) = transport();
    let mut dialog = Dialog::new(Box::new(transport))
        .with_signer(Box::new(signer()), "originator_signature".into());
    init_dialog(&mut dialog);

    // the full signed delivery (signed via the dialog's signer; not sent)
    let mut full = unsigned_out(MessageType::StoreDelivery, None);
    full.entry_inner =
        Some("<osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into());
    full.containers.push(OutContentContainer {
        id: "contentcontainer".into(),
        contents: vec![OutContent {
            id: "content1".into(),
            text: Some("the chunked payload of the full delivery".into()),
            href: None,
        }],
        encrypted_attachments: Vec::new(),
    });
    // the full stream carries its own MIME framing - the chunk messages
    // must use a different boundary so the blob bytes cannot collide
    // with the outer multipart markers
    let stream = dialog
        .compose_signed_stream(&mut full, &[], "FULL_boundary")
        .expect("full delivery composed and signed");

    // split the serialized delivery into two chunk blobs
    let half = stream.len() / 2;
    let blobs = [&stream[..half], &stream[half..]];
    let total = stream.len() as i64;

    for (i, blob) in blobs.iter().enumerate() {
        let mut out = unsigned_out(MessageType::PartialStoreDelivery, None);
        out.entry_inner =
            Some("<osci:MessageId>bXNn</osci:MessageId><osci:Subject>S</osci:Subject>".into());
        out.chunk_information = Some(osci_core::message::ChunkInformation {
            chunk_number: (i + 1) as i64,
            chunk_size: Some(blob.len() as i64),
            total_chunk_numbers: Some(blobs.len() as i64),
            total_message_size: Some(total),
            received_chunks: Vec::new(),
        });
        out.feature_description = Some(osci_core::soap::FeatureDescription {
            chunk_message_timeout: Some(60),
            max_chunk_size: Some(1024),
            max_message_size: Some(4096),
            min_chunk_size: Some(128),
            features: vec![
                ("DisableBase64".into(), "1.2.0".into()),
                ("OAEPEncryption".into(), "1.6.0".into()),
                ("SHA3HashAlgo".into(), "1.6.3".into()),
                ("GCMPaddingModus".into(), "1.7.0".into()),
                ("PartialMessageTransmission".into(), "1.8.0".into()),
                ("Support96Bit12ByteIV".into(), "1.9.0".into()),
            ],
        });
        out.containers.push(OutContentContainer {
            id: "ChunkContentContainer".into(),
            contents: vec![OutContent {
                id: "ChunkContent".into(),
                href: Some(format!("cid:ChunkBlob{i}")),
                text: None,
            }],
            encrypted_attachments: Vec::new(),
        });
        out.attachments.push(OutAttachment {
            content_id: format!("ChunkBlob{i}"),
            content_type: "application/octet-stream".into(),
            base64_encoding: false,
            data: blob.to_vec(),
        });
        // the chunk blob is a signed cid: reference (the live-accepted
        // fixture's SignedInfo carries cid:ChunkBlobStoreDelivery)
        let attachments = vec![(format!("ChunkBlob{i}"), blob.to_vec())];
        let response = dialog
            .send(&mut out, &attachments, "MIME_boundary")
            .unwrap();
        assert_eq!(
            response.kind,
            Some(MessageType::ResponseToPartialStoreDelivery),
            "chunk {i}"
        );
        let feedback = first_feedback(&response).unwrap();
        assert!(feedback.code.starts_with('0'), "chunk {i}: {feedback:?}");
        assert_eq!(
            response.chunk_information.as_ref().unwrap().received_chunks,
            vec![1, 2],
            "chunk {i}: reassembly echo"
        );
    }
    assert_eq!(seen.lock().unwrap().len(), 3, "init + two chunks");
}

/// Issue #7 part 1: feedback 3800 ("more deliveries pending after a
/// successful fetch") accompanies successful fetch-all responses and
/// must reach the downstream classification, not abort the exchange.
#[test]
fn fetch_feedback_3800_is_accepted() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let intermediary = ScriptedIntermediary::new(seen.clone());
    // applies to the fetch round (the init response keeps its success code)
    *intermediary.feedback_override.lock().unwrap() =
        Some(("3800".into(), "Weitere Lieferungen stehen aus".into()));
    let transport = LoopbackTransport::new(Box::new(intermediary));
    let mut dialog = Dialog::new(Box::new(transport));
    init_dialog(&mut dialog);

    let mut out = unsigned_out(MessageType::FetchDelivery, None);
    out.selection_rule = Some("bXNn".into());
    let response = dialog.send(&mut out, &[], "MIME_boundary").unwrap();
    assert_eq!(response.kind, Some(MessageType::ResponseToFetchDelivery));
    let feedback = first_feedback(&response).unwrap();
    assert_eq!(feedback.code, "3800", "3800 reaches the caller");
}

/// The tolerance does not extend to other non-success codes: 3707 stays
/// an exchange error.
#[test]
fn fetch_feedback_3707_is_rejected() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let intermediary = ScriptedIntermediary::new(seen.clone());
    *intermediary.feedback_override.lock().unwrap() =
        Some(("3707".into(), "Zertifikat abgelaufen".into()));
    let transport = LoopbackTransport::new(Box::new(intermediary));
    let mut dialog = Dialog::new(Box::new(transport));
    init_dialog(&mut dialog);

    let mut out = unsigned_out(MessageType::FetchDelivery, None);
    out.selection_rule = Some("bXNn".into());
    let error = dialog.send(&mut out, &[], "MIME_boundary").unwrap_err();
    assert!(
        matches!(error, DialogError::ErrorFeedback { ref code, .. } if code == "3707"),
        "3707 rejected: {error:?}"
    );
}
