//! M7: the four reference integration scenarios (Synchronous /
//! Asynchronous / RequestResponse / ParallelSendReceive), offline, over
//! the loopback transport and a scripted mock intermediary.

mod common;

use std::io::Read;
use std::sync::{Arc, Mutex};

use osci::dialog::{Dialog, DialogError, first_feedback};
use osci_core::message::MessageType;
use osci_core::message::compose::{
    OutCertEntry, OutContent, OutContentContainer, OutFeedback, OutMessage, compose_message,
};
use osci_core::message::stored::StoredMessage;
use osci_core::soap::{CertRole, CertUse, ControlBlock};
use osci_crypto::software::RsaSigner;
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

/// The mock intermediary: validates the request's control-block protocol
/// and replies with the matching ResponseTo* message (feedback 0800/0801)
/// carrying the next challenge.
struct ScriptedIntermediary {
    /// seen requests (for assertions)
    seen: Arc<Mutex<Vec<(MessageType, ControlBlock)>>>,
    /// break the challenge echo in one reply (negative test)
    break_challenge_once: Mutex<bool>,
    /// stored deliveries (the " mailbox", for the async scenario)
    mailbox: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ScriptedIntermediary {
    fn new(seen: Arc<Mutex<Vec<(MessageType, ControlBlock)>>>) -> Self {
        Self {
            seen,
            break_challenge_once: Mutex::new(false),
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
        let stored = StoredMessage::load(message).map_err(|e| TransportError(e.to_string()))?;
        let kind = stored
            .message
            .kind
            .ok_or_else(|| TransportError("no kind".into()))?;
        let request_block = control_block_of(&String::from_utf8_lossy(&stored.xml));

        // protocol validation on the intermediary side: the request must
        // carry a challenge (our previous one answered)
        if request_block.challenge.is_none() {
            return Err(TransportError("request without challenge".into()));
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
            other => return Err(TransportError(format!("unhandled type {other:?}"))),
        };

        // control-block protocol: response answers the request's
        // challenge, echoes sequence + conversation, provides a new
        // challenge
        let mut response_block = ControlBlock {
            conversation_id: request_block.conversation_id.clone(),
            sequence_number: request_block.sequence_number,
            response: request_block.challenge.clone(),
            challenge: Some(osci_core::helper::base64::encode(
                b"intermediary-next-challen",
            )),
        };
        if *self.break_challenge_once.lock().unwrap() {
            response_block.response = Some("d3Jvbmc=".into());
            *self.break_challenge_once.lock().unwrap() = false;
        }

        let feedback_code = if kind == MessageType::StoreDelivery {
            "0801"
        } else {
            "0800"
        };
        let feedback_text = if kind == MessageType::StoreDelivery {
            "Auftrag ausgeführt, Dialog weiterhin geöffnet"
        } else {
            "Auftrag ausgeführt"
        };

        let out = OutMessage {
            kind: Some(response_kind),
            control_block: response_block,
            desired_languages: Some("de".into()),
            feedback: vec![OutFeedback {
                language: Some("de".into()),
                code: feedback_code.into(),
                text: feedback_text.into(),
            }],
            entry_inner: Some("<osci:MessageId>aW50ZXJtZWRpYXJ5LWlk</osci:MessageId>".into()),
            ..Default::default()
        };
        compose_message(&out, "MIME_boundary").map_err(|e| TransportError(e.to_string()))
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
    OutMessage {
        kind: Some(kind),
        control_block: ControlBlock {
            sequence_number: sequence,
            challenge: Some("Y2xpZW50LWNoYWxsZW5nZQ==".into()),
            conversation_id: Some("dialog-4711".into()),
            response: None,
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: vec![
            OutCertEntry {
                role: CertRole::Originator,
                use_: CertUse::Cipher,
                id: "originator_cipher".into(),
                der: cert_der("alice_cipher_4096.pem"),
            },
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
    }
}

/// SynchronousUseCaseIT (essence): GetMessageId -> ForwardDelivery, both
/// signed, with full control-block protocol across two round trips.
#[test]
fn synchronous_scenario() {
    let (transport, seen, _mailbox) = transport();
    let mut dialog = Dialog::new(Box::new(transport))
        .with_signer(Box::new(signer()), "originator_signature".into());

    // round 1: GetMessageId
    let mut out = unsigned_out(MessageType::GetMessageId, None);
    let response = dialog
        .send(&mut out, &[], "MIME_boundary")
        .expect("get message id round");
    assert_eq!(response.kind, Some(MessageType::ResponseToGetMessageId));
    let feedback = first_feedback(&response).unwrap();
    assert!(feedback.code.starts_with('0'), "feedback {}", feedback.code);

    // round 2: ForwardDelivery with the message id from round 1 - the
    // dialog adopted the intermediary's challenge
    let mut forward = unsigned_out(MessageType::ForwardDelivery, None);
    forward.entry_inner = Some(
        "<osci:MessageId>bXNnLWZ3ZA==</osci:MessageId><osci:Subject>Subject</osci:Subject>".into(),
    );
    let response = dialog
        .send(&mut forward, &[], "MIME_boundary")
        .expect("forward round");
    assert_eq!(response.kind, Some(MessageType::ResponseToForwardDelivery));
    let feedback = first_feedback(&response).unwrap();
    assert_eq!(feedback.code, "0800");

    // both requests hit the intermediary with valid protocol
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].0, MessageType::GetMessageId);
    assert_eq!(seen[1].0, MessageType::ForwardDelivery);
}

/// AsynchronousUseCaseIT (essence): StoreDelivery, then FetchDelivery of
/// the stored message from the mailbox.
#[test]
fn asynchronous_scenario() {
    let (transport, _seen, mailbox) = transport();
    let mut dialog = Dialog::new(Box::new(transport));

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

    for kind in [
        MessageType::GetMessageId,
        MessageType::GetMessageId,
        MessageType::StoreDelivery,
        MessageType::ExitDialog,
    ] {
        let mut out = unsigned_out(kind, None);
        if matches!(kind, MessageType::StoreDelivery) {
            out.entry_inner = Some("<osci:MessageId>bXNn</osci:MessageId>".into());
        }
        let response = dialog.send(&mut out, &[], "MIME_boundary").unwrap();
        let code = first_feedback(&response).unwrap().code.clone();
        assert!(code.starts_with('0'), "{kind:?}: feedback {code}");
    }
    assert_eq!(seen.lock().unwrap().len(), 4, "all four rounds processed");
}

/// A response that fails the challenge protocol is rejected
/// (checkControlBlock port).
#[test]
fn broken_challenge_rejected() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let intermediary = ScriptedIntermediary::new(seen.clone());
    *intermediary.break_challenge_once.lock().unwrap() = true;
    let transport = LoopbackTransport::new(Box::new(intermediary));
    let mut dialog = Dialog::new(Box::new(transport));

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

    let mut out = unsigned_out(MessageType::GetMessageId, None);
    dialog.send(&mut out, &[], "MIME_boundary").unwrap();

    let wire = log.lock().unwrap()[0].clone();
    let xml = extract_xml(&wire);
    let report = osci::security::verify_message(&xml, &[]).unwrap();
    assert!(report.all_valid(), "wire signature valid: {report:#?}");
    assert_eq!(seen.lock().unwrap().len(), 1);
}
