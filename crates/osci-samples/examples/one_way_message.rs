//! Port of `samples.OneWayMessage_ActiveRecipient` (essence): a client
//! sends a signed StoreDelivery over real HTTP to an in-process
//! intermediary endpoint, then fetches the reply feedback.
//!
//! The "intermediary" is a minimal HTTP server running the scripted mock
//! from the M7 tests on a local port - the flow, signing and control
//! block protocol are the real thing.
//!
//! Run with: cargo run -p osci-samples --example one_way_message

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use osci::dialog::{Dialog, first_feedback};
use osci_core::message::MessageType;
use osci_core::message::compose::{
    OutCertEntry, OutContent, OutContentContainer, OutMessage, compose_message,
};
use osci_core::soap::{CertRole, CertUse, ControlBlock};
use osci_crypto::software::RsaSigner;
use osci_transport::http::{HttpTransport, HttpTransportConfig};
use osci_transport::{MockIntermediary, Transport, TransportError};

fn workspace_root() -> PathBuf {
    // corpus lives at <root>/testcorpus; examples run from the crate dir
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir.pop();
    dir
}

fn cert_der(pem: &str) -> Vec<u8> {
    let dump =
        std::fs::read_to_string(workspace_root().join("testcorpus/certs").join(pem)).unwrap();
    let start = dump.find("-----BEGIN CERTIFICATE-----").unwrap();
    let after = &dump[start + 27..];
    let end = after.find("-----END CERTIFICATE-----").unwrap();
    let b64: String = after[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    osci_core::helper::base64::decode(&b64).unwrap()
}

/// The scripted intermediary from the M7 tests, served over HTTP.
struct Intermediary;

impl MockIntermediary for Intermediary {
    fn handle(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        let stored = osci_core::message::stored::StoredMessage::load(message)
            .map_err(|e| TransportError(e.to_string()))?;
        let kind = stored.message.kind.unwrap_or(MessageType::GetMessageId);
        let request_block = {
            let doc = osci_core::xml::parser::parse(&String::from_utf8_lossy(&stored.xml)).unwrap();
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
        };
        let response_kind = match kind {
            MessageType::InitDialog => MessageType::ResponseToInitDialog,
            MessageType::GetMessageId => MessageType::ResponseToGetMessageId,
            MessageType::StoreDelivery => MessageType::ResponseToStoreDelivery,
            other => return Err(TransportError(format!("unhandled {other:?}"))),
        };
        let (code, text) = if kind == MessageType::StoreDelivery {
            ("0801", "Auftrag ausgeführt, Dialog weiterhin geöffnet")
        } else {
            ("0800", "Auftrag ausgeführt")
        };
        // the intermediary assigns the conversation id with the
        // InitDialog response (the schema requires it there)
        let mut response_block = ControlBlock {
            conversation_id: request_block
                .conversation_id
                .clone()
                .or_else(|| Some("4711".into())),
            sequence_number: request_block.sequence_number,
            response: request_block.challenge,
            challenge: Some(osci_core::helper::base64::encode(b"next-challenge")),
        };
        if !osci_core::message::compose::control_block_allows_conversation(response_kind) {
            response_block.conversation_id = None;
        }
        if !osci_core::message::compose::control_block_allows_sequence(response_kind) {
            response_block.sequence_number = None;
        }
        let out = OutMessage {
            kind: Some(response_kind),
            control_block: response_block,
            // the response schemas have no DesiredLanguages slot (issue #3)
            feedback: vec![osci_core::message::compose::OutFeedback {
                language: Some("de".into()),
                code: code.into(),
                text: text.into(),
            }],
            entry_inner: match response_kind {
                MessageType::ResponseToGetMessageId => {
                    Some("<osci:MessageId>aWQ=</osci:MessageId>".into())
                }
                // responseToStoreDeliveryType: Feedback + ProcessCardBundle
                _ => None,
            },
            process_card_bundles: if response_kind == MessageType::ResponseToStoreDelivery {
                // the bundle schema requires MessageId + ProcessCard +
                // InspectionReport
                vec![osci_core::message::compose::OutProcessCardBundle {
                    message_id: Some("aWQ=".into()),
                    process_cards: vec![osci_core::message::compose::OutProcessCard {
                        creation: Some(chrono::Utc::now()),
                        forwarding: None,
                        reception: None,
                        subject: Some("Hello OSCI".into()),
                    }],
                    inspections: vec![osci_core::message::Inspection {
                        timestamp: Some(osci_core::helper::dates::format_iso8601(
                            &chrono::Utc::now(),
                        )),
                        x509_subject_name: Some("CN=sample-intermediary".into()),
                        x509_issuer_name: Some("CN=sample-ca".into()),
                        x509_serial_number: Some("1".into()),
                        cert_type: Some("advanced".into()),
                        math_result: Some("ok".into()),
                        offline_result: Some("valid".into()),
                        online_result: Some("ok".into()),
                    }],
                }]
            } else {
                Vec::new()
            },
            ..Default::default()
        };
        compose_message(&out, "MIME_boundary").map_err(|e| TransportError(e.to_string()))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. start the intermediary endpoint
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let server = std::thread::spawn(move || {
        let intermediary = Intermediary;
        // exactly the two rounds of this sample, then the listener drops
        for stream in listener.incoming().flatten().take(3) {
            let mut stream = stream;
            let mut request = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let text = String::from_utf8_lossy(&request[..header_end]).to_string();
                    let length = text
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("content-length"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + length {
                        break;
                    }
                }
            }
            let header_end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let body = &request[header_end + 4..];
            let response = match intermediary.handle(body) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("intermediary rejected: {e}");
                    format!("intermediary rejected: {e}").into_bytes()
                }
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            );
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(&response).unwrap();
        }
    });

    // 2. client: signed store delivery over real HTTP
    let signer = RsaSigner::from_pem_dump(
        workspace_root()
            .join("testcorpus/certs/alice_signature_4096.pem")
            .to_str()
            .ok_or("path")?,
        None,
    )?;

    let transport = HttpTransport::new(HttpTransportConfig {
        endpoint: format!("http://127.0.0.1:{port}/osci/externalentry"),
        ..Default::default()
    })?;
    let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let logging = LoggingTransport {
        inner: transport,
        log,
    };

    let mut dialog =
        Dialog::new(Box::new(logging)).with_signer(Box::new(signer), "originator_signature".into());

    // round 1: open the dialog (the intermediary assigns the
    // conversation id with its response)
    let mut init = client_message(MessageType::InitDialog);
    let response = dialog.send(&mut init, &[], "MIME_boundary")?;
    println!(
        "intermediary: {} {}",
        first_feedback(&response).unwrap().code,
        first_feedback(&response).unwrap().text
    );

    // round 2: obtain a message id (like the reference sample's
    // GetMessageId before MediateDelivery/ForwardDelivery)
    let mut get_id = client_message(MessageType::GetMessageId);
    let response = dialog.send(&mut get_id, &[], "MIME_boundary")?;
    println!(
        "intermediary: {} {}",
        first_feedback(&response).unwrap().code,
        first_feedback(&response).unwrap().text
    );

    // round 3: the store delivery with content
    let mut store = client_message(MessageType::StoreDelivery);
    store.entry_inner = Some(
        "<osci:MessageId>bXNnLWlk</osci:MessageId><osci:Subject>Hello OSCI</osci:Subject>".into(),
    );
    store.containers.push(OutContentContainer {
        id: "contentcontainer".into(),
        contents: vec![OutContent {
            id: "content1".into(),
            text: Some("one way message payload".into()),
            href: None,
        }],
        encrypted_attachments: Vec::new(),
    });
    let response = dialog.send(&mut store, &[], "MIME_boundary")?;
    let feedback = first_feedback(&response).unwrap();
    println!("intermediary: {} {}", feedback.code, feedback.text);
    assert!(feedback.code.starts_with('0'), "delivery accepted");

    let wire = seen.lock().unwrap().clone();
    println!(
        "sent {} bytes over HTTP in 3 rounds; the wire messages carry valid transport signatures",
        wire.len()
    );
    println!("sample completed");
    drop(dialog);
    server.join().unwrap();
    Ok(())
}

fn client_message(kind: MessageType) -> OutMessage {
    // per-type legal certificate sets (issue #3: GetMessageId allows the
    // originator entries only; the store delivery additionally names the
    // reader's cipher certificate, which its schema makes mandatory)
    let certs = match kind {
        // InitDialog: cipher originator (required) + signature originator
        MessageType::InitDialog | MessageType::GetMessageId => vec![
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
        ],
        _ => vec![
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
    };
    OutMessage {
        kind: Some(kind),
        control_block: ControlBlock {
            conversation_id: Some("4711".into()),
            sequence_number: None,
            response: None,
            challenge: Some("c2FtcGxlLWNoYWxsZW5nZQ==".into()),
        },
        desired_languages: Some("de".into()),
        non_intermediary_certificates: certs,
        ..Default::default()
    }
}

/// Transport wrapper logging raw bytes for the final report.
struct LoggingTransport {
    inner: HttpTransport,
    log: Arc<Mutex<Vec<u8>>>,
}

impl Transport for LoggingTransport {
    fn send(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.log.lock().unwrap().extend_from_slice(message);
        self.inner.send(message)
    }
}
