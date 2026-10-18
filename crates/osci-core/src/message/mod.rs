//! OSCI message types (port of `de.osci.osci12.messagetypes`): message
//! recognition and parsing, plus composition (`compose`).

pub mod compose;
pub use compose::ComposeError;
pub mod mmd;
pub mod stored;

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::helper::dates::parse_iso8601;
use crate::soap::{self, OSCI_NS, OSCI2017_NS};
use crate::xml::{Document, Element, SOAP_ENVELOPE_NS};

#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("no SOAP envelope")]
    NoEnvelope,
    #[error("no message entry found")]
    NoMessageEntry,
    #[error("multiple message entries found")]
    MultipleMessageEntries,
    #[error("invalid message: {0}")]
    Invalid(String),
}

/// All OSCI-Transport 1.2 message types (element names from
/// `Constants.HeaderTags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    InitDialog,
    ExitDialog,
    GetMessageId,
    StoreDelivery,
    FetchDelivery,
    AcceptDelivery,
    ProcessDelivery,
    ForwardDelivery,
    MediateDelivery,
    FetchProcessCard,
    PartialStoreDelivery,
    PartialFetchDelivery,
    ResponseToInitDialog,
    ResponseToExitDialog,
    ResponseToGetMessageId,
    ResponseToStoreDelivery,
    ResponseToFetchDelivery,
    ResponseToAcceptDelivery,
    ResponseToProcessDelivery,
    ResponseToForwardDelivery,
    ResponseToMediateDelivery,
    ResponseToFetchProcessCard,
    ResponseToPartialStoreDelivery,
    ResponseToPartialFetchDelivery,
}

impl MessageType {
    /// Recognize a message entry by namespace URI and element name.
    pub fn from_element(uri: &str, local: &str) -> Option<Self> {
        Some(match (uri, local) {
            (OSCI_NS, "initDialog") => Self::InitDialog,
            (OSCI_NS, "exitDialog") => Self::ExitDialog,
            (OSCI_NS, "getMessageId") => Self::GetMessageId,
            (OSCI_NS, "storeDelivery") => Self::StoreDelivery,
            (OSCI_NS, "fetchDelivery") => Self::FetchDelivery,
            (OSCI_NS, "acceptDelivery") => Self::AcceptDelivery,
            (OSCI_NS, "processDelivery") => Self::ProcessDelivery,
            (OSCI_NS, "forwardDelivery") => Self::ForwardDelivery,
            (OSCI_NS, "mediateDelivery") => Self::MediateDelivery,
            (OSCI_NS, "fetchProcessCard") => Self::FetchProcessCard,
            (OSCI2017_NS, "partialStoreDelivery") => Self::PartialStoreDelivery,
            (OSCI2017_NS, "partialFetchDelivery") => Self::PartialFetchDelivery,
            (OSCI_NS, "responseToInitDialog") => Self::ResponseToInitDialog,
            (OSCI_NS, "responseToExitDialog") => Self::ResponseToExitDialog,
            (OSCI_NS, "responseToGetMessageId") => Self::ResponseToGetMessageId,
            (OSCI_NS, "responseToStoreDelivery") => Self::ResponseToStoreDelivery,
            (OSCI_NS, "responseToFetchDelivery") => Self::ResponseToFetchDelivery,
            (OSCI_NS, "responseToAcceptDelivery") => Self::ResponseToAcceptDelivery,
            (OSCI_NS, "responseToProcessDelivery") => Self::ResponseToProcessDelivery,
            (OSCI_NS, "responseToForwardDelivery") => Self::ResponseToForwardDelivery,
            (OSCI_NS, "responseToMediateDelivery") => Self::ResponseToMediateDelivery,
            (OSCI_NS, "responseToFetchProcessCard") => Self::ResponseToFetchProcessCard,
            (OSCI2017_NS, "responseToPartialStoreDelivery") => Self::ResponseToPartialStoreDelivery,
            (OSCI2017_NS, "responseToPartialFetchDelivery") => Self::ResponseToPartialFetchDelivery,
            _ => return None,
        })
    }

    pub fn element_name(&self) -> &'static str {
        match self {
            Self::InitDialog => "initDialog",
            Self::ExitDialog => "exitDialog",
            Self::GetMessageId => "getMessageId",
            Self::StoreDelivery => "storeDelivery",
            Self::FetchDelivery => "fetchDelivery",
            Self::AcceptDelivery => "acceptDelivery",
            Self::ProcessDelivery => "processDelivery",
            Self::ForwardDelivery => "forwardDelivery",
            Self::MediateDelivery => "mediateDelivery",
            Self::FetchProcessCard => "fetchProcessCard",
            Self::PartialStoreDelivery => "partialStoreDelivery",
            Self::PartialFetchDelivery => "partialFetchDelivery",
            Self::ResponseToInitDialog => "responseToInitDialog",
            Self::ResponseToExitDialog => "responseToExitDialog",
            Self::ResponseToGetMessageId => "responseToGetMessageId",
            Self::ResponseToStoreDelivery => "responseToStoreDelivery",
            Self::ResponseToFetchDelivery => "responseToFetchDelivery",
            Self::ResponseToAcceptDelivery => "responseToAcceptDelivery",
            Self::ResponseToProcessDelivery => "responseToProcessDelivery",
            Self::ResponseToForwardDelivery => "responseToForwardDelivery",
            Self::ResponseToMediateDelivery => "responseToMediateDelivery",
            Self::ResponseToFetchProcessCard => "responseToFetchProcessCard",
            Self::ResponseToPartialStoreDelivery => "responseToPartialStoreDelivery",
            Self::ResponseToPartialFetchDelivery => "responseToPartialFetchDelivery",
        }
    }

    pub fn is_response(&self) -> bool {
        self.element_name().starts_with("responseTo")
    }

    pub fn namespace(&self) -> &'static str {
        match self {
            Self::PartialStoreDelivery
            | Self::PartialFetchDelivery
            | Self::ResponseToPartialStoreDelivery
            | Self::ResponseToPartialFetchDelivery => OSCI2017_NS,
            _ => OSCI_NS,
        }
    }
}

/// Fields of a request message entry (present ones depend on the type).
#[derive(Debug, Clone, Default)]
pub struct RequestFields {
    /// Base64 message id, exactly as on the wire.
    pub message_id: Option<String>,
    pub subject: Option<String>,
    /// Selection rule content (fetch deliveries); the element may be
    /// empty or carry attributes only.
    pub selection_rule: Option<Element>,
    pub quantity: Option<String>,
    pub content_receiver: Option<String>,
}

/// One feedback entry (`osci:Feedback/osci:Entry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackEntry {
    /// `xml:lang` attribute, when present.
    pub language: Option<String>,
    /// OSCI feedback code (e.g. `0800`).
    pub code: String,
    pub text: String,
}

/// One process card (`osci:ProcessCard`): delivery receipt timestamps.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessCard {
    pub recent_modification: Option<DateTime<Utc>>,
    pub creation: Option<DateTime<Utc>>,
    pub forwarding: Option<DateTime<Utc>>,
    pub reception: Option<DateTime<Utc>>,
    pub subject: Option<String>,
}

/// One inspection (`osci:Inspection` of an inspection report).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inspection {
    pub timestamp: Option<String>,
    pub x509_subject_name: Option<String>,
    pub x509_issuer_name: Option<String>,
    pub x509_serial_number: Option<String>,
    pub cert_type: Option<String>,
    pub math_result: Option<String>,
    pub offline_result: Option<String>,
    pub online_result: Option<String>,
}

/// `osci:ProcessCardBundle`: message id plus cards and inspection report.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessCardBundle {
    pub message_id: Option<String>,
    pub process_cards: Vec<ProcessCard>,
    pub inspections: Vec<Inspection>,
}

/// One content unit of a container (`osci:Content`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Content {
    pub id: Option<String>,
    /// `href="cid:..."` attachment reference, when present.
    pub href: Option<String>,
    /// Raw (still base64-encoded) inline content text.
    pub base64_content: Option<String>,
}

/// `osci:ContentContainer` (signable unit; signatures come with M6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentContainer {
    pub id: Option<String>,
    pub contents: Vec<Content>,
    pub signed: bool,
}

/// Structural reference to an `xenc:EncryptedData` element (decryption is
/// the crypto layer's job; this records where it sits).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncryptedDataRef {
    pub id: Option<String>,
    pub mime_type: Option<String>,
    /// Inline ciphertext (still base64-encoded).
    pub cipher_value: Option<String>,
    /// Reference to a ciphertext attachment (`cid:...`).
    pub cipher_reference: Option<String>,
}

/// `osci:ContentPackage` of the SOAP body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentPackage {
    pub containers: Vec<ContentContainer>,
    pub encrypted_data: Vec<EncryptedDataRef>,
}

/// `osci2017:ChunkInformation` of partial deliveries. Store side carries
/// the total chunk count and message size; fetch side may carry the
/// number of already-received chunks instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkInformation {
    pub chunk_number: i64,
    pub chunk_size: Option<i64>,
    pub total_chunk_numbers: Option<i64>,
    pub total_message_size: Option<i64>,
    pub received_chunks: Option<i64>,
}

fn parse_chunk_information(element: &Element) -> Option<ChunkInformation> {
    element
        .elements()
        .find(|e| e.local == "ChunkInformation")
        .map(|c| ChunkInformation {
            chunk_number: c
                .attr("ChunkNumber")
                .and_then(|v| v.parse().ok())
                .unwrap_or(-1),
            chunk_size: c.attr("ChunkSize").and_then(|v| v.parse().ok()),
            total_chunk_numbers: c.attr("TotalChunkNumbers").and_then(|v| v.parse().ok()),
            total_message_size: c.attr("TotalMessageSize").and_then(|v| v.parse().ok()),
            received_chunks: c.attr("ReceivedChunks").and_then(|v| v.parse().ok()),
        })
}

/// A parsed OSCI message.
#[derive(Debug, Clone, Default)]
pub struct OsciMessage {
    pub kind: Option<MessageType>,
    /// Entry Id attribute (`#`-referenceable), when present.
    pub entry_id: Option<String>,
    /// Request-entry fields (also used for the echoed request inside
    /// responses).
    pub request: Option<RequestFields>,
    pub feedback: Vec<FeedbackEntry>,
    pub process_card_bundles: Vec<ProcessCardBundle>,
    /// The request echoed inside a response entry.
    pub echoed_request_kind: Option<MessageType>,
    /// Chunk information of partial deliveries (entry or echoed entry).
    pub chunk_information: Option<ChunkInformation>,
    pub body: Option<ContentPackage>,
}

fn child_text(element: &Element, local: &str) -> Option<String> {
    element
        .elements()
        .find(|e| e.local == local)
        .map(|e| e.text())
}

fn descendant_text(element: &Element, local: &str) -> Option<String> {
    if let Some(direct) = child_text(element, local) {
        return Some(direct);
    }
    for child in element.elements() {
        if let Some(found) = descendant_text(child, local) {
            return Some(found);
        }
    }
    None
}

fn parse_request_fields(element: &Element) -> RequestFields {
    RequestFields {
        // fetch deliveries nest the MessageId inside the SelectionRule
        message_id: descendant_text(element, "MessageId"),
        subject: child_text(element, "Subject"),
        selection_rule: element
            .elements()
            .find(|e| e.local == "SelectionRule")
            .cloned(),
        quantity: child_text(element, "Quantity"),
        content_receiver: child_text(element, "ContentReceiver"),
    }
}

fn parse_feedback(entry: &Element) -> Vec<FeedbackEntry> {
    let mut out = Vec::new();
    for feedback in entry.elements().filter(|e| e.local == "Feedback") {
        for e in feedback.elements().filter(|e| e.local == "Entry") {
            out.push(FeedbackEntry {
                language: e.attr("xml:lang").map(str::to_string),
                code: child_text(e, "Code").unwrap_or_default(),
                text: child_text(e, "Text").unwrap_or_default(),
            });
        }
    }
    out
}

fn parse_timestamp(parent: &Element, local: &str) -> Option<DateTime<Utc>> {
    let element = parent.elements().find(|e| e.local == local)?;
    let plain = element
        .elements()
        .find(|e| e.local == "Plain")
        .map(|e| e.text())
        .or_else(|| element.attr("Plain").map(str::to_string))?;
    parse_iso8601(&plain).ok()
}

fn parse_process_card(element: &Element) -> ProcessCard {
    ProcessCard {
        recent_modification: element
            .attr("RecentModification")
            .and_then(|v| parse_iso8601(v).ok()),
        creation: parse_timestamp(element, "Creation"),
        forwarding: parse_timestamp(element, "Forwarding"),
        reception: parse_timestamp(element, "Reception"),
        subject: child_text(element, "Subject"),
    }
}

fn parse_inspection(element: &Element) -> Inspection {
    Inspection {
        timestamp: element
            .elements()
            .find(|e| e.local == "Timestamp")
            .map(|e| child_text(e, "Plain").unwrap_or_else(|| e.text())),
        // Timestamp may nest Plain
        x509_subject_name: child_text(element, "X509SubjectName"),
        x509_issuer_name: child_text(element, "X509IssuerName"),
        x509_serial_number: child_text(element, "X509SerialNumber"),
        cert_type: element
            .elements()
            .find(|e| e.local == "CertType")
            .and_then(|e| e.attr("Type").map(str::to_string)),
        math_result: element
            .elements()
            .find(|e| e.local == "MathResult")
            .and_then(|e| e.attr("Result").map(str::to_string)),
        offline_result: element
            .elements()
            .find(|e| e.local == "OfflineResult")
            .and_then(|e| e.attr("Result").map(str::to_string)),
        online_result: element
            .elements()
            .find(|e| e.local == "OnlineResult")
            .and_then(|e| e.attr("Result").map(str::to_string)),
    }
}

fn parse_process_card_bundles(entry: &Element) -> Vec<ProcessCardBundle> {
    let mut out = Vec::new();
    let is_bundle = |local: &str| {
        local == "ProcessCardBundle"
            || local == "RequestProcessCardBundle"
            || local == "ReplyProcessCardBundle"
    };
    for bundle in entry.elements().filter(|e| is_bundle(&e.local)) {
        let mut parsed = ProcessCardBundle {
            message_id: child_text(bundle, "MessageId"),
            ..Default::default()
        };
        for child in bundle.elements() {
            match child.local.as_str() {
                "ProcessCard" => parsed.process_cards.push(parse_process_card(child)),
                "InspectionReport" => {
                    for inspection in child.elements().filter(|e| e.local == "Inspection") {
                        parsed.inspections.push(parse_inspection(inspection));
                    }
                }
                _ => {}
            }
        }
        out.push(parsed);
    }
    out
}

fn parse_encrypted_data_ref(child: &Element) -> EncryptedDataRef {
    let cipher = child
        .elements()
        .find(|e| e.local == "CipherData")
        .map(|data| {
            let value = child_text(data, "CipherValue");
            let reference = data
                .elements()
                .find(|e| e.local == "CipherReference")
                .and_then(|r| r.attr("URI").map(str::to_string));
            (value, reference)
        })
        .unwrap_or((None, None));
    EncryptedDataRef {
        id: child.id_attr().map(str::to_string),
        mime_type: child.attr("MimeType").map(str::to_string),
        cipher_value: cipher.0,
        cipher_reference: cipher.1,
    }
}

fn parse_content_package(element: &Element) -> ContentPackage {
    let mut package = ContentPackage::default();
    for child in element.elements() {
        match child.local.as_str() {
            "ContentContainer" => {
                let mut container = ContentContainer {
                    id: child.id_attr().map(str::to_string),
                    signed: child.elements().any(|e| e.local == "Signature"),
                    ..Default::default()
                };
                for content in child.elements().filter(|e| e.local == "Content") {
                    container.contents.push(Content {
                        id: content.id_attr().map(str::to_string),
                        href: content.attr("href").map(str::to_string),
                        base64_content: child_text(content, "Base64Content"),
                    });
                }
                package.containers.push(container);
            }
            "EncryptedData" => {
                package.encrypted_data.push(parse_encrypted_data_ref(child));
            }
            _ => {}
        }
    }
    package
}

fn element_uri_with(element: &Element, inherited: &BTreeMap<String, String>) -> Option<String> {
    let mut bindings = inherited.clone();
    for (k, v) in &element.attrs {
        if let Some(p) = k.strip_prefix("xmlns:") {
            bindings.insert(p.to_string(), v.clone());
        } else if k == "xmlns" {
            bindings.insert(String::new(), v.clone());
        }
    }
    bindings.get(&element.prefix).cloned()
}

fn bindings_of(
    element: &Element,
    inherited: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut bindings = inherited.clone();
    for (k, v) in &element.attrs {
        if let Some(p) = k.strip_prefix("xmlns:") {
            bindings.insert(p.to_string(), v.clone());
        } else if k == "xmlns" {
            bindings.insert(String::new(), v.clone());
        }
    }
    bindings
}

/// Parse a message from a document: locates the message entry among the
/// SOAP header children (the single element matching the type table) and
/// reads its fields plus the body content package.
pub fn parse_message(doc: &Document) -> Result<OsciMessage, MessageError> {
    let Some(header) = soap::find_header(doc) else {
        // encrypted transport envelope: the whole message is the body's
        // EncryptedData payload (decrypted and re-parsed in M6)
        let mut message = OsciMessage::default();
        if let Some(package) = parse_body(doc)
            && !package.encrypted_data.is_empty()
        {
            message.body = Some(package);
            return Ok(message);
        }
        return Err(MessageError::NoEnvelope);
    };
    let root_bindings = bindings_of(&doc.root, &BTreeMap::new());
    let header_bindings = bindings_of(header, &root_bindings);

    // message entries are header children for most types, but
    // fetchProcessCard and its response carry the entry in the Body
    let body_element = doc.root.elements().find(|e| {
        e.local == "Body"
            && element_uri_with(e, &root_bindings).as_deref() == Some(SOAP_ENVELOPE_NS)
    });
    let body_bindings = body_element
        .map(|b| bindings_of(b, &root_bindings))
        .unwrap_or_default();

    let mut entry_element: Option<(&Element, MessageType)> = None;
    let candidate_sets = [
        (header.elements().collect::<Vec<_>>(), &header_bindings),
        (
            body_element
                .map(|b| b.elements().collect::<Vec<_>>())
                .unwrap_or_default(),
            &body_bindings,
        ),
    ];
    for (candidates, bindings) in candidate_sets {
        for child in candidates {
            let Some(uri) = element_uri_with(child, bindings) else {
                continue;
            };
            if let Some(kind) = MessageType::from_element(&uri, &child.local) {
                if entry_element.is_some() {
                    return Err(MessageError::MultipleMessageEntries);
                }
                entry_element = Some((child, kind));
            }
        }
    }
    let Some((entry, kind)) = entry_element else {
        return Err(MessageError::NoMessageEntry);
    };

    let mut message = OsciMessage {
        kind: Some(kind),
        entry_id: entry.id_attr().map(str::to_string),
        ..Default::default()
    };

    let entry_bindings = bindings_of(entry, &header_bindings);

    // process card bundles ride on requests (accept/process delivery)
    // and responses alike; responseToMediateDelivery carries the
    // Request/Reply variants
    message.process_card_bundles = parse_process_card_bundles(entry);

    message.chunk_information = parse_chunk_information(entry);

    if kind.is_response() {
        message.feedback = parse_feedback(entry);
        // the echoed request: a nested request-type element inside the
        // response entry (e.g. fetchDelivery inside responseToFetchDelivery)
        for child in entry.elements() {
            let Some(uri) = element_uri_with(child, &entry_bindings) else {
                continue;
            };
            if let Some(nested) = MessageType::from_element(&uri, &child.local)
                && !nested.is_response()
            {
                message.echoed_request_kind = Some(nested);
                message.request = Some(parse_request_fields(child));
                break;
            }
        }
    } else {
        message.request = Some(parse_request_fields(entry));
    }

    // body content package
    message.body = parse_body(doc);

    Ok(message)
}

fn parse_body(doc: &Document) -> Option<ContentPackage> {
    let root_bindings = bindings_of(&doc.root, &BTreeMap::new());
    let body = doc.root.elements().find(|e| {
        e.local == "Body"
            && element_uri_with(e, &root_bindings).as_deref() == Some(SOAP_ENVELOPE_NS)
    })?;
    let mut package = ContentPackage::default();
    let mut found = false;
    for child in body.elements() {
        match child.local.as_str() {
            "ContentPackage" => {
                package = parse_content_package(child);
                found = true;
            }
            "EncryptedData" => {
                // fully encrypted bodies carry the EncryptedData
                // directly under the Body element
                package.encrypted_data.push(parse_encrypted_data_ref(child));
                found = true;
            }
            _ => {}
        }
    }
    found.then_some(package)
}
