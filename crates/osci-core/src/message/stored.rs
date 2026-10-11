//! Stored messages and the passive-recipient side
//! (port of `messagetypes.StoredMessage`, `PassiveRecipientParser` and
//! `extinterfaces.DialogFinder`): load/store of full message streams and
//! correlation of incoming requests to dialogs by conversation id.

use std::collections::HashMap;
use std::io::Read;

use crate::helper::mime::MimeParser;
use crate::xml::parser;

use super::{MessageError, MessageType, OsciMessage, compose, parse_message};

/// One attachment of a loaded message: transfer-decoded content plus its
/// part metadata.
#[derive(Debug, Clone, Default)]
pub struct LoadedAttachment {
    pub content_id: String,
    pub content_type: String,
    pub encoding: Option<String>,
    pub data: Vec<u8>,
}

/// A complete message loaded from its wire format.
#[derive(Debug, Clone, Default)]
pub struct StoredMessage {
    pub message: OsciMessage,
    /// XML part bytes (for re-serialization and signature walks).
    pub xml: Vec<u8>,
    pub attachments: Vec<LoadedAttachment>,
}

impl StoredMessage {
    /// Load and parse a message from its full MIME stream (or bare XML
    /// part, detected by the leading `<?xml`).
    pub fn load(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.starts_with(b"<?xml") {
            return Self::load_xml(bytes);
        }
        let mut mime =
            MimeParser::new(bytes).map_err(|e| MessageError::Invalid(format!("MIME: {e}")))?;
        let mut xml = Vec::new();
        let mut attachments = Vec::new();
        while let Some(mut part) = mime
            .next_part()
            .map_err(|e| MessageError::Invalid(format!("MIME part: {e}")))?
        {
            if part.content_id() == "osci@message" {
                part.read_to_end(&mut xml)
                    .map_err(|e| MessageError::Invalid(format!("part read: {e}")))?;
            } else {
                let mut raw = Vec::new();
                // keep the transfer-encoded form: the reference library
                // hands attachments over as streams, decoding on demand
                part.read_to_end(&mut raw)
                    .map_err(|e| MessageError::Invalid(format!("part read: {e}")))?;
                let data = if part.encoding() == Some("base64") {
                    crate::helper::base64::decode(&String::from_utf8_lossy(&raw))
                        .map_err(|e| MessageError::Invalid(format!("attachment base64: {e}")))?
                } else {
                    raw
                };
                attachments.push(LoadedAttachment {
                    content_id: part.content_id().to_string(),
                    content_type: part.content_type().to_string(),
                    encoding: part.encoding().map(str::to_string),
                    data,
                });
            }
        }
        if xml.is_empty() {
            return Err(MessageError::Invalid("no osci@message part".into()));
        }
        let message = Self::parse_xml_part(&xml)?;
        Ok(Self {
            message,
            xml,
            attachments,
        })
    }

    fn load_xml(bytes: &[u8]) -> Result<Self, MessageError> {
        let message = Self::parse_xml_part(bytes)?;
        Ok(Self {
            message,
            xml: bytes.to_vec(),
            attachments: Vec::new(),
        })
    }

    fn parse_xml_part(xml: &[u8]) -> Result<OsciMessage, MessageError> {
        let text =
            std::str::from_utf8(xml).map_err(|e| MessageError::Invalid(format!("utf-8: {e}")))?;
        let doc = parser::parse(text).map_err(|e| MessageError::Invalid(e.to_string()))?;
        parse_message(&doc)
    }

    /// Compose a message to its full MIME stream.
    pub fn store(out: &compose::OutMessage, boundary: &str) -> Result<Vec<u8>, String> {
        compose::compose_message(out, boundary)
    }

    /// Attachment content by content id (without `cid:` scheme).
    pub fn attachment(&self, content_id: &str) -> Option<&LoadedAttachment> {
        self.attachments.iter().find(|a| a.content_id == content_id)
    }
}

/// Correlates incoming passive-recipient requests to established dialogs
/// by conversation id (port of `extinterfaces.DialogFinder`).
#[derive(Debug, Default)]
pub struct DialogFinder {
    dialogs: HashMap<String, ControlBlockState>,
}

/// The dialog-correlation state extracted from a control block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlBlockState {
    pub conversation_id: String,
    pub sequence_number: Option<u32>,
    pub last_challenge: Option<String>,
}

impl DialogFinder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a dialog (from an InitDialog exchange or configuration).
    pub fn register(&mut self, state: ControlBlockState) {
        self.dialogs.insert(state.conversation_id.clone(), state);
    }

    /// Find the dialog for a conversation id.
    pub fn find(&self, conversation_id: &str) -> Option<&ControlBlockState> {
        self.dialogs.get(conversation_id)
    }

    /// Parse and correlate a raw incoming request (the passive recipient
    /// entry point, mirroring `PassiveRecipientParser.parseStream`).
    pub fn accept(
        &self,
        bytes: &[u8],
    ) -> Result<(StoredMessage, Option<&ControlBlockState>), MessageError> {
        let stored = StoredMessage::load(bytes)?;
        let conversation = stored.message.control_block_conversation_id(&stored.xml)?;
        let dialog = conversation.as_deref().and_then(|id| self.dialogs.get(id));
        Ok((stored, dialog))
    }
}

impl OsciMessage {
    /// Conversation id of the message's control block (parsed from the
    /// XML part bytes).
    pub fn control_block_conversation_id_public(
        &self,
        xml: &[u8],
    ) -> Result<Option<String>, MessageError> {
        self.control_block_conversation_id(xml)
    }

    fn control_block_conversation_id(&self, xml: &[u8]) -> Result<Option<String>, MessageError> {
        let text =
            std::str::from_utf8(xml).map_err(|e| MessageError::Invalid(format!("utf-8: {e}")))?;
        let doc = parser::parse(text).map_err(|e| MessageError::Invalid(e.to_string()))?;
        let header = crate::soap::find_header(&doc).ok_or(MessageError::NoEnvelope)?;
        for child in header.elements() {
            if child.local == "ControlBlock" {
                return Ok(child.attr("ConversationId").map(str::to_string));
            }
        }
        Ok(None)
    }
}

/// Whether the message type is one a passive recipient backend receives
/// (`AcceptDelivery`, `ProcessDelivery`, `StoreDelivery`-addressed or
/// `PartialStoreDelivery`).
pub fn is_passive_recipient_request(kind: MessageType) -> bool {
    matches!(
        kind,
        MessageType::AcceptDelivery | MessageType::ProcessDelivery
    )
}
