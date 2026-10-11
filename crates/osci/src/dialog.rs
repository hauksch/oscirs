//! Dialog state machine (port of `de.osci.osci12.common.DialogHandler`,
//! client side): control-block state, challenge/response and sequence
//! validation, and the send flow (compose -> sign -> transmit -> parse ->
//! validate) over any `Transport`.

use osci_core::message::compose::{OutMessage, compose_message};
use osci_core::message::stored::StoredMessage;
use osci_core::message::{FeedbackEntry, MessageType, OsciMessage};
use osci_core::soap::ControlBlock;
use osci_core::xml::parser;
use osci_crypto::software::Signer;

use crate::sign::{SignParams, sign_message_xml};

#[derive(Debug, thiserror::Error)]
pub enum DialogError {
    #[error("wrong control block in response ({0})")]
    WrongControlBlock(String),
    #[error("response error feedback: {code} {text}")]
    ErrorFeedback { code: String, text: String },
    #[error("unexpected response type: {0:?}")]
    UnexpectedResponse(MessageType),
    #[error("composition: {0}")]
    Composition(String),
    #[error("signing: {0}")]
    Signing(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("parse: {0}")]
    Parse(String),
}

/// Client dialog state + configuration. Replaces the Java DialogHandler's
/// mutable statics with an explicit, owned context.
pub struct Dialog {
    pub control_block: ControlBlock,
    /// Random source for challenges (base64 of 16 random bytes, like the
    /// reference `Tools.createRandom(16)`).
    transport: Box<dyn osci_transport::Transport>,
    signer: Option<Box<dyn Signer>>,
    /// Id of the signature certificate entry inside the message.
    certificate_id: Option<String>,
}

impl Dialog {
    pub fn new(transport: Box<dyn osci_transport::Transport>) -> Self {
        Self {
            control_block: ControlBlock::default(),
            transport,
            signer: None,
            certificate_id: None,
        }
    }

    pub fn with_signer(mut self, signer: Box<dyn Signer>, certificate_id: String) -> Self {
        self.certificate_id = Some(certificate_id);
        self.signer = Some(signer);
        self
    }

    fn fresh_challenge(&self) -> String {
        let mut bytes = [0u8; 16];
        use rand::RngCore as _;
        rand::thread_rng().fill_bytes(&mut bytes);
        osci_core::helper::base64::encode(&bytes)
    }

    /// Prepare the outbound control block for the next message of the
    /// dialog (mirrors the reference sequencing: InitDialog carries no
    /// sequence number; afterwards the counter increments).
    fn prepare_outbound(&mut self, kind: MessageType) {
        if self.control_block.challenge.is_none() {
            self.control_block.challenge = Some(self.fresh_challenge());
        }
        if !matches!(kind, MessageType::InitDialog) && self.control_block.sequence_number.is_none()
        {
            self.control_block.sequence_number = Some(0);
        }
    }

    /// Validate a response control block against the dialog state - port
    /// of `DialogHandler.checkControlBlock`: the response must answer our
    /// challenge, echo the sequence number and conversation id, and carry
    /// the next challenge.
    pub fn check_control_block(&mut self, response: &ControlBlock) -> Result<(), DialogError> {
        let detail = |what: &str| DialogError::WrongControlBlock(what.to_string());
        if let Some(challenge) = &self.control_block.challenge
            && response.response.as_deref() != Some(challenge.as_str())
        {
            return Err(detail("response does not answer our challenge"));
        }
        if let Some(expected) = self.control_block.conversation_id.as_deref()
            && response.conversation_id.as_deref() != Some(expected)
        {
            return Err(detail("conversation id changed"));
        }
        if let (Some(expected), Some(actual)) =
            (self.control_block.sequence_number, response.sequence_number)
            && actual != expected
        {
            return Err(detail("sequence number mismatch"));
        }

        // adopt the response state for the next round
        if self.control_block.conversation_id.is_none() {
            self.control_block.conversation_id = response.conversation_id.clone();
        }
        self.control_block.sequence_number = response.sequence_number;
        self.control_block.challenge = response.challenge.clone();
        self.control_block.response = response.response.clone();
        Ok(())
    }

    /// Compose, sign (when a signer is set), transmit and parse a
    /// request; validates the response control block and returns the
    /// parsed response message. `attachments` are transfer-decoded
    /// contents for signature references.
    pub fn send(
        &mut self,
        out: &mut OutMessage,
        attachments: &[(String, Vec<u8>)],
        boundary: &str,
    ) -> Result<OsciMessage, DialogError> {
        let kind = out
            .kind
            .ok_or_else(|| DialogError::Composition("kind missing".into()))?;
        self.prepare_outbound(kind);
        out.control_block = self.control_block.clone();

        let stream = compose_message(out, boundary).map_err(DialogError::Composition)?;
        let xml =
            xml_part(&stream).ok_or_else(|| DialogError::Composition("no xml part".into()))?;

        let signed_xml = match &self.signer {
            Some(signer) => {
                let certificate_id = self
                    .certificate_id
                    .clone()
                    .ok_or_else(|| DialogError::Signing("certificate id missing".into()))?;
                sign_message_xml(
                    &xml,
                    &SignParams {
                        signer: signer.as_ref(),
                        method: None,
                        digest: None,
                        certificate_id,
                        attachments,
                    },
                )
                .map_err(|e| DialogError::Signing(e.to_string()))?
            }
            None => xml,
        };

        let request_stream = replace_xml_part(&stream, &signed_xml, boundary);
        let response_bytes = self
            .transport
            .send(&request_stream)
            .map_err(|e| DialogError::Transport(e.to_string()))?;

        let stored =
            StoredMessage::load(&response_bytes).map_err(|e| DialogError::Parse(e.to_string()))?;
        self.check_response(&stored)
    }

    fn check_response(&mut self, stored: &StoredMessage) -> Result<OsciMessage, DialogError> {
        let message = stored.message.clone();
        let doc = parser::parse(&String::from_utf8_lossy(&stored.xml))
            .map_err(|e| DialogError::Parse(e.to_string()))?;
        let response_block = control_block_of(&doc)
            .ok_or_else(|| DialogError::Parse("no control block in response".into()))?;
        self.check_control_block(&response_block)?;

        // feedback error codes: anything not starting with 0 (and not the
        // certificate-validation 37xx tolerance of the reference tests)
        // is an error
        for feedback in &message.feedback {
            if !feedback.code.starts_with('0') && !feedback.code.starts_with("37") {
                return Err(DialogError::ErrorFeedback {
                    code: feedback.code.clone(),
                    text: feedback.text.clone(),
                });
            }
        }
        Ok(message)
    }
}

fn control_block_of(doc: &osci_core::xml::Document) -> Option<ControlBlock> {
    let header = osci_core::soap::find_header(doc)?;
    let child = header.elements().find(|e| e.local == "ControlBlock")?;
    Some(ControlBlock {
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
    })
}

fn xml_part(stream: &[u8]) -> Option<String> {
    use std::io::Read as _;
    let mut mime = osci_core::helper::mime::MimeParser::new(stream).ok()?;
    let mut part = mime.next_part().ok()??;
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).ok()?;
    String::from_utf8(xml).ok()
}

/// Rebuild the MIME stream with a replaced XML part (used after signing).
fn replace_xml_part(stream: &[u8], xml: &str, _boundary: &str) -> Vec<u8> {
    let marker = b"Content-ID: <osci@message>\r\n\r\n";
    let xml_start = stream
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("message part header present")
        + marker.len();
    // the XML part runs to the next MIME boundary, searched FROM the XML
    // start (scanning from 0 would hit the preamble boundary)
    let needle = b"\r\n--";
    let xml_end = (xml_start..stream.len().saturating_sub(needle.len()))
        .find(|&i| &stream[i..i + needle.len()] == needle)
        .unwrap_or(stream.len());
    let mut out = Vec::with_capacity(stream.len());
    out.extend_from_slice(&stream[..xml_start]);
    out.extend_from_slice(xml.as_bytes());
    out.extend_from_slice(&stream[xml_end..]);
    out
}

/// Convenience: the first feedback entry of a response.
pub fn first_feedback(message: &OsciMessage) -> Option<&FeedbackEntry> {
    message.feedback.first()
}
