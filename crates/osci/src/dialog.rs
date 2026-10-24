//! Dialog state machine (port of `de.osci.osci12.common.DialogHandler`,
//! client side): control-block state, challenge/response and sequence
//! validation, and the send flow (compose -> sign -> transmit -> parse ->
//! validate) over any `Transport`.

use osci_core::message::compose::{OutContentContainer, OutMessage, compose_message};
use osci_core::message::stored::StoredMessage;
use osci_core::message::{FeedbackEntry, MessageType, OsciMessage};
use osci_core::soap::ControlBlock;
use osci_core::xml::parser;
use osci_crypto::Certificate;
use osci_crypto::software::{Decrypter, RsaDecrypter, Signer};

use crate::security::{StoredMessageLike, VerificationReport, decrypt_transport_message};
use crate::sign::{SignParams, sign_message_xml};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    #[error("verification: {0}")]
    Verification(String),
    #[error("decryption: {0}")]
    Decryption(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("parse: {0}")]
    Parse(String),
}

/// How strictly `Dialog::send` treats the response's transport
/// signature (the intermediary's `SupplierSignature`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SignaturePolicy {
    /// Do not verify response signatures.
    Ignore,
    /// Verify signatures when present and fail on invalid ones;
    /// unsigned responses are accepted (default, interoperable).
    #[default]
    VerifyIfPresent,
    /// Require at least one valid signature; unsigned responses are
    /// rejected.
    Require,
}

/// Client dialog state + configuration. Replaces the Java DialogHandler's
/// mutable statics with an explicit, owned context.
pub struct Dialog {
    pub control_block: ControlBlock,
    transport: Box<dyn osci_transport::Transport>,
    signer: Option<Box<dyn Signer>>,
    /// Id of the signature certificate entry inside the message.
    certificate_id: Option<String>,
    /// Optional transport-level encryption toward the intermediary: the
    /// signed stream is wrapped into a SOAPMessageEncrypted envelope as
    /// the last step before sending.
    transport_encryption: Option<TransportEncryption>,
    /// Keys for unwrapping transport-encrypted responses.
    response_decrypters: Vec<RsaDecrypter>,
    /// Signature-verification policy for responses.
    signature_policy: SignaturePolicy,
    /// Verification report of the last response (when the policy
    /// verifies).
    last_response_report: Option<VerificationReport>,
}

/// One content-encryption request for [`Dialog::send_encrypted`].
pub struct ContentEncryption<'a> {
    pub inner: OutContentContainer,
    pub recipients: &'a [crate::security::EncRecipient],
    pub config: crate::security::EncryptConfig,
}

/// Transport-encryption configuration (the intermediary's cipher cert).
#[derive(Debug, Clone)]
pub struct TransportEncryption {
    pub recipient_cert: Certificate,
    pub config: crate::security::EncryptConfig,
}

impl Dialog {
    pub fn new(transport: Box<dyn osci_transport::Transport>) -> Self {
        Self {
            control_block: ControlBlock::default(),
            transport,
            transport_encryption: None,
            signer: None,
            certificate_id: None,
            response_decrypters: Vec::new(),
            signature_policy: SignaturePolicy::default(),
            last_response_report: None,
        }
    }

    pub fn with_signer(mut self, signer: Box<dyn Signer>, certificate_id: String) -> Self {
        self.certificate_id = Some(certificate_id);
        self.signer = Some(signer);
        self
    }

    /// Enable transport-level encryption toward the intermediary: the
    /// signed MIME stream is wrapped into a SOAPMessageEncrypted envelope
    /// as the last step of [`Dialog::send`].
    pub fn with_transport_encryption(
        mut self,
        recipient_cert: Certificate,
        config: crate::security::EncryptConfig,
    ) -> Self {
        self.transport_encryption = Some(TransportEncryption {
            recipient_cert,
            config,
        });
        self
    }

    /// Keys for opening transport-encrypted responses (the client's own
    /// cipher certificates): when a response arrives as a
    /// SOAPMessageEncrypted envelope, `send` unwraps it before parsing.
    pub fn with_response_decrypters(mut self, decrypters: Vec<RsaDecrypter>) -> Self {
        self.response_decrypters = decrypters;
        self
    }

    /// Set how strictly the response's transport signature is verified
    /// (default [`SignaturePolicy::VerifyIfPresent`]).
    pub fn set_signature_policy(&mut self, policy: SignaturePolicy) -> &mut Self {
        self.signature_policy = policy;
        self
    }

    /// The verification report of the last response, when the signature
    /// policy verified it. Each [`crate::SignatureResult`] also carries
    /// the weak-key/algorithm verdicts.
    pub fn last_response_report(&self) -> Option<&VerificationReport> {
        self.last_response_report.as_ref()
    }

    /// Convenience: encrypt `request.inner` for the given recipients
    /// (content encryption, composed into the message body before
    /// signing), then [`Dialog::send`].
    pub fn send_encrypted(
        &mut self,
        out: &mut OutMessage,
        request: ContentEncryption<'_>,
        attachments: &[(String, Vec<u8>)],
        boundary: &str,
    ) -> Result<OsciMessage, DialogError> {
        // encdata_N convention: index within this message
        let enc_id = Some(format!("encdata_{}", out.encrypted_data.len()));
        let encrypted = crate::security::encrypt_container(
            &request.inner,
            request.recipients,
            &request.config,
            enc_id,
            None,
        )
        .map_err(|e| DialogError::Composition(e.to_string()))?;
        out.encrypted_data.push(encrypted);
        self.send(out, attachments, boundary)
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
        if !matches!(kind, MessageType::InitDialog)
            && osci_core::message::compose::control_block_allows_sequence(kind)
            && self.control_block.sequence_number.is_none()
        {
            self.control_block.sequence_number = Some(0);
        }
    }

    /// The dialog state as the outbound control block of `kind`: fields
    /// the kind's ControlBlock schema prohibits are masked out of the
    /// copy (the dialog state itself is kept for the following rounds).
    fn outbound_block(&self, kind: MessageType) -> ControlBlock {
        let mut block = self.control_block.clone();
        if !osci_core::message::compose::control_block_allows_conversation(kind) {
            block.conversation_id = None;
        }
        if !osci_core::message::compose::control_block_allows_sequence(kind) {
            block.sequence_number = None;
        }
        block
    }

    /// Validate a response control block against the dialog state - port
    /// of `DialogHandler.checkControlBlock`: the response must answer our
    /// challenge, echo the sequence number and conversation id, and carry
    /// the next challenge.
    pub fn check_control_block(&mut self, response: &ControlBlock) -> Result<(), DialogError> {
        let detail = |what: &str| DialogError::WrongControlBlock(what.to_string());
        // The adopted values are composed into the next (signed) request -
        // reject anything that is not well-formed protocol data before it
        // gets there, in addition to the composer-side escaping.
        let well_formed = |value: &str| {
            value.len() <= 256
                && value
                    .chars()
                    .all(|c| c.is_ascii_graphic() && !matches!(c, '"' | '<' | '>' | '&'))
        };
        for (what, value) in [
            ("challenge", &response.challenge),
            ("response", &response.response),
        ] {
            if let Some(value) = value
                && !well_formed(value)
            {
                return Err(detail(&format!("malformed {what} in response")));
            }
        }
        // the schema types ConversationId as osci:Number (\d+); a
        // non-numeric value would make the next signed request
        // schema-invalid, so reject it at adoption time
        if let Some(value) = &response.conversation_id
            && !value.chars().all(|c| c.is_ascii_digit())
        {
            return Err(detail("malformed conversation id in response"));
        }
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
        let request_stream = self.compose_signed_stream(out, attachments, boundary)?;

        let response_bytes = self
            .transport
            .send(&request_stream)
            .map_err(|e| DialogError::Transport(e.to_string()))?;

        let stored =
            StoredMessage::load(&response_bytes).map_err(|e| DialogError::Parse(e.to_string()))?;
        // a transport-encrypted response must be unwrapped before the
        // control block is reachable
        let stored = match self.transport_envelope(&stored)? {
            Some(inner) => {
                StoredMessage::load(&inner).map_err(|e| DialogError::Parse(e.to_string()))?
            }
            None => stored,
        };
        self.check_response(&stored)
    }

    /// Everything [`Dialog::send`] does up to (excluding) the
    /// transport send: prepare the control block, compose, sign
    /// (when a signer is set) and apply transport-level encryption.
    /// The dialog state advances exactly once, like a normal send.
    ///
    /// This is the seam for EFFI message chunking (issue #4): the
    /// returned stream of the full delivery is what gets split into
    /// chunk blobs - build one [`OutMessage`] per chunk (a
    /// PartialStoreDelivery carrying the blob as its single attachment)
    /// and ship each through [`Dialog::send`]. Do not `send` the same
    /// `OutMessage` afterwards; its control block was already adopted.
    pub fn compose_signed_stream(
        &mut self,
        out: &mut OutMessage,
        attachments: &[(String, Vec<u8>)],
        boundary: &str,
    ) -> Result<Vec<u8>, DialogError> {
        let kind = out
            .kind
            .ok_or_else(|| DialogError::Composition("kind missing".into()))?;
        self.prepare_outbound(kind);
        out.control_block = self.outbound_block(kind);

        let stream =
            compose_message(out, boundary).map_err(|e| DialogError::Composition(e.to_string()))?;
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
                        header_element: Some(osci_core::message::compose::signature_header_name(
                            kind,
                        )),
                    },
                )
                .map_err(|e| DialogError::Signing(e.to_string()))?
            }
            None => xml,
        };

        let request_stream = replace_xml_part(&stream, &signed_xml)
            .map_err(|e| DialogError::Composition(e.to_string()))?;

        // transport-level encryption wraps the signed stream last
        match &self.transport_encryption {
            Some(te) => crate::security::encrypt_message_for(
                &request_stream,
                &te.recipient_cert,
                &te.config,
                boundary,
            )
            .map_err(|e| DialogError::Composition(e.to_string())),
            None => Ok(request_stream),
        }
    }

    /// When the stored message is a SOAPMessageEncrypted transport
    /// envelope, decrypt it with the configured response decrypters and
    /// return the inner MIME stream.
    fn transport_envelope(&self, stored: &StoredMessage) -> Result<Option<Vec<u8>>, DialogError> {
        let doc = parser::parse(&String::from_utf8_lossy(&stored.xml))
            .map_err(|e| DialogError::Parse(e.to_string()))?;
        let is_envelope = osci_core::soap::find_header(&doc).is_none_or(|header| {
            // envelope: no control block, the body is the EncryptedData
            let body = doc.root.elements().find(|e| e.local == "Body");
            body.is_some_and(|body| body.elements().any(|e| e.local == "EncryptedData"))
                && header.elements().all(|e| e.local != "ControlBlock")
        });
        if !is_envelope {
            return Ok(None);
        }
        if self.response_decrypters.is_empty() {
            return Err(DialogError::Decryption(
                "transport-encrypted response but no response decrypters configured".into(),
            ));
        }
        let view = StoredMessageLike {
            xml: &stored.xml,
            attachments: &stored.attachments,
        };
        let refs: Vec<&dyn Decrypter> = self
            .response_decrypters
            .iter()
            .map(|d| d as &dyn Decrypter)
            .collect();
        decrypt_transport_message(&view, &refs)
            .map(Some)
            .map_err(|e| DialogError::Decryption(e.to_string()))
    }

    fn check_response(&mut self, stored: &StoredMessage) -> Result<OsciMessage, DialogError> {
        let message = stored.message.clone();
        let doc = parser::parse(&String::from_utf8_lossy(&stored.xml))
            .map_err(|e| DialogError::Parse(e.to_string()))?;
        let response_block = control_block_of(&doc)
            .ok_or_else(|| DialogError::Parse("no control block in response".into()))?;
        self.check_control_block(&response_block)?;
        self.check_response_signatures(stored)?;

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

    /// Apply the signature policy to the response and record the report.
    fn check_response_signatures(&mut self, stored: &StoredMessage) -> Result<(), DialogError> {
        let attachments: Vec<(String, Vec<u8>)> = stored
            .attachments
            .iter()
            .map(|a| (a.content_id.clone(), a.data.clone()))
            .collect();
        let verified = match crate::security::verify_message(
            &String::from_utf8_lossy(&stored.xml),
            &attachments,
        ) {
            Ok(report) => Some(report),
            // policy-relevant distinction: no signature element at all
            Err(crate::security::SecurityError::NoSignatures) => None,
            Err(e) => {
                return Err(DialogError::Verification(e.to_string()));
            }
        };
        match (self.signature_policy, verified) {
            (_, Some(report)) => {
                if !report.all_valid() {
                    return Err(DialogError::Verification(format!(
                        "invalid response signature: {report:?}"
                    )));
                }
                if self.signature_policy == SignaturePolicy::Require && report.signatures.is_empty()
                {
                    return Err(DialogError::Verification(
                        "policy requires a response signature".into(),
                    ));
                }
                self.last_response_report = Some(report);
            }
            (SignaturePolicy::Require, None) => {
                return Err(DialogError::Verification(
                    "policy requires a response signature".into(),
                ));
            }
            (_, None) => {
                self.last_response_report = None;
            }
        }
        Ok(())
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
fn replace_xml_part(stream: &[u8], xml: &str) -> Result<Vec<u8>, DialogError> {
    let marker = format!(
        "Content-ID: <{}>\r\n\r\n",
        osci_core::message::compose::MESSAGE_CONTENT_ID
    );
    let marker = marker.as_bytes();
    let xml_start = stream
        .windows(marker.len())
        .position(|w| w == marker)
        .ok_or_else(|| DialogError::Composition("message part header missing".into()))?
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
    Ok(out)
}

/// Convenience: the first feedback entry of a response.
pub fn first_feedback(message: &OsciMessage) -> Option<&FeedbackEntry> {
    message.feedback.first()
}
