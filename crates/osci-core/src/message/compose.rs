//! Message composition (port of the `OSCIMessage.writeXML` /
//! `MessagePartsFactory` write path): builds the MIME/OSCI wire format
//! from message models, using the Java library's part order:
//! ControlBlock, (signature - M6), DesiredLanguages, quality timestamps,
//! message entry, NonIntermediaryCertificates, FeatureDescription,
//! custom headers, Body, attachments.

use crate::helper::base64;
use crate::soap::{
    CertRole, CertUse, Composer as HeaderComposer, ControlBlock, FeatureDescription, NS_BLOCK,
    ns_block_2017,
};
use crate::xml::writer::{XmlWriter, escape_text};
use osci_crypto::algorithms::SymCipher;

use super::{ChunkInformation, MessageType};

pub const MIME_BOUNDARY_PREFIX: &str = "MIME_boundary";
pub const MESSAGE_CONTENT_ID: &str = "osci@message";

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ComposeError {
    #[error("message kind missing or unsupported: {0}")]
    Kind(String),
    #[error("required value missing: {0}")]
    Missing(String),
    #[error("schema violation: {0}")]
    Schema(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------
// Per-kind wire shape (issue #3: "the schemas are the contract"). The
// tables mirror the normative soap*.xsd / *.xsd content models of the
// vendored corpus (Korrigenda 1-10); compose enforces them so illegal
// header shapes are compose errors instead of wire-level surprises at
// the intermediary's validator.

/// One allowed NonIntermediaryCertificates child slot: (use, role,
/// minOccurs, maxOccurs) - `u32::MAX` = unbounded.
type CertSlot = (CertUse, CertRole, u32, u32);

/// The unrestricted NonIntermediaryCertificatesTemplate child sequence
/// (order.xsd): cipher originator -> cipher other authors -> cipher
/// addressee -> cipher other readers -> signature originator -> signature
/// other authors -> signature addressee (added by KORR1 last).
const NIC_TEMPLATE: &[CertSlot] = &[
    (CertUse::Cipher, CertRole::Originator, 0, 1),
    (CertUse::Cipher, CertRole::OtherAuthor, 0, u32::MAX),
    (CertUse::Cipher, CertRole::Addressee, 0, 1),
    (CertUse::Cipher, CertRole::OtherReader, 0, u32::MAX),
    (CertUse::Signature, CertRole::Originator, 0, 1),
    (CertUse::Signature, CertRole::OtherAuthor, 0, u32::MAX),
    (CertUse::Signature, CertRole::Addressee, 0, 1),
];

/// Allowed NonIntermediaryCertificates children per message kind
/// (`None` = the kind's soap schema has no NonIntermediaryCertificates
/// element at all).
fn nic_model(kind: MessageType) -> Option<&'static [CertSlot]> {
    Some(match kind {
        MessageType::InitDialog => &[
            (CertUse::Cipher, CertRole::Originator, 1, 1),
            (CertUse::Signature, CertRole::Originator, 0, 1),
        ][..],
        MessageType::ExitDialog | MessageType::FetchDelivery | MessageType::FetchProcessCard => {
            &[(CertUse::Signature, CertRole::Originator, 0, 1)][..]
        }
        MessageType::GetMessageId => &[
            (CertUse::Cipher, CertRole::Originator, 0, 1),
            (CertUse::Signature, CertRole::Originator, 0, 1),
        ][..],
        MessageType::StoreDelivery => &[
            (CertUse::Cipher, CertRole::Originator, 0, 1),
            (CertUse::Cipher, CertRole::OtherAuthor, 0, u32::MAX),
            (CertUse::Cipher, CertRole::Addressee, 1, 1),
            (CertUse::Cipher, CertRole::OtherReader, 0, u32::MAX),
            (CertUse::Signature, CertRole::Originator, 0, 1),
            (CertUse::Signature, CertRole::OtherAuthor, 0, u32::MAX),
        ][..],
        MessageType::ResponseToAcceptDelivery => {
            &[(CertUse::Signature, CertRole::Addressee, 0, 1)][..]
        }
        // full template via xsd:extension (no restriction): delivery
        // types and their process-delivery responses
        MessageType::AcceptDelivery
        | MessageType::ProcessDelivery
        | MessageType::ForwardDelivery
        | MessageType::MediateDelivery
        | MessageType::ResponseToFetchDelivery
        | MessageType::ResponseToMediateDelivery
        | MessageType::ResponseToProcessDelivery => NIC_TEMPLATE,
        // the 2017 partial messages import the osci types through the
        // OldNS schemas, which pull in the sibling delivery schemas:
        // PartialStoreDelivery inherits StoreDelivery's restriction
        // (addressee cipher required), PartialFetchDelivery FetchDelivery's
        MessageType::PartialStoreDelivery => &[
            (CertUse::Cipher, CertRole::Originator, 0, 1),
            (CertUse::Cipher, CertRole::OtherAuthor, 0, u32::MAX),
            (CertUse::Cipher, CertRole::Addressee, 1, 1),
            (CertUse::Cipher, CertRole::OtherReader, 0, u32::MAX),
            (CertUse::Signature, CertRole::Originator, 0, 1),
            (CertUse::Signature, CertRole::OtherAuthor, 0, u32::MAX),
        ][..],
        MessageType::PartialFetchDelivery => {
            &[(CertUse::Signature, CertRole::Originator, 0, 1)][..]
        }
        // the response schemas of the dialog lifecycle and of
        // store/forward/partial-store deliveries have no
        // NonIntermediaryCertificates element
        MessageType::ResponseToInitDialog
        | MessageType::ResponseToExitDialog
        | MessageType::ResponseToGetMessageId
        | MessageType::ResponseToFetchProcessCard
        | MessageType::ResponseToStoreDelivery
        | MessageType::ResponseToForwardDelivery
        | MessageType::ResponseToPartialStoreDelivery
        | MessageType::ResponseToPartialFetchDelivery => return None,
    })
}

/// Message kinds whose soap schema requires the
/// NonIntermediaryCertificates element (minOccurs=1).
fn nic_required(kind: MessageType) -> bool {
    matches!(
        kind,
        MessageType::InitDialog | MessageType::StoreDelivery | MessageType::PartialStoreDelivery
    )
}

/// Message kinds whose soap schema requires a ContentPackage in the Body
/// (minOccurs=1): the deliveries. Entry-in-body types carry the entry
/// element instead; responses may have an empty Body.
fn body_requires_content_package(kind: MessageType) -> bool {
    matches!(
        kind,
        MessageType::StoreDelivery
            | MessageType::AcceptDelivery
            | MessageType::ProcessDelivery
            | MessageType::ForwardDelivery
            | MessageType::MediateDelivery
            | MessageType::PartialStoreDelivery
    )
}

/// QualityOfTimestamp cardinality per kind.
enum QotModel {
    /// No QualityOfTimestamp slot in the schema.
    Forbidden,
    /// Exactly creation + reception (StoreDelivery, ForwardDelivery);
    /// Java composes both unconditionally (plain when unset).
    TwoRequired,
    /// Exactly the creation stamp (PartialStoreDelivery).
    CreationRequired,
    /// Zero, one or both (MediateDelivery, ResponseToProcessDelivery).
    OptionalTwo,
}

fn qot_model(kind: MessageType) -> QotModel {
    match kind {
        MessageType::StoreDelivery | MessageType::ForwardDelivery => QotModel::TwoRequired,
        MessageType::PartialStoreDelivery => QotModel::CreationRequired,
        MessageType::MediateDelivery | MessageType::ResponseToProcessDelivery => {
            QotModel::OptionalTwo
        }
        _ => QotModel::Forbidden,
    }
}

/// The SOAP signature header element of a kind: requests carry
/// `osci:ClientSignature`, responses `osci:SupplierSignature` (the
/// soapResponseTo*.xsd slot).
pub fn signature_header_name(kind: MessageType) -> &'static str {
    if kind.is_response() {
        "SupplierSignature"
    } else {
        "ClientSignature"
    }
}

/// Attribute use of a ControlBlock field in a kind's ControlBlockType
/// restriction (`use="prohibited" | "optional" | "required"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttrUse {
    Prohibited,
    Optional,
    Required,
}

/// ControlBlock shape per kind, from the ControlBlockType restrictions
/// of the message schemas (2017 partial messages inherit the
/// unrestricted ControlBlockTemplate).
struct ControlBlockModel {
    response_allowed: bool,
    response_required: bool,
    challenge_allowed: bool,
    challenge_required: bool,
    conversation_id: AttrUse,
    sequence_number: AttrUse,
}

fn control_block_model(kind: MessageType) -> ControlBlockModel {
    use AttrUse::{Optional, Prohibited, Required};
    match kind {
        // dialog setup: no conversation, no sequence, no response
        MessageType::InitDialog => ControlBlockModel {
            response_allowed: false,
            response_required: false,
            challenge_allowed: true,
            challenge_required: true,
            conversation_id: Prohibited,
            sequence_number: Prohibited,
        },
        // store-like requests: conversation optional, sequence required
        MessageType::GetMessageId | MessageType::ForwardDelivery | MessageType::StoreDelivery => {
            ControlBlockModel {
                response_allowed: true,
                response_required: false,
                challenge_allowed: true,
                challenge_required: true,
                conversation_id: Optional,
                sequence_number: Required,
            }
        }
        // dialog-bound requests: everything required
        MessageType::ExitDialog
        | MessageType::FetchDelivery
        | MessageType::FetchProcessCard
        | MessageType::MediateDelivery => ControlBlockModel {
            response_allowed: true,
            response_required: true,
            challenge_allowed: true,
            challenge_required: true,
            conversation_id: Required,
            sequence_number: Required,
        },
        // accept/process requests carry no dialog attributes
        MessageType::AcceptDelivery | MessageType::ProcessDelivery => ControlBlockModel {
            response_allowed: true,
            response_required: false,
            challenge_allowed: true,
            challenge_required: true,
            conversation_id: Prohibited,
            sequence_number: Prohibited,
        },
        // responses always answer our challenge (Response required);
        // the next Challenge is mandatory on the accept/process and
        // dialog-exit/init families, optional elsewhere
        MessageType::ResponseToInitDialog => ControlBlockModel {
            response_allowed: true,
            response_required: true,
            challenge_allowed: true,
            challenge_required: true,
            conversation_id: Required,
            sequence_number: Prohibited,
        },
        MessageType::ResponseToGetMessageId | MessageType::ResponseToStoreDelivery => {
            ControlBlockModel {
                response_allowed: true,
                response_required: true,
                challenge_allowed: true,
                challenge_required: false,
                conversation_id: Required,
                sequence_number: Required,
            }
        }
        MessageType::ResponseToExitDialog => ControlBlockModel {
            response_allowed: true,
            response_required: true,
            challenge_allowed: true,
            challenge_required: true,
            conversation_id: Required,
            sequence_number: Required,
        },
        MessageType::ResponseToFetchDelivery
        | MessageType::ResponseToFetchProcessCard
        | MessageType::ResponseToMediateDelivery => ControlBlockModel {
            response_allowed: true,
            response_required: true,
            challenge_allowed: true,
            challenge_required: true,
            conversation_id: Required,
            sequence_number: Required,
        },
        MessageType::ResponseToAcceptDelivery | MessageType::ResponseToProcessDelivery => {
            ControlBlockModel {
                response_allowed: true,
                response_required: true,
                challenge_allowed: true,
                challenge_required: true,
                conversation_id: Prohibited,
                sequence_number: Prohibited,
            }
        }
        MessageType::ResponseToForwardDelivery => ControlBlockModel {
            response_allowed: true,
            response_required: true,
            challenge_allowed: true,
            challenge_required: false,
            conversation_id: Optional,
            sequence_number: Optional,
        },
        // 2017 partial messages: unrestricted ControlBlockTemplate
        MessageType::PartialStoreDelivery
        | MessageType::PartialFetchDelivery
        | MessageType::ResponseToPartialStoreDelivery
        | MessageType::ResponseToPartialFetchDelivery => ControlBlockModel {
            response_allowed: true,
            response_required: false,
            challenge_allowed: true,
            challenge_required: false,
            conversation_id: Optional,
            sequence_number: Optional,
        },
    }
}

/// Whether the kind's ControlBlock schema restriction allows a
/// ConversationId / SequenceNumber attribute (false = `use="prohibited"`).
pub fn control_block_allows_conversation(kind: MessageType) -> bool {
    control_block_model(kind).conversation_id != AttrUse::Prohibited
}

pub fn control_block_allows_sequence(kind: MessageType) -> bool {
    control_block_model(kind).sequence_number != AttrUse::Prohibited
}

/// ChunkInformation attribute rules per kind (the ChunkInformationType
/// restrictions of the four 2017 partial schemas; `None` = the kind has
/// no ChunkInformation slot at all).
struct ChunkModel {
    chunk_size: AttrUse,
    received_chunks: AttrUse,
    total_chunk_numbers: AttrUse,
    total_message_size: AttrUse,
}

fn chunk_model(kind: MessageType) -> Option<ChunkModel> {
    use AttrUse::{Optional, Prohibited, Required};
    Some(match kind {
        MessageType::PartialStoreDelivery => ChunkModel {
            chunk_size: Required,
            received_chunks: Prohibited,
            total_chunk_numbers: Required,
            total_message_size: Required,
        },
        MessageType::PartialFetchDelivery => ChunkModel {
            chunk_size: Required,
            received_chunks: Required,
            total_chunk_numbers: Prohibited,
            total_message_size: Prohibited,
        },
        MessageType::ResponseToPartialFetchDelivery => ChunkModel {
            chunk_size: Prohibited,
            received_chunks: Prohibited,
            total_chunk_numbers: Optional,
            total_message_size: Optional,
        },
        MessageType::ResponseToPartialStoreDelivery => ChunkModel {
            chunk_size: Prohibited,
            received_chunks: Required,
            total_chunk_numbers: Optional,
            total_message_size: Prohibited,
        },
        _ => return None,
    })
}

/// Validate the chunk information against the kind's schema shape.
fn check_chunk_shape(kind: MessageType, chunk: &ChunkInformation) -> Result<(), ComposeError> {
    let Some(model) = chunk_model(kind) else {
        return Err(ComposeError::Schema(format!(
            "{kind:?} does not allow ChunkInformation"
        )));
    };
    let schema = |what: &str| ComposeError::Schema(format!("{kind:?}: {what}"));
    let check = |value: Option<i64>, use_: AttrUse, what: &str| match (value, use_) {
        (Some(_), AttrUse::Prohibited) => {
            Err(schema(&format!("ChunkInformation does not allow {what}")))
        }
        (None, AttrUse::Required) => Err(schema(&format!("ChunkInformation requires {what}"))),
        _ => Ok(()),
    };
    check(chunk.chunk_size, model.chunk_size, "ChunkSize")?;
    // ReceivedChunks is always written (-1 when the list is empty), so
    // only the prohibition of actual chunk numbers can be violated
    if !chunk.received_chunks.is_empty() && model.received_chunks == AttrUse::Prohibited {
        return Err(schema("ChunkInformation does not allow ReceivedChunks"));
    }
    check(
        chunk.total_chunk_numbers,
        model.total_chunk_numbers,
        "TotalChunkNumbers",
    )?;
    check(
        chunk.total_message_size,
        model.total_message_size,
        "TotalMessageSize",
    )?;
    Ok(())
}

/// Validate the outbound control block against the kind's schema shape
/// (issue #3); the ConversationId is an `osci:Number` (`\d+`).
fn check_control_block_shape(kind: MessageType, block: &ControlBlock) -> Result<(), ComposeError> {
    let model = control_block_model(kind);
    let schema = |what: &str| ComposeError::Schema(format!("{kind:?}: {what}"));
    if block.response.is_some() && !model.response_allowed {
        return Err(schema("ControlBlock does not allow Response"));
    }
    if model.response_required && block.response.is_none() {
        return Err(schema("ControlBlock requires Response"));
    }
    if block.challenge.is_some() && !model.challenge_allowed {
        return Err(schema("ControlBlock does not allow Challenge"));
    }
    if model.challenge_required && block.challenge.is_none() {
        return Err(schema("ControlBlock requires Challenge"));
    }
    let number = |value: &str, what: &str| {
        if !value.chars().all(|c| c.is_ascii_digit()) {
            Err(schema(&format!("{what} must be a number, got \"{value}\"")))
        } else {
            Ok(())
        }
    };
    let check = |value: &Option<String>, use_: AttrUse, what: &str| match (value, use_) {
        (Some(_), AttrUse::Prohibited) => {
            Err(schema(&format!("ControlBlock does not allow {what}")))
        }
        (Some(v), _) => number(v, what),
        (None, AttrUse::Required) => Err(schema(&format!("ControlBlock requires {what}"))),
        (None, _) => Ok(()),
    };
    check(
        &block.conversation_id,
        model.conversation_id,
        "ConversationId",
    )?;
    check(
        &block.sequence_number.map(|s| s.to_string()),
        model.sequence_number,
        "SequenceNumber",
    )?;
    Ok(())
}

/// Validate the outbound certificate entries against a kind's NIC model
/// and return them in the canonical schema sequence (stable within a
/// slot, so multiple OtherAuthor/OtherReader entries keep their order).
fn canonically_ordered_nic(
    kind: MessageType,
    entries: &[OutCertEntry],
) -> Result<Vec<&OutCertEntry>, ComposeError> {
    let model = nic_model(kind).ok_or_else(|| {
        ComposeError::Schema(format!(
            "{kind:?} does not allow NonIntermediaryCertificates"
        ))
    })?;
    let mut counts = vec![0u32; model.len()];
    for cert in entries {
        let slot = model
            .iter()
            .position(|(use_, role, _, _)| *use_ == cert.use_ && *role == cert.role)
            .ok_or_else(|| {
                ComposeError::Schema(format!(
                    "{kind:?} does not allow {}",
                    cert.role.element_name(cert.use_)
                ))
            })?;
        counts[slot] += 1;
    }
    for (slot, &(use_, role, min, max)) in model.iter().enumerate() {
        if counts[slot] < min {
            return Err(ComposeError::Schema(format!(
                "{kind:?} requires {} ({} of {} present)",
                role.element_name(use_),
                counts[slot],
                min
            )));
        }
        if counts[slot] > max {
            return Err(ComposeError::Schema(format!(
                "{kind:?} allows at most {max} {}",
                role.element_name(use_)
            )));
        }
    }
    let mut ordered = Vec::with_capacity(entries.len());
    for (slot, _) in model.iter().enumerate() {
        let (use_, role, _, _) = model[slot];
        ordered.extend(entries.iter().filter(|c| c.use_ == use_ && c.role == role));
    }
    Ok(ordered)
}

/// One content unit in an outbound container.
#[derive(Debug, Clone, Default)]
pub struct OutContent {
    pub id: String,
    /// Inline content; written as Base64Content (still clear text here —
    /// use [`encrypt_container`] to produce an encrypted container).
    pub text: Option<String>,
    /// Attachment reference (`cid:...`); the attachment itself rides in
    /// `OutMessage::attachments`.
    pub href: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OutContentContainer {
    pub id: String,
    pub contents: Vec<OutContent>,
    /// Encrypted attachments referenced from this container's `cid:`
    /// contents (Java `createEncryptedAttachments`); written after the
    /// Content elements. Built with [`encrypt_attachments`].
    pub encrypted_attachments: Vec<OutEncryptedAttachment>,
}

/// Key-transport parameters of one outbound encryption (how the session
/// key is wrapped for a recipient).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyTransportParams {
    /// `rsa-oaep` (with MGF + digest) or `rsa-1_5`.
    pub algorithm: String,
    /// MGF1 URI for OAEP (e.g. `...#mgf1sha256`); ignored for v1.5.
    pub mgf: Option<String>,
    /// OAEP digest URI; ignored for v1.5.
    pub digest: Option<String>,
}

impl KeyTransportParams {
    /// OAEP with MGF1-SHA256 and SHA-256 (the OSCI 2.6.x default).
    pub fn oaep_sha256() -> Self {
        Self {
            algorithm: osci_crypto::algorithms::KEY_TRANSPORT_RSA_OAEP.to_string(),
            mgf: Some(osci_crypto::algorithms::MGF1_SHA256.to_string()),
            digest: Some(osci_crypto::algorithms::DIGEST_SHA256.to_string()),
        }
    }

    /// Legacy RSAES-PKCS1-v1_5 (no parameters).
    pub fn rsa_1_5() -> Self {
        Self {
            algorithm: osci_crypto::algorithms::KEY_TRANSPORT_RSA_1_5.to_string(),
            mgf: None,
            digest: None,
        }
    }
}

/// How the recipient's key info is referenced in the EncryptedKey:
/// a `RetrievalMethod` to the cert element in the message header
/// (content encryption) or the inline X509 certificate (transport
/// envelope).
#[derive(Debug, Clone)]
pub enum KeyInfoRef {
    CertElementId(String),
    InlineCertDer(Vec<u8>),
    /// Raw base64 session key (the Java encrypted-attachment dialect:
    /// the key rides as MgmtData, protected by the container encryption
    /// around the element).
    MgmtData(String),
}

/// One wrapped session key for a recipient.
#[derive(Debug, Clone)]
pub struct OutEncryptedKey {
    pub key_transport: KeyTransportParams,
    pub key_info: KeyInfoRef,
    pub wrapped_key: Vec<u8>,
}

/// An outbound `xenc:EncryptedData` element (content-level, in the
/// ContentPackage, or transport-level in the Body): the session-key
/// encrypted plaintext plus one EncryptedKey per recipient.
#[derive(Debug, Clone)]
pub struct OutEncryptedData {
    /// `encdata_N` convention; optional on the wire (absent on transport
    /// envelopes).
    pub id: Option<String>,
    /// MimeType of the encrypted payload (`text/xml` for containers,
    /// `Multipart/Related` for transport envelopes).
    pub mime_type: Option<String>,
    /// Content cipher URI (e.g. AES-256-GCM).
    pub content_cipher: String,
    /// IV length in bytes; written as the Korrigenda-7 `IvLength` hint
    /// whenever it is not the legacy 16.
    pub iv_len: usize,
    /// IV || ciphertext, exactly as written base64 into CipherValue
    /// (content) or the referenced MIME part (transport).
    pub ciphertext: Vec<u8>,
    pub key_transport: KeyTransportParams,
    pub recipients: Vec<OutEncryptedKey>,
    /// Transport variant only: `CipherReference URI` instead of an inline
    /// CipherValue.
    pub cipher_reference: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OutAttachment {
    pub content_id: String,
    pub content_type: String,
    /// Legacy base64 transfer encoding (binary is the default since
    /// 03/2023).
    pub base64_encoding: bool,
    pub data: Vec<u8>,
}

/// One encrypted attachment (the Java `EncryptedDataOSCI` dialect): an
/// `xenc:EncryptedData Id="Attachment<refid>" MimeType="text/xml"`
/// written inside the encrypted container after the Content elements.
/// The per-attachment session key rides as `ds:KeyInfo/ds:MgmtData`
/// (protected by the container encryption); the ciphertext is the
/// attachment's MIME part (`[IV][ciphertext]`).
#[derive(Debug, Clone)]
pub struct OutEncryptedAttachment {
    /// `Attachment<refid>` (Java convention).
    pub id: String,
    /// Content id of the referenced attachment, without `cid:`.
    pub ref_id: String,
    pub content_cipher: String,
    pub iv_len: usize,
    /// base64 of the raw session key.
    pub mgmt_data: String,
    /// IV || ciphertext, exactly the bytes of the MIME part.
    pub ciphertext: Vec<u8>,
}

/// One outbound vendor-extension (custom) header: the caller supplies
/// the raw XML fragment (Java passes the JAXB-marshaled string); compose
/// canonicalizes it, strips any XML declaration and splices
/// ` Id="..."` into the root start tag (Java `addIdToCustomHeader`).
#[derive(Debug, Clone)]
pub struct OutCustomHeader {
    pub id: String,
    pub xml: String,
}

/// One feedback entry of a response.
#[derive(Debug, Clone)]
pub struct OutFeedback {
    pub language: Option<String>,
    pub code: String,
    pub text: String,
}

/// Process card of an outbound bundle (timestamps in UTC; rendered in the
/// given zone offset).
#[derive(Debug, Clone, Default)]
pub struct OutProcessCard {
    pub creation: Option<chrono::DateTime<chrono::Utc>>,
    pub forwarding: Option<chrono::DateTime<chrono::Utc>>,
    pub reception: Option<chrono::DateTime<chrono::Utc>>,
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OutProcessCardBundle {
    pub message_id: Option<String>,
    pub process_cards: Vec<OutProcessCard>,
    /// Inspection report entries (the schemas require the report on
    /// accept/process bundles).
    pub inspections: Vec<super::Inspection>,
}

/// Certificate entry of the outbound NonIntermediaryCertificates header.
#[derive(Debug, Clone)]
pub struct OutCertEntry {
    pub role: crate::soap::CertRole,
    pub use_: crate::soap::CertUse,
    pub id: String,
    pub der: Vec<u8>,
}

/// An outbound OSCI message.
#[derive(Debug, Clone, Default)]
pub struct OutMessage {
    pub kind: Option<MessageType>,
    pub control_block: ControlBlock,
    pub desired_languages: Option<String>,
    /// Quality-of-timestamp headers (cryptographic quality flag).
    pub quality_creation: Option<bool>,
    pub quality_reception: Option<bool>,
    pub non_intermediary_certificates: Vec<OutCertEntry>,
    pub feature_description: Option<FeatureDescription>,
    /// Vendor extension headers (e.g. MessageMetaData), written after the
    /// FeatureDescription, before the Body - the Java custom-header slot.
    /// The fragment is canonicalized and spliced with its `Id` on
    /// compose; it becomes a transport-signature reference.
    pub custom_headers: Vec<OutCustomHeader>,
    /// Children XML of the message entry element (e.g. MessageId/Subject);
    /// the entry itself is placed by `kind`.
    pub entry_inner: Option<String>,
    /// Selection rule content (fetch messages): written inside the entry.
    pub selection_rule: Option<String>,
    /// Process card bundles (accept/process deliveries and responses).
    pub process_card_bundles: Vec<OutProcessCardBundle>,
    /// Response feedback entries.
    pub feedback: Vec<OutFeedback>,
    /// Chunk information of partial deliveries.
    pub chunk_information: Option<ChunkInformation>,
    /// Body content (containers; omitted for entry-in-body types).
    pub containers: Vec<OutContentContainer>,
    /// Encrypted containers (content-level EncryptedData, emitted in the
    /// ContentPackage before the plaintext containers per the 2.6.1
    /// writer). Built with [`encrypt_container`].
    pub encrypted_data: Vec<OutEncryptedData>,
    pub attachments: Vec<OutAttachment>,
}

/// Where the message entry element goes (mirrors the Java split: most
/// types use an OsciH header entry; dialog lifecycle and fetchProcessCard
/// write the entry into the Body).
fn entry_in_body(kind: MessageType) -> bool {
    matches!(
        kind,
        MessageType::InitDialog
            | MessageType::ExitDialog
            | MessageType::GetMessageId
            | MessageType::FetchProcessCard
            | MessageType::ResponseToInitDialog
            | MessageType::ResponseToExitDialog
            | MessageType::ResponseToGetMessageId
            | MessageType::ResponseToFetchProcessCard
    )
}

fn quality_header(
    w: &mut XmlWriter<&mut Vec<u8>>,
    reception: bool,
    cryptographic: bool,
) -> std::io::Result<()> {
    let id = if reception {
        "qualityoftimestamp_reception"
    } else {
        "qualityoftimestamp_creation"
    };
    let quality = if cryptographic {
        "cryptographic"
    } else {
        "plain"
    };
    let service = if reception { "reception" } else { "creation" };
    w.raw(
        format!(
            "<osci:QualityOfTimestamp{NS_BLOCK} Id=\"{id}\" Quality=\"{quality}\" Service=\"{service}\" soap:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" soap:mustUnderstand=\"1\"></osci:QualityOfTimestamp>"
        )
        .as_bytes(),
    )
}

/// Compose the message entry element (children XML depends on the type;
/// child order per the entry-type sequences: responses carry Feedback
/// first, chunk information comes after the entry content).
fn entry_inner_xml(msg: &OutMessage, kind: MessageType) -> String {
    let mut inner = String::new();
    let feedback_xml = || -> String {
        let mut xml = String::new();
        if !msg.feedback.is_empty() {
            xml.push_str("<osci:Feedback>");
            for fb in &msg.feedback {
                let lang = fb
                    .language
                    .as_deref()
                    .map(|l| format!(" xml:lang=\"{l}\""))
                    .unwrap_or_default();
                let mut text = Vec::new();
                escape_text(&fb.text, &mut text).ok();
                xml.push_str(&format!(
                    "<osci:Entry{lang}><osci:Code>{}</osci:Code><osci:Text>{}</osci:Text></osci:Entry>",
                    fb.code,
                    String::from_utf8_lossy(&text)
                ));
            }
            xml.push_str("</osci:Feedback>");
        }
        xml
    };
    // responseTo*Type sequences start with Feedback, before the echoed
    // entry content
    if kind.is_response() {
        inner.push_str(&feedback_xml());
    }
    match kind {
        MessageType::StoreDelivery | MessageType::ForwardDelivery => {
            if let Some(entry) = &msg.entry_inner {
                inner.push_str(entry);
            }
        }
        MessageType::FetchDelivery | MessageType::FetchProcessCard => {
            // the selection rule is element-only (order.xsd
            // SelectionRuleFetchType: a choice of MessageId or date
            // elements); the composed rule nests the message id
            let rule = msg.selection_rule.clone().unwrap_or_default();
            let mut escaped = Vec::new();
            escape_text(&rule, &mut escaped).ok();
            inner.push_str(&format!(
                "<osci:SelectionRule><osci:MessageId>{}</osci:MessageId></osci:SelectionRule>",
                String::from_utf8_lossy(&escaped)
            ));
            // fetchDelivery's entry contains ONLY the SelectionRule
            // (fetchDeliveryType extends the empty header block template)
            let _ = kind;
        }
        _ => {
            if let Some(entry) = &msg.entry_inner {
                inner.push_str(entry);
            }
        }
    }
    if let Some(chunk) = &msg.chunk_information {
        // Java ChunkInformation.writeXML order: ChunkNumber, ChunkSize,
        // ReceivedChunks, TotalChunkNumbers, TotalMessageSize; the
        // received list is space separated, -1 when empty - the
        // attribute is omitted entirely when the kind prohibits it
        let mut attrs = format!(" ChunkNumber=\"{}\"", chunk.chunk_number);
        if let Some(v) = chunk.chunk_size {
            attrs.push_str(&format!(" ChunkSize=\"{v}\""));
        }
        let received_prohibited =
            chunk_model(kind).is_some_and(|m| m.received_chunks == AttrUse::Prohibited);
        if !received_prohibited {
            let received = if chunk.received_chunks.is_empty() {
                "-1".to_string()
            } else {
                chunk
                    .received_chunks
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            attrs.push_str(&format!(" ReceivedChunks=\"{received}\""));
        }
        if let Some(v) = chunk.total_chunk_numbers {
            attrs.push_str(&format!(" TotalChunkNumbers=\"{v}\""));
        }
        if let Some(v) = chunk.total_message_size {
            attrs.push_str(&format!(" TotalMessageSize=\"{v}\""));
        }
        inner.push_str(&format!(
            "<osci2017:ChunkInformation{attrs}></osci2017:ChunkInformation>"
        ));
    }
    if !msg.process_card_bundles.is_empty() {
        inner.push_str(&bundles_xml(&msg.process_card_bundles));
    }
    if !kind.is_response() {
        // request entries have no Feedback slot (the entry types of the
        // delivery/fetch requests are Feedback-free); compose errors on
        // it in compose_xml, this branch only keeps the legacy position
        inner.push_str(&feedback_xml());
    }
    inner
}

fn timestamp_xml(label: &str, stamp: &Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
    stamp.map(|t| {
        let zone = chrono::FixedOffset::east_opt(3600).unwrap();
        let text = crate::helper::dates::format_iso8601(&t.with_timezone(&zone));
        format!("<osci:{label}><osci:Plain>{text}</osci:Plain></osci:{label}>")
    })
}

fn bundles_xml(bundles: &[OutProcessCardBundle]) -> String {
    let mut xml = String::new();
    for bundle in bundles {
        xml.push_str("<osci:ProcessCardBundle>");
        if let Some(id) = &bundle.message_id {
            let mut escaped = Vec::new();
            escape_text(id, &mut escaped).ok();
            xml.push_str(&format!(
                "<osci:MessageId>{}</osci:MessageId>",
                String::from_utf8_lossy(&escaped)
            ));
        }
        for card in &bundle.process_cards {
            let recent = card
                .creation
                .or(card.reception)
                .map(|t| {
                    let zone = chrono::FixedOffset::east_opt(3600).unwrap();
                    crate::helper::dates::format_iso8601(&t.with_timezone(&zone))
                })
                .unwrap_or_default();
            xml.push_str(&format!(
                "<osci:ProcessCard RecentModification=\"{recent}\">"
            ));
            for (label, stamp) in [
                ("Creation", &card.creation),
                ("Forwarding", &card.forwarding),
                ("Reception", &card.reception),
            ] {
                if let Some(part) = timestamp_xml(label, stamp) {
                    xml.push_str(&part);
                }
            }
            if let Some(subject) = &card.subject {
                let mut escaped = Vec::new();
                escape_text(subject, &mut escaped).ok();
                xml.push_str(&format!(
                    "<osci:Subject>{}</osci:Subject>",
                    String::from_utf8_lossy(&escaped)
                ));
            }
            xml.push_str("</osci:ProcessCard>");
        }
        if !bundle.inspections.is_empty() {
            xml.push_str("<osci:InspectionReport>");
            for inspection in &bundle.inspections {
                xml.push_str("<osci:Inspection>");
                if let Some(timestamp) = &inspection.timestamp {
                    xml.push_str(&format!(
                        "<osci:Timestamp><osci:Plain>{timestamp}</osci:Plain></osci:Timestamp>"
                    ));
                }
                for (tag, value) in [
                    ("X509SubjectName", &inspection.x509_subject_name),
                    ("X509IssuerName", &inspection.x509_issuer_name),
                    ("X509SerialNumber", &inspection.x509_serial_number),
                ] {
                    if let Some(value) = value {
                        xml.push_str(&format!("<osci:{tag}>{value}</osci:{tag}>"));
                    }
                }
                if let Some(cert_type) = &inspection.cert_type {
                    xml.push_str(&format!(
                        "<osci:CertType Type=\"{cert_type}\"></osci:CertType>"
                    ));
                }
                if let Some(result) = &inspection.math_result {
                    xml.push_str(&format!(
                        "<osci:MathResult Result=\"{result}\"></osci:MathResult>"
                    ));
                }
                if let Some(result) = &inspection.offline_result {
                    xml.push_str(&format!(
                        "<osci:OfflineResult Result=\"{result}\"></osci:OfflineResult>"
                    ));
                }
                if let Some(result) = &inspection.online_result {
                    xml.push_str(&format!(
                        "<osci:OnlineResult Result=\"{result}\"></osci:OnlineResult>"
                    ));
                }
                xml.push_str("</osci:Inspection>");
            }
            xml.push_str("</osci:InspectionReport>");
        }
        xml.push_str("</osci:ProcessCardBundle>");
    }
    xml
}

/// Compose the full MIME stream (message part + attachments).
pub fn compose_message(msg: &OutMessage, boundary: &str) -> Result<Vec<u8>, ComposeError> {
    let kind = msg
        .kind
        .ok_or_else(|| ComposeError::Kind("message kind missing".into()))?;
    let mut xml = compose_xml(msg, kind, boundary)?;

    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "MIME-Version: 1.0\r\nContent-Type: Multipart/Related; boundary={boundary}; type=text/xml\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Type: text/xml; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <{MESSAGE_CONTENT_ID}>\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(&xml);
    for att in &msg.attachments {
        out.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
        out.extend_from_slice(
            format!(
                "Content-Type: {}\r\nContent-Transfer-Encoding: {}\r\nContent-ID: <{}>\r\n\r\n",
                att.content_type,
                if att.base64_encoding {
                    "base64"
                } else {
                    "binary"
                },
                att.content_id
            )
            .as_bytes(),
        );
        if att.base64_encoding {
            out.extend_from_slice(base64::encode(&att.data).as_bytes());
        } else {
            out.extend_from_slice(&att.data);
        }
    }
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    xml.clear();
    Ok(out)
}

/// Compose only the XML part.
pub fn compose_xml(
    msg: &OutMessage,
    kind: MessageType,
    _boundary: &str,
) -> Result<Vec<u8>, ComposeError> {
    // the Java writer derives the hint from the class name:
    // "soap" + PascalCase(elementName) + ".xsd"
    let element = kind.element_name();
    let mut pascal = String::with_capacity(element.len());
    let mut chars = element.chars();
    if let Some(first) = chars.next() {
        pascal.extend(first.to_uppercase());
        pascal.push_str(chars.as_str());
    }
    let schema = format!(
        " xsi:schemaLocation=\"http://schemas.xmlsoap.org/soap/envelope/ soap{pascal}.xsd http://www.w3.org/2000/09/xmldsig# oscisig.xsd http://www.w3.org/2001/04/xmlenc# oscienc.xsd\""
    );
    let mut out = Vec::new();
    let mut w = XmlWriter::new(&mut out);
    w.write_decl().map_err(ComposeError::Io)?;
    w.raw(b"\r\n\r\n<soap:Envelope").ok();
    w.raw(NS_BLOCK.as_bytes()).ok();
    w.raw(schema.as_bytes()).ok();
    w.raw(b"><soap:Header>").ok();

    // ControlBlock - shape-validated against the kind's schema
    // restriction before anything is written
    check_control_block_shape(kind, &msg.control_block)?;
    // deliveries must carry a ContentPackage (their Body schema has it
    // at minOccurs=1)
    if body_requires_content_package(kind)
        && msg.containers.is_empty()
        && msg.encrypted_data.is_empty()
    {
        return Err(ComposeError::Schema(format!(
            "{kind:?} requires a ContentPackage in the Body"
        )));
    }
    // Feedback exists only in responseTo* entries
    if !msg.feedback.is_empty() && !kind.is_response() {
        return Err(ComposeError::Schema(format!(
            "{kind:?} does not allow Feedback"
        )));
    }
    // the EFFI schema requires at least one supported feature
    if let Some(fd) = &msg.feature_description
        && fd.features.is_empty()
    {
        return Err(ComposeError::Schema(
            "FeatureDescription requires at least one supported feature".into(),
        ));
    }
    if let Some(chunk) = &msg.chunk_information {
        check_chunk_shape(kind, chunk)?;
    }
    let mut header_out = Vec::new();
    {
        let mut hc = HeaderComposer::new(&mut header_out);
        hc.header_entry(&crate::soap::HeaderEntry::ControlBlock(
            msg.control_block.clone(),
        ))
        .map_err(ComposeError::Io)?;
    }
    w.raw(&header_out).ok();

    // DesiredLanguages - request schemas only (the soapResponseTo*.xsd
    // header sequences have no DesiredLanguages slot); LanguagesList is
    // an xsd:list of xs:language tokens (space separated)
    if let Some(languages) = &msg.desired_languages {
        if kind.is_response() {
            return Err(ComposeError::Schema(format!(
                "{kind:?} does not allow DesiredLanguages"
            )));
        }
        for token in languages.split_whitespace() {
            let valid = token
                .split('-')
                .all(|sub| !sub.is_empty() && sub.chars().all(|c| c.is_ascii_alphanumeric()));
            if !valid {
                return Err(ComposeError::Schema(format!(
                    "DesiredLanguages: \"{token}\" is not a language token"
                )));
            }
        }
        let mut lang_out = Vec::new();
        {
            let mut hc = HeaderComposer::new(&mut lang_out);
            hc.header_entry(&crate::soap::HeaderEntry::DesiredLanguages {
                languages: languages.clone(),
            })
            .map_err(ComposeError::Io)?;
        }
        w.raw(&lang_out).ok();
    }

    // Quality of timestamps (creation first, then reception), in the
    // cardinality the kind's schema demands
    match qot_model(kind) {
        QotModel::TwoRequired => {
            quality_header(&mut w, false, msg.quality_creation.unwrap_or(false))
                .map_err(ComposeError::Io)?;
            quality_header(&mut w, true, msg.quality_reception.unwrap_or(false))
                .map_err(ComposeError::Io)?;
        }
        QotModel::CreationRequired => {
            if msg.quality_reception.is_some() {
                return Err(ComposeError::Schema(format!(
                    "{kind:?} allows only the creation QualityOfTimestamp"
                )));
            }
            quality_header(&mut w, false, msg.quality_creation.unwrap_or(false))
                .map_err(ComposeError::Io)?;
        }
        QotModel::OptionalTwo => {
            if let Some(cryptographic) = msg.quality_creation {
                quality_header(&mut w, false, cryptographic).map_err(ComposeError::Io)?;
            }
            if let Some(cryptographic) = msg.quality_reception {
                quality_header(&mut w, true, cryptographic).map_err(ComposeError::Io)?;
            }
        }
        QotModel::Forbidden => {
            if msg.quality_creation.is_some() || msg.quality_reception.is_some() {
                return Err(ComposeError::Schema(format!(
                    "{kind:?} does not allow QualityOfTimestamp"
                )));
            }
        }
    }

    // Message entry (header types; dialog/fetchProcessCard types go to
    // the body below)
    if !entry_in_body(kind) {
        let id = kind.element_name().to_lowercase();
        let ns_attr = if kind.namespace() == crate::soap::OSCI2017_NS {
            // OsciH writes ns2017 for non-OSCI namespaces
            " xmlns:osci=\"http://www.osci.de/2002/04/osci\" xmlns:osci2017=\"http://xoev.de/transport/osci12/7\"".to_string()
        } else {
            String::new()
        };
        let prefix = if kind.namespace() == crate::soap::OSCI2017_NS {
            "osci2017"
        } else {
            "osci"
        };
        let _ = ns_attr;
        let header_ns = if prefix == "osci2017" {
            ns_block_2017()
        } else {
            NS_BLOCK.to_string()
        };
        w.raw(
            format!(
                "<{prefix}:{}{header_ns} Id=\"{id}\" soap:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" soap:mustUnderstand=\"1\">",
                kind.element_name()
            )
            .as_bytes(),
        )
        .ok();
        w.raw(entry_inner_xml(msg, kind).as_bytes()).ok();
        w.raw(format!("</{prefix}:{}>", kind.element_name()).as_bytes())
            .ok();
    }

    // NonIntermediaryCertificates - present iff the kind's schema has a
    // slot; children validated against the per-type model and written in
    // the canonical schema sequence
    if !msg.non_intermediary_certificates.is_empty() || nic_required(kind) {
        let ordered = canonically_ordered_nic(kind, &msg.non_intermediary_certificates)?;
        w.raw(
                format!(
                    "<osci:NonIntermediaryCertificates{NS_BLOCK} Id=\"nonintermediarycertificates\" soap:actor=\"http://www.w3.org/2001/12/soap-envelope/actor/none\" soap:mustUnderstand=\"1\">"
                )
                .as_bytes(),
            )
            .ok();
        for cert in ordered {
            w.raw(
                format!(
                    "<osci:{} Id=\"{}\"><ds:X509Data><ds:X509Certificate>",
                    cert.role.element_name(cert.use_),
                    cert.id
                )
                .as_bytes(),
            )
            .ok();
            w.raw(base64::encode(&cert.der).as_bytes()).ok();
            w.raw(
                format!(
                    "</ds:X509Certificate></ds:X509Data></osci:{}>",
                    cert.role.element_name(cert.use_)
                )
                .as_bytes(),
            )
            .ok();
        }
        w.raw(b"</osci:NonIntermediaryCertificates>").ok();
    }

    // FeatureDescription
    if let Some(fd) = &msg.feature_description {
        let mut fd_out = Vec::new();
        {
            let mut hc = HeaderComposer::new(&mut fd_out);
            hc.header_entry(&crate::soap::HeaderEntry::FeatureDescription(fd.clone()))
                .map_err(ComposeError::Io)?;
        }
        w.raw(&fd_out).ok();
    }

    // custom (vendor extension) headers, canonicalized with the spliced Id
    for custom in &msg.custom_headers {
        w.raw(canonical_custom_header(custom)?.as_bytes()).ok();
    }

    w.raw(b"</soap:Header>").ok();

    // Body
    w.raw(format!("<soap:Body{NS_BLOCK} Id=\"body\">").as_bytes())
        .ok();
    if entry_in_body(kind) {
        let prefix = if kind.namespace() == crate::soap::OSCI2017_NS {
            "osci2017"
        } else {
            "osci"
        };
        let inner = entry_inner_xml(msg, kind);
        if inner.is_empty() {
            w.raw(
                format!(
                    "<{prefix}:{}></{prefix}:{}>",
                    kind.element_name(),
                    kind.element_name()
                )
                .as_bytes(),
            )
            .ok();
        } else {
            w.raw(
                format!(
                    "<{prefix}:{}>{inner}</{prefix}:{}>",
                    kind.element_name(),
                    kind.element_name()
                )
                .as_bytes(),
            )
            .ok();
        }
    } else if !msg.containers.is_empty() || !msg.encrypted_data.is_empty() {
        w.raw(b"<osci:ContentPackage>").ok();
        // Java 2.6.1 writer + XSD order: EncryptedData elements first,
        // then the plaintext containers.
        for enc in &msg.encrypted_data {
            write_encrypted_data_xml(enc, &mut w);
        }
        for container in &msg.containers {
            w.raw(format!("<osci:ContentContainer{NS_BLOCK} Id=\"{}\">", container.id).as_bytes())
                .ok();
            for content in &container.contents {
                match (&content.text, &content.href) {
                    (Some(text), _) => {
                        // the schema puts the Id on Base64Content, matching
                        // the fixtures (`<osci:Content><osci:Base64Content
                        // Id="content0">...`)
                        w.raw(b"<osci:Content><osci:Base64Content Id=\"").ok();
                        w.raw(content.id.as_bytes()).ok();
                        w.raw(b"\">").ok();
                        w.raw(base64::encode(text.as_bytes()).as_bytes()).ok();
                        w.raw(b"</osci:Base64Content></osci:Content>").ok();
                    }
                    (None, Some(href)) => {
                        w.raw(
                            format!(
                                "<osci:Content Id=\"{}\" href=\"{href}\"></osci:Content>",
                                content.id
                            )
                            .as_bytes(),
                        )
                        .ok();
                    }
                    (None, None) => {
                        w.raw(
                            format!("<osci:Content Id=\"{}\"></osci:Content>", content.id)
                                .as_bytes(),
                        )
                        .ok();
                    }
                }
            }
            w.raw(b"</osci:ContentContainer>").ok();
        }
        w.raw(b"</osci:ContentPackage>").ok();
    }
    w.raw(b"</soap:Body></soap:Envelope>").ok();
    let _ = w;
    Ok(out)
}

/// Write one ContentContainer element (ns decls, Id, Signature*,
/// Content*) — the exact Java `writeXML` shape, and the plaintext byte
/// source for content encryption.
pub fn write_container_xml<W: std::io::Write>(
    container: &OutContentContainer,
    w: &mut XmlWriter<W>,
) {
    w.raw(format!("<osci:ContentContainer{NS_BLOCK} Id=\"{}\">", container.id).as_bytes())
        .ok();
    for content in &container.contents {
        match (&content.text, &content.href) {
            (Some(text), _) => {
                // the schema puts the Id on Base64Content, matching the
                // fixtures (`<osci:Content><osci:Base64Content
                // Id="content0">...`)
                w.raw(b"<osci:Content><osci:Base64Content Id=\"").ok();
                w.raw(content.id.as_bytes()).ok();
                w.raw(b"\">").ok();
                w.raw(base64::encode(text.as_bytes()).as_bytes()).ok();
                w.raw(b"</osci:Base64Content></osci:Content>").ok();
            }
            (None, Some(href)) => {
                w.raw(
                    format!(
                        "<osci:Content Id=\"{}\" href=\"{href}\"></osci:Content>",
                        content.id
                    )
                    .as_bytes(),
                )
                .ok();
            }
            (None, None) => {
                w.raw(format!("<osci:Content Id=\"{}\"></osci:Content>", content.id).as_bytes())
                    .ok();
            }
        }
    }
    // Java ContentContainer order: the Content elements first, then the
    // encrypted-attachment EncryptedData elements
    for enc in &container.encrypted_attachments {
        write_encrypted_attachment_xml(enc, w);
    }
    w.raw(b"</osci:ContentContainer>").ok();
}

/// Write one encrypted-attachment `xenc:EncryptedData` (Java
/// `EncryptedDataOSCI` dialect: MgmtData key info, CipherReference to
/// the attachment's MIME part with the base64 transform).
pub fn write_encrypted_attachment_xml<W: std::io::Write>(
    enc: &OutEncryptedAttachment,
    w: &mut XmlWriter<W>,
) {
    w.raw(b"<xenc:EncryptedData Id=\"").ok();
    w.raw(enc.id.as_bytes()).ok();
    w.raw(b"\" MimeType=\"text/xml\">").ok();
    w.raw(b"<xenc:EncryptionMethod Algorithm=\"").ok();
    w.raw(enc.content_cipher.as_bytes()).ok();
    w.raw(b"\"").ok();
    if enc.iv_len != 16 {
        w.raw(b"><osci128:IvLength xmlns:osci128=\"http://xoev.de/transport/osci12/8\" Value=\"")
            .ok();
        w.raw(enc.iv_len.to_string().as_bytes()).ok();
        w.raw(b"\"></osci128:IvLength></xenc:EncryptionMethod>")
            .ok();
    } else {
        w.raw(b"></xenc:EncryptionMethod>").ok();
    }
    w.raw(b"<ds:KeyInfo><ds:MgmtData>").ok();
    w.raw(enc.mgmt_data.as_bytes()).ok();
    w.raw(b"</ds:MgmtData></ds:KeyInfo>").ok();
    w.raw(b"<xenc:CipherData><xenc:CipherReference URI=\"cid:")
        .ok();
    w.raw(enc.ref_id.as_bytes()).ok();
    w.raw(
        b"\"><xenc:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#base64\"></ds:Transform></xenc:Transforms></xenc:CipherReference></xenc:CipherData></xenc:EncryptedData>",
    )
    .ok();
}

/// Canonicalize a custom-header fragment and set ` Id="..."` on the root
/// start tag (Java `makeOSCICustomHeader` + `addIdToCustomHeader`: the
/// wire form is the canonical form of the fragment with the Id
/// attribute, any XML declaration stripped). An existing root Id is
/// replaced, not duplicated.
fn canonical_custom_header(custom: &OutCustomHeader) -> Result<String, ComposeError> {
    let doc = crate::xml::parser::parse(&custom.xml)
        .map_err(|e| ComposeError::Missing(format!("custom header {}: {e}", custom.id)))?;
    let canonical = crate::xml::c14n::canonicalize(&doc)
        .map_err(|e| ComposeError::Missing(format!("custom header {}: {e}", custom.id)))?;
    let body = String::from_utf8(canonical.bytes)
        .map_err(|e| ComposeError::Missing(format!("custom header {}: {e}", custom.id)))?;
    // the root start tag ends at the first '>' (attribute values are
    // escaped, so no '>' can appear inside it)
    let Some(pos) = body.find('>') else {
        return Err(ComposeError::Missing(format!(
            "custom header {}: no root element",
            custom.id
        )));
    };
    let mut start_tag = body[..pos].to_string();
    let self_closing = start_tag.ends_with('/');
    if self_closing {
        start_tag.pop();
    }
    let id_attr = format!(" Id=\"{}\"", escape_attr_text(&custom.id));
    match start_tag.find(" Id=\"") {
        Some(existing) => {
            // replace the existing Id attribute value
            let value_start = existing + " Id=\"".len();
            let value_end = start_tag[value_start..]
                .find('"')
                .map(|p| value_start + p)
                .ok_or_else(|| {
                    ComposeError::Missing(format!("custom header {}: bad Id", custom.id))
                })?;
            // replace through the closing quote
            start_tag.replace_range(existing..value_end + 1, &id_attr);
        }
        None => start_tag.push_str(&id_attr),
    }
    if self_closing {
        start_tag.push('/');
    }
    Ok(format!("{start_tag}>{}", &body[pos + 1..]))
}

/// Attribute-value escaping for the spliced Id (quotes and specials).
fn escape_attr_text(value: &str) -> String {
    let mut out = Vec::new();
    crate::xml::writer::escape_attr(value, &mut out).ok();
    String::from_utf8(out).unwrap_or_default()
}

/// Write one `xenc:EncryptedData` element (content or transport shape).
pub fn write_encrypted_data_xml<W: std::io::Write>(enc: &OutEncryptedData, w: &mut XmlWriter<W>) {
    w.raw(b"<xenc:EncryptedData").ok();
    if let Some(id) = &enc.id {
        w.raw(format!(" Id=\"{id}\"").as_bytes()).ok();
    }
    if let Some(mime) = &enc.mime_type {
        w.raw(format!(" MimeType=\"{mime}\"").as_bytes()).ok();
    }
    w.raw(b">").ok();

    // EncryptionMethod (+ Korrigenda-7 IV hint when non-legacy)
    w.raw(b"<xenc:EncryptionMethod Algorithm=\"").ok();
    w.raw(enc.content_cipher.as_bytes()).ok();
    w.raw(b"\"").ok();
    if enc.iv_len != 16 {
        w.raw(b"><osci128:IvLength xmlns:osci128=\"http://xoev.de/transport/osci12/8\" Value=\"")
            .ok();
        w.raw(enc.iv_len.to_string().as_bytes()).ok();
        w.raw(b"\"></osci128:IvLength></xenc:EncryptionMethod>")
            .ok();
    } else {
        w.raw(b"></xenc:EncryptionMethod>").ok();
    }

    // KeyInfo with one EncryptedKey per recipient
    w.raw(b"<ds:KeyInfo>").ok();
    for recipient in &enc.recipients {
        w.raw(b"<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"")
            .ok();
        w.raw(recipient.key_transport.algorithm.as_bytes()).ok();
        w.raw(b"\"").ok();
        if let (Some(mgf), Some(digest)) = (
            &recipient.key_transport.mgf,
            &recipient.key_transport.digest,
        ) {
            w.raw(b"><xenc11:MGF xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"")
                .ok();
            w.raw(mgf.as_bytes()).ok();
            w.raw(b"\"></xenc11:MGF><ds:DigestMethod Algorithm=\"").ok();
            w.raw(digest.as_bytes()).ok();
            // the children closed the start tag already: appending the
            // bare ">" of the childless branch here would become
            // character content inside EncryptionMethod (issue #3)
            w.raw(b"\"></ds:DigestMethod></xenc:EncryptionMethod><ds:KeyInfo>")
                .ok();
        } else {
            w.raw(b"></xenc:EncryptionMethod><ds:KeyInfo>").ok();
        }
        match &recipient.key_info {
            KeyInfoRef::CertElementId(id) => {
                w.raw(
                    b"<ds:RetrievalMethod Type=\"http://www.w3.org/2000/09/xmldsig#X509Data\" URI=\"#",
                )
                .ok();
                w.raw(id.as_bytes()).ok();
                w.raw(b"\"></ds:RetrievalMethod>").ok();
            }
            KeyInfoRef::InlineCertDer(der) => {
                w.raw(b"<ds:X509Data><ds:X509Certificate>").ok();
                w.raw(base64::encode(der).as_bytes()).ok();
                w.raw(b"</ds:X509Certificate></ds:X509Data>").ok();
            }
            KeyInfoRef::MgmtData(key) => {
                w.raw(b"<ds:MgmtData>").ok();
                w.raw(key.as_bytes()).ok();
                w.raw(b"</ds:MgmtData>").ok();
            }
        }
        w.raw(b"</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>")
            .ok();
        w.raw(base64::encode(&recipient.wrapped_key).as_bytes())
            .ok();
        w.raw(b"</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>")
            .ok();
    }
    w.raw(b"</ds:KeyInfo>").ok();

    // CipherData: inline CipherValue (content) or CipherReference (transport)
    if let Some(cid) = &enc.cipher_reference {
        w.raw(b"<xenc:CipherData><xenc:CipherReference URI=\"").ok();
        w.raw(cid.as_bytes()).ok();
        w.raw(
            b"\"><xenc:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#base64\"></ds:Transform></xenc:Transforms></xenc:CipherReference></xenc:CipherData>",
        )
        .ok();
    } else {
        w.raw(b"<xenc:CipherData><xenc:CipherValue>").ok();
        w.raw(base64::encode(&enc.ciphertext).as_bytes()).ok();
        w.raw(b"</xenc:CipherValue></xenc:CipherData>").ok();
    }

    w.raw(b"</xenc:EncryptedData>").ok();
}

/// Parameters of one outbound encryption.
#[derive(Debug, Clone)]
pub struct EncryptParams {
    /// Content cipher URI (default: AES-256-GCM, the 2.6.x default).
    pub content_cipher: String,
    /// Key-transport parameters (default: OAEP-SHA256/MGF1-SHA256).
    pub key_transport: KeyTransportParams,
    /// Id for the EncryptedData element (`encdata_N` convention).
    pub id: Option<String>,
}

impl Default for EncryptParams {
    fn default() -> Self {
        Self {
            content_cipher: osci_crypto::algorithms::DEFAULT_SYMMETRIC_CIPHER.to_string(),
            key_transport: KeyTransportParams::oaep_sha256(),
            id: None,
        }
    }
}

/// Encrypt one inner ContentContainer for the given recipients (port of
/// the `EncryptedDataOSCI.encrypt` flow): the container's plain writeXML
/// bytes are session-key encrypted (`[IV][ciphertext]`), the session key
/// is wrapped once per recipient.
///
/// `iv` pins the IV for deterministic tests; pass `None` in production.
pub fn encrypt_container(
    inner: &OutContentContainer,
    reader_certs: &[&osci_crypto::Certificate],
    reader_cert_element_ids: &[String],
    params: &EncryptParams,
    iv: Option<&[u8]>,
) -> Result<OutEncryptedData, ComposeError> {
    if reader_certs.len() != reader_cert_element_ids.len() {
        return Err(ComposeError::Missing(
            "reader certs and cert element ids must pair".into(),
        ));
    }

    // 1. plaintext = the container's plain writeXML bytes
    let mut plain = Vec::new();
    write_container_xml(inner, &mut XmlWriter::new(&mut plain));

    // 2. session key + IV + content encryption ([IV][ct(+tag/pad)])
    let session_key = osci_crypto::calc::create_sym_key(&params.content_cipher)
        .map_err(|e| ComposeError::Missing(e.to_string()))?;
    let cipher = osci_crypto::algorithms::SymCipher::from_uri(&params.content_cipher)
        .ok_or_else(|| ComposeError::Missing(params.content_cipher.clone()))?;
    let iv_owned = match iv {
        Some(iv) => iv.to_vec(),
        None => osci_crypto::calc::create_iv(&params.content_cipher, None)
            .map_err(|e| ComposeError::Missing(e.to_string()))?,
    };
    let ciphertext =
        osci_crypto::symcipher::oneshot::encrypt(cipher, &session_key, &iv_owned, &plain)
            .map_err(|e| ComposeError::Missing(e.to_string()))?;

    // 3. wrap the session key per recipient
    let mut recipients = Vec::new();
    for (cert, id) in reader_certs.iter().zip(reader_cert_element_ids) {
        let wrapped = osci_crypto::software::wrap_session_key(
            cert,
            &session_key,
            &params.key_transport.algorithm,
            params
                .key_transport
                .digest
                .as_deref()
                .unwrap_or(osci_crypto::algorithms::DIGEST_SHA256),
        )
        .map_err(|e| ComposeError::Missing(e.to_string()))?;
        recipients.push(OutEncryptedKey {
            key_transport: params.key_transport.clone(),
            key_info: KeyInfoRef::CertElementId(id.clone()),
            wrapped_key: wrapped,
        });
    }

    let iv_len = iv_owned.len();
    Ok(OutEncryptedData {
        id: params.id.clone(),
        mime_type: Some("text/xml".into()),
        content_cipher: params.content_cipher.clone(),
        iv_len,
        ciphertext,
        key_transport: params.key_transport.clone(),
        recipients,
        cipher_reference: None,
    })
}

/// Encrypt the attachments referenced from `contents` (`href="cid:X"`
/// where X is an attachment content id) with one session key each
/// (Java `createEncryptedAttachments` + `EncryptedDataOSCI`): the
/// results go into [`OutContentContainer::encrypted_attachments`], and
/// the caller replaces each attachment's MIME part data with the
/// ciphertext. Referenced-but-unknown ids are skipped; each reference is
/// encrypted once.
///
/// `iv` pins the IV of the FIRST attachment for deterministic tests;
/// pass `None` in production.
pub fn encrypt_attachments(
    contents: &[OutContent],
    attachments: &[OutAttachment],
    content_cipher: &str,
    iv: Option<&[u8]>,
) -> Result<Vec<OutEncryptedAttachment>, ComposeError> {
    let cipher = SymCipher::from_uri(content_cipher)
        .ok_or_else(|| ComposeError::Missing(content_cipher.to_string()))?;
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for content in contents {
        let Some(href) = &content.href else {
            continue;
        };
        let Some(ref_id) = href.strip_prefix("cid:") else {
            continue;
        };
        if !seen.insert(ref_id.to_string()) {
            continue;
        }
        let Some(attachment) = attachments.iter().find(|a| a.content_id == ref_id) else {
            continue;
        };
        let key = osci_crypto::calc::create_sym_key(content_cipher)
            .map_err(|e| ComposeError::Missing(e.to_string()))?;
        let iv_bytes = match iv {
            Some(iv) if out.is_empty() => iv.to_vec(),
            _ => osci_crypto::calc::create_iv(content_cipher, None)
                .map_err(|e| ComposeError::Missing(e.to_string()))?,
        };
        let ciphertext =
            osci_crypto::symcipher::oneshot::encrypt(cipher, &key, &iv_bytes, &attachment.data)
                .map_err(|e| ComposeError::Missing(e.to_string()))?;
        out.push(OutEncryptedAttachment {
            id: format!("Attachment{ref_id}"),
            ref_id: ref_id.to_string(),
            content_cipher: content_cipher.to_string(),
            iv_len: iv_bytes.len(),
            mgmt_data: base64::encode(&key),
            ciphertext,
        });
    }
    Ok(out)
}
