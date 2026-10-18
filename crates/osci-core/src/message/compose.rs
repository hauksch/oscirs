//! Message composition (port of the `OSCIMessage.writeXML` /
//! `MessagePartsFactory` write path): builds the MIME/OSCI wire format
//! from message models, using the Java library's part order:
//! ControlBlock, (signature - M6), DesiredLanguages, quality timestamps,
//! message entry, NonIntermediaryCertificates, FeatureDescription,
//! custom headers, Body, attachments.

use crate::helper::base64;
use crate::soap::{
    Composer as HeaderComposer, ControlBlock, FeatureDescription, NS_BLOCK, ns_block_2017,
};
use crate::xml::writer::{XmlWriter, escape_text};

use super::{ChunkInformation, MessageType};

pub const MIME_BOUNDARY_PREFIX: &str = "MIME_boundary";
pub const MESSAGE_CONTENT_ID: &str = "osci@message";

#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error("message kind missing or unsupported: {0}")]
    Kind(String),
    #[error("required value missing: {0}")]
    Missing(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
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

/// Compose the message entry element (children XML depends on the type).
fn entry_inner_xml(msg: &OutMessage, kind: MessageType) -> String {
    let mut inner = String::new();
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
        let mut attrs = format!(" ChunkNumber=\"{}\"", chunk.chunk_number);
        if let Some(v) = chunk.chunk_size {
            attrs.push_str(&format!(" ChunkSize=\"{v}\""));
        }
        if let Some(v) = chunk.total_chunk_numbers {
            attrs.push_str(&format!(" TotalChunkNumbers=\"{v}\""));
        }
        if let Some(v) = chunk.total_message_size {
            attrs.push_str(&format!(" TotalMessageSize=\"{v}\""));
        }
        if let Some(v) = chunk.received_chunks {
            attrs.push_str(&format!(" ReceivedChunks=\"{v}\""));
        }
        inner.push_str(&format!(
            "<osci2017:ChunkInformation{attrs}></osci2017:ChunkInformation>"
        ));
    }
    if !msg.process_card_bundles.is_empty() {
        inner.push_str(&bundles_xml(&msg.process_card_bundles));
    }
    if !msg.feedback.is_empty() {
        inner.push_str("<osci:Feedback>");
        for fb in &msg.feedback {
            let lang = fb
                .language
                .as_deref()
                .map(|l| format!(" xml:lang=\"{l}\""))
                .unwrap_or_default();
            let mut text = Vec::new();
            escape_text(&fb.text, &mut text).ok();
            inner.push_str(&format!(
                "<osci:Entry{lang}><osci:Code>{}</osci:Code><osci:Text>{}</osci:Text></osci:Entry>",
                fb.code,
                String::from_utf8_lossy(&text)
            ));
        }
        inner.push_str("</osci:Feedback>");
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

    // ControlBlock
    let mut header_out = Vec::new();
    {
        let mut hc = HeaderComposer::new(&mut header_out);
        hc.header_entry(&crate::soap::HeaderEntry::ControlBlock(
            msg.control_block.clone(),
        ))
        .map_err(ComposeError::Io)?;
    }
    w.raw(&header_out).ok();

    // DesiredLanguages
    if let Some(languages) = &msg.desired_languages {
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

    // Quality of timestamps (creation first, then reception)
    if let Some(cryptographic) = msg.quality_creation {
        quality_header(&mut w, false, cryptographic).map_err(ComposeError::Io)?;
    }
    if let Some(cryptographic) = msg.quality_reception {
        quality_header(&mut w, true, cryptographic).map_err(ComposeError::Io)?;
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

    // NonIntermediaryCertificates
    if !msg.non_intermediary_certificates.is_empty() {
        w.raw(
            format!(
                "<osci:NonIntermediaryCertificates{NS_BLOCK} Id=\"nonintermediarycertificates\" soap:actor=\"http://www.w3.org/2001/12/soap-envelope/actor/none\" soap:mustUnderstand=\"1\">"
            )
            .as_bytes(),
        )
        .ok();
        for cert in &msg.non_intermediary_certificates {
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
    w.raw(b"</osci:ContentContainer>").ok();
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
            w.raw(b"\"></ds:DigestMethod>").ok();
        }
        w.raw(b"></xenc:EncryptionMethod><ds:KeyInfo>").ok();
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
