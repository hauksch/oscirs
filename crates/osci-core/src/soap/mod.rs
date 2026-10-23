//! SOAP envelope headers of OSCI-Transport 1.2 messages
//! (port of `de.osci.osci12.soapheader`): typed model, parser over the
//! XML tree, and a composer reproducing the Java `writeXML` byte order
//! with the default prefixes (`soap`, `osci`, `ds`).

use std::collections::BTreeMap;

use crate::helper::base64;
use crate::xml::writer::{escape_attr, escape_text};
use crate::xml::{Document, Element, SOAP_ENVELOPE_NS};

pub const OSCI_NS: &str = "http://www.osci.de/2002/04/osci";
pub const OSCI2017_NS: &str = "http://xoev.de/transport/osci12/7";

pub const ACTOR_NEXT: &str = "http://schemas.xmlsoap.org/soap/actor/next";
pub const ACTOR_NONE: &str = "http://www.w3.org/2001/12/soap-envelope/actor/none";

/// Namespace declaration block of the Java `MessagePart.ns` constant
/// (ds, osci, soap, xenc, xsi - in this order).
pub const NS_BLOCK: &str = " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:osci=\"http://www.osci.de/2002/04/osci\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"";

/// `MessagePart.ns2017` (adds osci2017 after osci).
pub fn ns_block_2017() -> String {
    NS_BLOCK.replace(
        "xmlns:osci=\"http://www.osci.de/2002/04/osci\"",
        "xmlns:osci=\"http://www.osci.de/2002/04/osci\" xmlns:osci2017=\"http://xoev.de/transport/osci12/7\"",
    )
}

#[derive(Debug, thiserror::Error)]
pub enum SoapError {
    #[error("no SOAP envelope")]
    NoEnvelope,
    #[error("invalid header: {0}")]
    Invalid(String),
    #[error("unsupported certificate element {0}")]
    UnknownCertificate(String),
}

/// One parsed certificate entry of a certificate header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertEntry {
    pub id: String,
    pub der: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRole {
    Intermediary,
    Originator,
    Addressee,
    OtherReader,
    OtherAuthor,
}

impl CertRole {
    /// `CipherCertificateOriginator` -> (role, use)
    pub fn parse(element_name: &str) -> Option<(CertRole, CertUse)> {
        for use_name in ["Cipher", "Signature"] {
            let prefix = format!("{use_name}Certificate");
            if let Some(role) = element_name.strip_prefix(&prefix) {
                let role = match role {
                    "Intermediary" => CertRole::Intermediary,
                    "Originator" => CertRole::Originator,
                    "Addressee" => CertRole::Addressee,
                    "OtherReader" => CertRole::OtherReader,
                    "OtherAuthor" => CertRole::OtherAuthor,
                    _ => return None,
                };
                let use_ = if use_name == "Cipher" {
                    CertUse::Cipher
                } else {
                    CertUse::Signature
                };
                return Some((role, use_));
            }
        }
        None
    }

    pub fn element_name(&self, use_: CertUse) -> String {
        let use_name = match use_ {
            CertUse::Cipher => "Cipher",
            CertUse::Signature => "Signature",
        };
        let role = match self {
            CertRole::Intermediary => "Intermediary",
            CertRole::Originator => "Originator",
            CertRole::Addressee => "Addressee",
            CertRole::OtherReader => "OtherReader",
            CertRole::OtherAuthor => "OtherAuthor",
        };
        format!("{use_name}Certificate{role}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertUse {
    Cipher,
    Signature,
}

/// Position of a (use, role) certificate entry in the canonical
/// NonIntermediaryCertificates child sequence (issue #3, from the
/// NonIntermediaryCertificatesTemplate in order.xsd): cipher originator,
/// cipher other authors, cipher addressee, cipher other readers,
/// signature originator, signature other authors, signature addressee.
pub fn cert_order(use_: CertUse, role: CertRole) -> u8 {
    match (use_, role) {
        (CertUse::Cipher, CertRole::Originator) => 0,
        (CertUse::Cipher, CertRole::OtherAuthor) => 1,
        (CertUse::Cipher, CertRole::Addressee) => 2,
        (CertUse::Cipher, CertRole::OtherReader) => 3,
        (CertUse::Signature, CertRole::Originator) => 4,
        (CertUse::Signature, CertRole::OtherAuthor) => 5,
        (CertUse::Signature, CertRole::Addressee) => 6,
        // SignatureCertificateOtherReader does not exist in any schema;
        // Intermediary entries live in IntermediaryCertificates, never in
        // NonIntermediaryCertificates - both sort last
        _ => u8::MAX,
    }
}

/// Dialog state carried on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlBlock {
    pub conversation_id: Option<String>,
    pub sequence_number: Option<u32>,
    pub response: Option<String>,
    pub challenge: Option<String>,
}

impl ControlBlock {
    pub const REF_ID: &'static str = "controlblock";
}

/// Feature-negotiation header (OSCI 2017 namespace).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeatureDescription {
    pub chunk_message_timeout: Option<u64>,
    pub max_chunk_size: Option<u64>,
    pub max_message_size: Option<u64>,
    pub min_chunk_size: Option<u64>,
    /// (key, version) pairs of SupportedFeatures entries.
    pub features: Vec<(String, String)>,
}

impl FeatureDescription {
    pub const REF_ID: &'static str = "featuredescription";
}

/// A typed SOAP header entry.
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderEntry {
    ControlBlock(ControlBlock),
    DesiredLanguages {
        languages: String,
    },
    QualityOfTimestamp {
        service_reception: bool,
        quality_cryptographic: bool,
    },
    IntermediaryCertificates {
        cipher: Option<CertEntry>,
        signature: Option<CertEntry>,
    },
    NonIntermediaryCertificates {
        entries: Vec<(CertRole, CertUse, CertEntry)>,
    },
    FeatureDescription(FeatureDescription),
    /// Signature headers and message entries (parsed in later milestones);
    /// kept for completeness of header walking.
    Other {
        uri: String,
        local: String,
    },
    /// Custom extension header (raw XML passthrough, Id extracted).
    Custom {
        id: Option<String>,
    },
}

impl HeaderEntry {
    /// Reference Id of the entry for digest references (`#controlblock`,
    /// `#desiredlanguages`, ...), mirroring the Java id conventions.
    pub fn ref_id(&self) -> Option<String> {
        match self {
            Self::ControlBlock(_) => Some("controlblock".into()),
            Self::DesiredLanguages { .. } => Some("desiredlanguages".into()),
            Self::QualityOfTimestamp {
                service_reception, ..
            } => Some(format!(
                "qualityoftimestamp_{}",
                if *service_reception {
                    "reception"
                } else {
                    "creation"
                }
            )),
            Self::IntermediaryCertificates { .. } => Some("intermediarycertificates".into()),
            Self::NonIntermediaryCertificates { .. } => Some("nonintermediarycertificates".into()),
            Self::FeatureDescription(_) => Some("featuredescription".into()),
            Self::Custom { id } => id.clone(),
            Self::Other { .. } => None,
        }
    }
}

/// Resolve the namespace URI of an element, including its own
/// declarations.
fn element_uri(element: &Element, inherited: &crate::xml::NsBindings) -> Option<String> {
    crate::xml::resolve_prefix(
        &crate::xml::declared_bindings_plus(element, inherited),
        &element.prefix,
    )
    .map(str::to_string)
}

fn child_bindings(element: &Element, inherited: &crate::xml::NsBindings) -> crate::xml::NsBindings {
    crate::xml::declared_bindings_plus(element, inherited)
}

/// Locate the `soap:Header` element of a document.
pub fn find_header(doc: &Document) -> Option<&Element> {
    let root_bindings = child_bindings(&doc.root, &BTreeMap::new());
    doc.root.elements().find(|e| {
        e.local == "Header" && element_uri(e, &root_bindings).as_deref() == Some(SOAP_ENVELOPE_NS)
    })
}

/// Parse all header entries of a document.
pub fn parse_headers(doc: &Document) -> Result<Vec<HeaderEntry>, SoapError> {
    let header = find_header(doc).ok_or(SoapError::NoEnvelope)?;
    let mut out = Vec::new();
    let bindings = child_bindings(&doc.root, &BTreeMap::new());
    for child in header.elements() {
        let uri = element_uri(child, &bindings);
        out.push(parse_entry(child, uri.as_deref())?);
    }
    Ok(out)
}

fn parse_entry(element: &Element, uri: Option<&str>) -> Result<HeaderEntry, SoapError> {
    let local = element.local.as_str();
    match (uri, local) {
        (Some(OSCI_NS), "ControlBlock") => Ok(HeaderEntry::ControlBlock(ControlBlock {
            conversation_id: element.attr("ConversationId").map(str::to_string),
            sequence_number: element.attr("SequenceNumber").and_then(|v| v.parse().ok()),
            response: element
                .elements()
                .find(|e| e.local == "Response")
                .map(|e| e.text()),
            challenge: element
                .elements()
                .find(|e| e.local == "Challenge")
                .map(|e| e.text()),
        })),
        (Some(OSCI_NS), "DesiredLanguages") => Ok(HeaderEntry::DesiredLanguages {
            languages: element
                .attr("LanguagesList")
                .ok_or_else(|| SoapError::Invalid("DesiredLanguages without LanguagesList".into()))?
                .to_string(),
        }),
        (Some(OSCI_NS), "QualityOfTimestamp") => {
            let quality = element
                .attr("Quality")
                .ok_or_else(|| SoapError::Invalid("QualityOfTimestamp without Quality".into()))?;
            let service = element
                .attr("Service")
                .ok_or_else(|| SoapError::Invalid("QualityOfTimestamp without Service".into()))?;
            Ok(HeaderEntry::QualityOfTimestamp {
                quality_cryptographic: quality == "cryptographic",
                service_reception: service == "reception",
            })
        }
        (Some(OSCI_NS), "IntermediaryCertificates") => {
            let mut cipher = None;
            let mut signature = None;
            for child in element.elements() {
                let Some((role, use_)) = CertRole::parse(&child.local) else {
                    continue;
                };
                let entry = parse_cert_entry(child)?;
                match (role, use_) {
                    (CertRole::Intermediary, CertUse::Cipher) => cipher = Some(entry),
                    (CertRole::Intermediary, CertUse::Signature) => signature = Some(entry),
                    _ => {
                        return Err(SoapError::Invalid(
                            "non-intermediary cert in IntermediaryCertificates".into(),
                        ));
                    }
                }
            }
            Ok(HeaderEntry::IntermediaryCertificates { cipher, signature })
        }
        (Some(OSCI_NS), "NonIntermediaryCertificates") => {
            let mut entries = Vec::new();
            for child in element.elements() {
                if let Some((role, use_)) = CertRole::parse(&child.local) {
                    entries.push((role, use_, parse_cert_entry(child)?));
                }
            }
            Ok(HeaderEntry::NonIntermediaryCertificates { entries })
        }
        (Some(OSCI2017_NS), "FeatureDescription") => {
            let mut fd = FeatureDescription {
                chunk_message_timeout: element
                    .attr("ChunkMessageTimeout")
                    .and_then(|v| v.parse().ok()),
                max_chunk_size: element.attr("MaxChunkSize").and_then(|v| v.parse().ok()),
                max_message_size: element.attr("MaxMessageSize").and_then(|v| v.parse().ok()),
                min_chunk_size: element.attr("MinChunkSize").and_then(|v| v.parse().ok()),
                features: Vec::new(),
            };
            for supported in element.elements() {
                if supported.local == "SupportedFeatures" {
                    for feature in supported.elements() {
                        if feature.local == "Feature" {
                            fd.features.push((
                                feature.attr("Key").unwrap_or_default().to_string(),
                                feature.attr("Version").unwrap_or_default().to_string(),
                            ));
                        }
                    }
                }
            }
            Ok(HeaderEntry::FeatureDescription(fd))
        }
        (Some(OSCI_NS), "ClientSignature")
        | (Some(OSCI_NS), "SupplierSignature")
        | (Some(OSCI2017_NS), _)
            if local != "FeatureDescription" =>
        {
            Ok(HeaderEntry::Other {
                uri: uri.unwrap_or_default().to_string(),
                local: local.to_string(),
            })
        }
        _ => Ok(HeaderEntry::Custom {
            id: element.id_attr().map(str::to_string),
        }),
    }
}

fn parse_cert_entry(element: &Element) -> Result<CertEntry, SoapError> {
    let mut der = None;
    for child in element.elements() {
        if child.local == "X509Data" {
            for data in child.elements() {
                if data.local == "X509Certificate" {
                    der = Some(
                        base64::decode(data.text().trim())
                            .map_err(|e| SoapError::Invalid(format!("certificate base64: {e}")))?,
                    );
                }
            }
        }
    }
    Ok(CertEntry {
        id: element.id_attr().unwrap_or_default().to_string(),
        der: der.ok_or_else(|| SoapError::Invalid("no X509Certificate data".into()))?,
    })
}

// ------------------------------------------------------------------ compose

/// Compose with the Java `writeXML` conventions and default prefixes.
pub struct Composer<W: std::io::Write> {
    out: W,
}

impl<W: std::io::Write> Composer<W> {
    pub fn new(out: W) -> Self {
        Self { out }
    }

    pub fn header_entry(&mut self, entry: &HeaderEntry) -> std::io::Result<()> {
        match entry {
            HeaderEntry::ControlBlock(cb) => self.control_block(cb),
            HeaderEntry::DesiredLanguages { languages } => {
                write!(
                    self.out,
                    "<osci:DesiredLanguages{NS_BLOCK} Id=\"desiredlanguages\" LanguagesList=\""
                )?;
                escape_attr(languages, &mut self.out)?;
                write!(
                    self.out,
                    "\" soap:actor=\"{ACTOR_NEXT}\" soap:mustUnderstand=\"1\"></osci:DesiredLanguages>"
                )
            }
            HeaderEntry::QualityOfTimestamp {
                service_reception,
                quality_cryptographic,
            } => {
                let id = if *service_reception {
                    "qualityoftimestamp_reception"
                } else {
                    "qualityoftimestamp_creation"
                };
                let quality = if *quality_cryptographic {
                    "cryptographic"
                } else {
                    "plain"
                };
                let service = if *service_reception {
                    "reception"
                } else {
                    "creation"
                };
                write!(
                    self.out,
                    "<osci:QualityOfTimestamp{NS_BLOCK} Id=\"{id}\" Quality=\"{quality}\" Service=\"{service}\" soap:actor=\"{ACTOR_NEXT}\" soap:mustUnderstand=\"1\"></osci:QualityOfTimestamp>"
                )
            }
            HeaderEntry::IntermediaryCertificates { cipher, signature } => {
                write!(
                    self.out,
                    "<osci:IntermediaryCertificates{NS_BLOCK} Id=\"intermediarycertificates\" soap:actor=\"{ACTOR_NONE}\" soap:mustUnderstand=\"1\">"
                )?;
                if let Some(entry) = cipher {
                    self.cert_entry(CertRole::Intermediary, CertUse::Cipher, entry)?;
                }
                if let Some(entry) = signature {
                    self.cert_entry(CertRole::Intermediary, CertUse::Signature, entry)?;
                }
                write!(self.out, "</osci:IntermediaryCertificates>")
            }
            HeaderEntry::NonIntermediaryCertificates { entries } => {
                write!(
                    self.out,
                    "<osci:NonIntermediaryCertificates{NS_BLOCK} Id=\"nonintermediarycertificates\" soap:actor=\"{ACTOR_NONE}\" soap:mustUnderstand=\"1\">"
                )?;
                // canonical child sequence (issue #3), stable within a slot
                let mut ordered: Vec<&(CertRole, CertUse, CertEntry)> = entries.iter().collect();
                ordered.sort_by_key(|(role, use_, _)| cert_order(*use_, *role));
                for (role, use_, entry) in ordered {
                    self.cert_entry(*role, *use_, entry)?;
                }
                write!(self.out, "</osci:NonIntermediaryCertificates>")
            }
            HeaderEntry::FeatureDescription(fd) => self.feature_description(fd),
            HeaderEntry::Other { .. } | HeaderEntry::Custom { .. } => {
                Err(std::io::Error::other("entry type has no fixed composition"))
            }
        }
    }

    fn control_block(&mut self, cb: &ControlBlock) -> std::io::Result<()> {
        // Every value is escaped: on the wire these may originate from a
        // hostile peer (the dialog adopts challenge/response/conversation
        // id from responses) - unescaped interpolation would smuggle XML
        // into the next signed request.
        write!(self.out, "<osci:ControlBlock{NS_BLOCK}")?;
        if let Some(conversation_id) = &cb.conversation_id {
            write!(self.out, " ConversationId=\"")?;
            escape_attr(conversation_id, &mut self.out)?;
            write!(self.out, "\"")?;
        }
        write!(self.out, " Id=\"controlblock\"")?;
        if let Some(sequence) = cb.sequence_number {
            write!(self.out, " SequenceNumber=\"{sequence}\"")?;
        }
        write!(
            self.out,
            " soap:actor=\"{ACTOR_NEXT}\" soap:mustUnderstand=\"1\">"
        )?;
        if let Some(response) = &cb.response {
            write!(self.out, "<osci:Response>")?;
            escape_text(response, &mut self.out)?;
            write!(self.out, "</osci:Response>")?;
        }
        if let Some(challenge) = &cb.challenge {
            write!(self.out, "<osci:Challenge>")?;
            escape_text(challenge, &mut self.out)?;
            write!(self.out, "</osci:Challenge>")?;
        }
        write!(self.out, "</osci:ControlBlock>")
    }

    fn cert_entry(
        &mut self,
        role: CertRole,
        use_: CertUse,
        entry: &CertEntry,
    ) -> std::io::Result<()> {
        write!(self.out, "<osci:{} Id=\"", role.element_name(use_))?;
        escape_attr(&entry.id, &mut self.out)?;
        write!(self.out, "\"><ds:X509Data><ds:X509Certificate>")?;
        self.out.write_all(base64::encode(&entry.der).as_bytes())?;
        write!(
            self.out,
            "</ds:X509Certificate></ds:X509Data></osci:{}>",
            role.element_name(use_)
        )
    }

    /// Attribute order matters for signature verification (the Java code
    /// notes it deliberately writes lexicographic attribute order).
    fn feature_description(&mut self, fd: &FeatureDescription) -> std::io::Result<()> {
        let ns2017 = ns_block_2017();
        write!(self.out, "<osci2017:FeatureDescription{ns2017}")?;
        if let Some(timeout) = fd.chunk_message_timeout {
            write!(self.out, " ChunkMessageTimeout=\"{timeout}\"")?;
        }
        write!(self.out, " Id=\"featuredescription\"")?;
        if let Some(v) = fd.max_chunk_size {
            write!(self.out, " MaxChunkSize=\"{v}\"")?;
        }
        if let Some(v) = fd.max_message_size {
            write!(self.out, " MaxMessageSize=\"{v}\"")?;
        }
        if let Some(v) = fd.min_chunk_size {
            write!(self.out, " MinChunkSize=\"{v}\"")?;
        }
        write!(self.out, ">")?;
        // the 2017 EFFI schema: SupportedFeatures (with at least one
        // Feature) is mandatory inside FeatureDescription
        write!(self.out, "<osci2017:SupportedFeatures>")?;
        for (key, version) in &fd.features {
            write!(self.out, "<osci2017:Feature Key=\"")?;
            escape_attr(key, &mut self.out)?;
            write!(self.out, "\" Version=\"")?;
            escape_attr(version, &mut self.out)?;
            write!(self.out, "\"></osci2017:Feature>")?;
        }
        write!(self.out, "</osci2017:SupportedFeatures>")?;
        write!(self.out, "</osci2017:FeatureDescription>")
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}
