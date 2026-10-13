//! Restricted C14N 1.0 canonicalizer with inline digesting - a faithful
//! port of `de.osci.helper.CanParser` as driven through `Canonizer`.
//!
//! Differences from full W3C C14N 1.0 (all inherited from the Java
//! implementation and part of the OSCI wire contract):
//! - attributes sort by a `" prefix-key"` scheme where namespace
//!   declarations come first (by qname), then unprefixed attributes (by
//!   qname), then namespaced attributes (by namespace URI, then qname);
//! - redundant namespace declarations are suppressed, **except** on signed
//!   elements (SOAP header entries, Body, ContentContainer, SignedInfo,
//!   SignedProperties), where every namespace in scope is re-declared so
//!   the canonical form of that element is self-contained;
//! - the namespace block of `SignedInfo`/`SignedProperties` is appended
//!   only to the captured bytes, not to the document stream;
//! - processing instructions appear only at document level, joined by
//!   newlines; comments are dropped; CDATA becomes regular escaped text;
//! - empty elements always expand to `<x ...></x>`;
//! - text keeps its whitespace verbatim (line endings were normalized by
//!   the parser).
//!
//! While canonicalizing, the walk digests SOAP header entries and the Body
//! by their `Id`, captures canonical `SignedInfo` byte ranges (the input
//! to RSA signature verification), `SignedProperties` strings and
//! `ContentContainer` namespace strings.

use std::collections::{BTreeMap, HashMap, HashSet};

use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

use super::parser;
use super::writer::{escape_attr, escape_text};
use super::{Document, Element, Node, XMLDSIG_NS};
use super::{OSCI_NS, SOAP_ENVELOPE_NS};

pub const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const DIGEST_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
pub const DIGEST_RIPEMD160: &str = "http://www.w3.org/2001/04/xmlenc#ripemd160";
pub const DIGEST_SHA3_256: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";
pub const DIGEST_SHA3_384: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";
pub const DIGEST_SHA3_512: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

#[derive(Debug, thiserror::Error)]
pub enum C14nError {
    #[error(transparent)]
    Parse(#[from] parser::XmlError),
    #[error("canonicalization failed: {0}")]
    Malformed(String),
}

/// Products of one canonicalization run.
#[derive(Debug, Default)]
pub struct Canonicalization {
    /// Canonical form of the whole document.
    pub bytes: Vec<u8>,
    /// `#id` -> digest of the canonical form of the element with that Id
    /// (SOAP header entries and Body, plus the control block), computed
    /// with the digest method selected when the element started (Java
    /// parity, including its ordering quirks).
    pub digest_values: HashMap<String, Vec<u8>>,
    /// `#id` -> the canonical bytes of the signed element (header entries,
    /// Body, control block). Signature verification digests these with the
    /// algorithm each reference declares.
    pub canonical_regions: HashMap<String, Vec<u8>>,
    /// Canonical SignedInfo byte ranges in document order; `None` marks
    /// the transport-signature slot when a message carries none.
    /// Java-parity flat vector (every direct-child-of-a-Signature
    /// SignedInfo captured, placeholder for content-only signatures).
    pub signed_infos: Vec<Option<Vec<u8>>>,
    /// One capture slot per `ds:Signature` element in document order -
    /// the verification pipeline's securely-bound pairing. `None` when
    /// that signature carries no SignedInfo, or carries one that is not a
    /// direct child (decoys are never captured).
    pub signature_captures: Vec<Option<Vec<u8>>>,
    /// Canonical SignedProperties strings (content-container signatures).
    pub signed_properties: Vec<String>,
    /// Namespace attribute strings of ContentContainer elements.
    pub coco_ns: Vec<String>,
}

/// Canonicalize a whole document.
pub fn canonicalize(doc: &Document) -> Result<Canonicalization, C14nError> {
    canonicalize_with(doc, true)
}

pub fn canonicalize_with(doc: &Document, check_ids: bool) -> Result<Canonicalization, C14nError> {
    let mut walker = Walker {
        out: Vec::new(),
        captures: Vec::new(),
        ns_stack: vec![{
            let mut m = BTreeMap::new();
            m.insert("xmlns".to_string(), String::new());
            m
        }],
        element_depth: 0,
        inside_header: false,
        header_already_found: false,
        inside_transport_signed_info: false,
        inside_container_signature_props: false,
        current_transport_signature_ref: String::new(),
        transport_digest_methods: HashMap::new(),
        found_ref_ids: HashSet::new(),
        digest_values: HashMap::new(),
        canonical_regions: HashMap::new(),
        signed_infos: Vec::new(),
        signed_properties: Vec::new(),
        coco_ns: Vec::new(),
        soap_prefix: None,
        control_block: None,
        control_block_id: String::new(),
        current_id: None,
        digest_region: None,
        check_ids,
        signature_depths: Vec::new(),
        signature_captures: Vec::new(),
        gated_si: None,
    };

    // Document-level processing instructions.
    let mut is_first_pi = true;
    for (target, data) in doc.pis_before_root.iter().chain(&doc.pis_after_root) {
        if is_first_pi {
            walker.write_through(format!("<?{target} ").as_bytes());
            walker.write_pi_data(data);
            walker.write_through(b"?>\n");
            is_first_pi = false;
        } else {
            walker.write_through(b"\n<?");
            walker.write_through(target.as_bytes());
            walker.write_through(b" ");
            walker.write_pi_data(data);
            walker.write_through(b"?>");
        }
    }

    walker.element(&doc.root)?;
    Ok(Canonicalization {
        bytes: walker.out,
        digest_values: walker.digest_values,
        canonical_regions: walker.canonical_regions,
        signed_infos: walker.signed_infos,
        signature_captures: walker.signature_captures,
        signed_properties: walker.signed_properties,
        coco_ns: walker.coco_ns,
    })
}

/// Parse and canonicalize in one step.
pub fn canonicalize_str(input: &str) -> Result<Canonicalization, C14nError> {
    canonicalize(&parser::parse(input)?)
}

/// Digest algorithm selection by XML URI (the JCA_JCE_MAP equivalent).
/// Returns `None` for unsupported algorithm URIs.
pub fn digest_bytes(uri: &str, data: &[u8]) -> Option<Vec<u8>> {
    use sha2::Digest as _;
    match uri {
        DIGEST_SHA1 => Some(Sha1::digest(data).to_vec()),
        DIGEST_SHA256 => Some(Sha256::digest(data).to_vec()),
        DIGEST_SHA512 => Some(Sha512::digest(data).to_vec()),
        DIGEST_RIPEMD160 => Some(Ripemd160::digest(data).to_vec()),
        DIGEST_SHA3_256 => Some(Sha3_256::digest(data).to_vec()),
        DIGEST_SHA3_384 => Some(Sha3_384::digest(data).to_vec()),
        DIGEST_SHA3_512 => Some(Sha3_512::digest(data).to_vec()),
        _ => None,
    }
}

struct Walker {
    /// Canonical document stream.
    out: Vec<u8>,
    /// Active SplitWriter captures; writes go to `out` and all captures,
    /// `capture_only` writes go to the innermost capture only.
    captures: Vec<Vec<u8>>,
    /// sampleNSStack: effective prefix -> URI bindings.
    ns_stack: Vec<BTreeMap<String, String>>,
    element_depth: usize,
    inside_header: bool,
    header_already_found: bool,
    inside_transport_signed_info: bool,
    inside_container_signature_props: bool,
    current_transport_signature_ref: String,
    transport_digest_methods: HashMap<String, String>,
    found_ref_ids: HashSet<String>,
    digest_values: HashMap<String, Vec<u8>>,
    canonical_regions: HashMap<String, Vec<u8>>,
    signed_infos: Vec<Option<Vec<u8>>>,
    signed_properties: Vec<String>,
    coco_ns: Vec<String>,
    soap_prefix: Option<String>,
    control_block: Option<Vec<u8>>,
    control_block_id: String,
    current_id: Option<String>,
    /// (start offset in `out`, digest URI, key)
    digest_region: Option<(usize, String, String)>,
    check_ids: bool,
    /// Depths of open `ds:Signature` elements (document order).
    signature_depths: Vec<usize>,
    /// One capture slot per `ds:Signature` element in document order;
    /// `None` when that signature carries no (direct-child) SignedInfo.
    /// SignedInfo elements elsewhere in the document are NEVER captured,
    /// so decoys cannot shift the positional pairing.
    signature_captures: Vec<Option<Vec<u8>>>,
    /// Index into `signature_captures` while a gated SignedInfo is open.
    gated_si: Option<usize>,
}

impl Walker {
    fn write_through(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
        for capture in &mut self.captures {
            capture.extend_from_slice(bytes);
        }
    }

    fn capture_only(&mut self, bytes: &[u8]) {
        if let Some(capture) = self.captures.last_mut() {
            capture.extend_from_slice(bytes);
        }
    }

    fn start_capture(&mut self) {
        self.captures.push(Vec::new());
    }

    fn end_capture(&mut self) -> Vec<u8> {
        self.captures.pop().unwrap_or_default()
    }

    fn write_pi_data(&mut self, data: &str) {
        for c in data.chars() {
            match c {
                '\r' => self.write_through(b"&#xD;"),
                _ => {
                    let mut buf = [0u8; 4];
                    self.write_through(c.encode_utf8(&mut buf).as_bytes());
                }
            }
        }
    }

    fn write_attr(&mut self, key: &str, value: &str) {
        let name = &key[key.find(',').map(|i| i + 1).unwrap_or(0)..];
        let prefix = format!(" {name}=\"");
        self.write_through(prefix.as_bytes());
        let mut escaped = Vec::new();
        escape_attr(value, &mut escaped).expect("vec write");
        self.write_through(&escaped);
        self.write_through(b"\"");
    }

    fn soap_envelope_qname(&self, local: &str) -> String {
        format!("{}:{local}", self.soap_prefix.clone().unwrap_or_default())
    }

    fn is_osci_signature_header(
        &self,
        element: &Element,
        bindings: &BTreeMap<String, String>,
    ) -> bool {
        let uri = element_uri(element, bindings);
        uri.as_deref() == Some(OSCI_NS)
            && (element.local == "ClientSignature" || element.local == "SupplierSignature")
    }

    fn element(&mut self, element: &Element) -> Result<(), C14nError> {
        self.start_element(element)?;

        for child in &element.children {
            match child {
                Node::Element(e) => self.element(e)?,
                Node::Text(t) => {
                    let mut escaped = Vec::new();
                    escape_text(t, &mut escaped).expect("vec write");
                    self.write_through(&escaped);
                }
            }
        }

        self.end_element(element)?;
        Ok(())
    }

    fn start_element(&mut self, element: &Element) -> Result<(), C14nError> {
        let qname = element.qname();

        // Duplicate Id check.
        if let Some(id) = element.id_attr()
            && !self.found_ref_ids.insert(format!("#{id}"))
            && self.check_ids
        {
            return Err(C14nError::Malformed(format!("duplicate Id found: #{id}")));
        }

        let mut signed_element = false;
        let mut read_ns = false;

        let parent_bindings = self.ns_stack.last().cloned().unwrap_or_default();
        self.element_depth += 1;

        // SOAP namespace prefix detection (first element declaring the
        // envelope URI; bug-compatible prefix extraction - "xmlns" without
        // a colon yields the whole attr name as "prefix").
        if self.soap_prefix.is_none() {
            let mut found: Option<String> = None;
            for (k, v) in &element.attrs {
                if v == SOAP_ENVELOPE_NS {
                    if found.is_some() {
                        return Err(C14nError::Malformed(
                            "multiple SOAP envelope namespace declarations".into(),
                        ));
                    }
                    let prefix = match k.find(':') {
                        Some(i) => k[i + 1..].to_string(),
                        None => k.clone(),
                    };
                    found = Some(prefix);
                }
            }
            self.soap_prefix = Some(found.unwrap_or_default());
        }

        // Track ds:Signature elements: each gets a capture slot, and only
        // their direct-child SignedInfos are captured (A1).
        let sig_element = element.local == "Signature"
            && element_uri(element, &parent_bindings).as_deref() == Some(XMLDSIG_NS);
        if sig_element {
            self.signature_captures.push(None);
            self.signature_depths.push(self.element_depth);
        }

        if qname == self.soap_envelope_qname("Header") {
            if !self.header_already_found {
                self.inside_header = true;
                self.header_already_found = true;
            } else {
                return Err(C14nError::Malformed("duplicate SOAP Header".into()));
            }
        } else if self.inside_header && self.element_depth == 3 && element.local == "ControlBlock" {
            signed_element = true;
            self.control_block_id = format!("#{}", element.id_attr().unwrap_or_default());
            self.start_capture();
        } else if (self.inside_header
            && self.element_depth == 3
            && !self.is_osci_signature_header(element, &parent_bindings))
            || (self.element_depth == 2 && qname == self.soap_envelope_qname("Body"))
        {
            let id = element.id_attr().map(str::to_string);
            let key = format!("#{}", id.clone().unwrap_or_default());
            let algo = self
                .transport_digest_methods
                .get(&key)
                .cloned()
                .unwrap_or_else(|| DIGEST_SHA256.to_string());
            signed_element = true;
            self.current_id = id;
            // Digest region opens before the start tag is written, like
            // outs.on(true) in the Java handler.
            self.digest_region = Some((self.out.len(), algo, key));
        } else if element.local == "SignedInfo"
            || (!self.inside_header && element.local == "SignedProperties")
        {
            signed_element = true;
            read_ns = true;
            // A1: gate SignedInfo captures to direct children of a
            // ds:Signature element - decoy or stripped SignedInfos
            // elsewhere in the document never get a capture slot.
            let gated_si = element.local == "SignedInfo"
                && self.signature_depths.last() == Some(&(self.element_depth - 1));
            if gated_si {
                self.gated_si = Some(self.signature_captures.len() - 1);
                self.start_capture();
                if self.inside_header {
                    self.inside_transport_signed_info = true;
                }
            } else if element.local == "SignedProperties" {
                self.start_capture();
                self.inside_container_signature_props = true;
            }
        } else if self.inside_transport_signed_info {
            if element.local == "Reference" {
                self.current_transport_signature_ref =
                    element.attr("URI").unwrap_or_default().to_string();
            } else if element.local == "DigestMethod" {
                self.transport_digest_methods.insert(
                    self.current_transport_signature_ref.clone(),
                    element.attr("Algorithm").unwrap_or_default().to_string(),
                );
            }
        } else if element.local == "ContentContainer" {
            signed_element = true;
            read_ns = true;
        }

        // Attribute collection: xmlns declarations first (so later
        // attributes can resolve their prefixes against this element's own
        // bindings, like the pre-resolved SAX attributes), then the rest.
        let mut sample_map = parent_bindings.clone();
        let mut out_map: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &element.attrs {
            if k.starts_with("xmlns:") || k == "xmlns" {
                let redundant = sample_map.get(k) == Some(v);
                if !redundant {
                    out_map.insert(format!(" ,{k}"), v.clone());
                }
                sample_map.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in &element.attrs {
            if k.starts_with("xmlns:") || k == "xmlns" {
                continue;
            }
            if let Some((prefix, _)) = k.split_once(':') {
                // bindings are keyed by declaration qname (xmlns:foo)
                match sample_map.get(&format!("xmlns:{prefix}")) {
                    Some(uri) => out_map.insert(format!("{uri},{k}"), v.clone()),
                    // unbound prefix: the parser already rejects this
                    None => out_map.insert(format!(",{k}"), v.clone()),
                };
            } else {
                out_map.insert(format!(",{k}"), v.clone());
            }
        }
        self.ns_stack.push(sample_map.clone());

        let tmp_map = if read_ns {
            std::mem::take(&mut out_map)
        } else {
            BTreeMap::new()
        };

        self.write_through(b"<");
        self.write_through(qname.as_bytes());

        if signed_element {
            for (k, v) in &sample_map {
                if !v.is_empty() {
                    out_map.insert(format!(" ,{k}"), v.clone());
                }
            }
        }

        if read_ns {
            // The namespace block of read-NS elements goes to the capture
            // (SignedInfo / SignedProperties) or the cocoNS list
            // (ContentContainer) - never into the document stream.
            let mut block = Vec::new();
            for (k, v) in &out_map {
                let name = &k[k.find(',').map(|i| i + 1).unwrap_or(0)..];
                block.extend_from_slice(format!(" {name}=\"").as_bytes());
                escape_attr(v, &mut block).expect("vec write");
                block.extend_from_slice(b"\"");
            }
            out_map = tmp_map;
            if self.gated_si.is_some() || self.inside_container_signature_props {
                self.capture_only(&block);
            } else {
                self.coco_ns
                    .push(String::from_utf8_lossy(&block).into_owned());
            }
        }

        for (k, v) in &out_map {
            self.write_attr(k, v);
        }
        self.write_through(b">");

        Ok(())
    }

    fn end_element(&mut self, element: &Element) -> Result<(), C14nError> {
        let qname = element.qname();
        self.element_depth -= 1;
        self.write_through(b"</");
        self.write_through(qname.as_bytes());
        self.write_through(b">");

        if element.local == "SignedInfo" {
            if let Some(sig_idx) = self.gated_si.take() {
                // Java-parity placeholder: when the first captured
                // SignedInfo is content-level, the transport slot is
                // recorded as absent (matching the reference's vector).
                if !self.inside_header && self.signed_infos.is_empty() {
                    self.signed_infos.push(None);
                }
                let captured = self.end_capture();
                self.signed_infos.push(Some(captured.clone()));
                self.signature_captures[sig_idx] = Some(captured);
                if self.inside_transport_signed_info {
                    self.inside_transport_signed_info = false;
                    if let Some(algo) = self.transport_digest_methods.get(&self.control_block_id) {
                        let algo = algo.clone();
                        let bytes = self.control_block.clone().unwrap_or_default();
                        if self.digest_values.contains_key(&self.control_block_id) {
                            return Err(C14nError::Malformed(format!(
                                "duplicate digest entry {}",
                                self.control_block_id
                            )));
                        }
                        if let Some(value) = digest_bytes(&algo, &bytes) {
                            self.digest_values
                                .insert(self.control_block_id.clone(), value);
                        }
                        self.canonical_regions
                            .insert(self.control_block_id.clone(), bytes);
                    }
                }
            }
            // Ungated SignedInfo (decoy): output already written, no
            // capture - it cannot shift the verification pairing.
        } else if self.inside_container_signature_props && element.local == "SignedProperties" {
            let captured = self.end_capture();
            self.signed_properties
                .push(String::from_utf8_lossy(&captured).into_owned());
            self.inside_container_signature_props = false;
        } else if self.inside_header && self.element_depth == 2 && element.local == "ControlBlock" {
            self.control_block = Some(self.end_capture());
            self.current_id = None;
        } else if (self.inside_header
            && self.element_depth == 2
            && !self.is_osci_signature_header(
                element,
                &self.ns_stack.last().cloned().unwrap_or_default(),
            ))
            || (self.element_depth == 1 && qname == self.soap_envelope_qname("Body"))
        {
            if let Some((start, algo, key)) = self.digest_region.take()
                && self.current_id.is_some()
            {
                if self.digest_values.contains_key(&key) {
                    return Err(C14nError::Malformed(format!(
                        "duplicate digest entry {key}"
                    )));
                }
                if let Some(value) = digest_bytes(&algo, &self.out[start..]) {
                    self.digest_values.insert(key.clone(), value);
                }
                self.canonical_regions
                    .insert(key, self.out[start..].to_vec());
            }
            self.current_id = None;
        }

        // Pop the signature tracking while the element's own bindings are
        // still on the stack (needed to resolve its prefix).
        let sig_element = element.local == "Signature"
            && element_uri(element, self.ns_stack.last().unwrap_or(&BTreeMap::new())).as_deref()
                == Some(XMLDSIG_NS);
        if sig_element {
            self.signature_depths.pop();
        }

        self.ns_stack.pop();

        if qname == self.soap_envelope_qname("Header") {
            self.inside_header = false;
        }
        Ok(())
    }
}

fn element_uri(element: &Element, bindings: &BTreeMap<String, String>) -> Option<String> {
    if element.prefix.is_empty() {
        return bindings.get("xmlns").cloned();
    }
    bindings.get(&format!("xmlns:{}", element.prefix)).cloned()
}
