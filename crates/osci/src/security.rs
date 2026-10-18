//! Signature verification and decryption pipelines over parsed messages
//! (integration of the M2 canonicalizer, M3 crypto and the M5 model -
//! the `OSCISignature` / `EncryptedDataOSCI` role of the reference
//! library, verification and decryption side).
//!
//! Transport and content-container signatures verify over the canonical
//! `SignedInfo` bytes with the certificate each signature references via
//! `ds:RetrievalMethod`; every `ds:Reference` digest is checked against
//! the canonical region of its target (header entries, Body, control
//! block), the base64-decoded content of transformed references, or the
//! transfer-decoded attachment bytes of `cid:` references.

use std::collections::HashMap;

use osci_core::helper::base64;
use osci_core::xml::c14n::{Canonicalization, canonicalize, digest_bytes}; // digest_bytes used in reference checks
use osci_core::xml::parser;
use osci_core::xml::{Document, Element};
use osci_crypto::algorithms::{KEY_TRANSPORT_RSA_1_5, SymCipher};
use osci_crypto::software::{Decrypter, verify_rsa};
use osci_crypto::symcipher::DecryptReader;

pub const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const BASE64_TRANSFORM: &str = "http://www.w3.org/2000/09/xmldsig#base64";

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("xml: {0}")]
    Xml(String),
    #[error("canonicalization: {0}")]
    Canonicalization(String),
    #[error("no signature over the message")]
    NoSignatures,
    #[error("signature structure mismatch: {0}")]
    Structure(String),
    #[error("decryption: {0}")]
    Decrypt(String),
}

/// Result of one `ds:Reference` digest check.
#[derive(Debug, Clone)]
pub struct ReferenceResult {
    pub uri: String,
    pub algorithm: String,
    /// `None` when the target was not resolvable (external URLs,
    /// certificate elements verified separately, missing attachments).
    pub checked: Option<bool>,
}

/// Result of one signature (transport or content-container).
#[derive(Debug, Clone)]
pub struct SignatureResult {
    /// Id of the certificate element the signature's key refers to.
    pub certificate_id: Option<String>,
    pub method: String,
    /// RSA verification over the canonical SignedInfo bytes.
    pub signature_valid: bool,
    pub references: Vec<ReferenceResult>,
}

impl SignatureResult {
    pub fn all_valid(&self) -> bool {
        self.signature_valid && self.references.iter().all(|r| r.checked != Some(false))
    }
}

#[derive(Debug, Clone, Default)]
pub struct VerificationReport {
    pub signatures: Vec<SignatureResult>,
}

impl VerificationReport {
    pub fn all_valid(&self) -> bool {
        !self.signatures.is_empty() && self.signatures.iter().all(|s| s.all_valid())
    }
}

/// Decrypted content of one `xenc:EncryptedData` element.
#[derive(Debug, Clone)]
pub struct DecryptedContent {
    pub cipher_uri: String,
    pub plaintext: Vec<u8>,
}

/// Collect Id -> certificate for elements carrying X509Certificate data.
fn collect_certificates(element: &Element, out: &mut HashMap<String, osci_crypto::Certificate>) {
    for child in element.elements() {
        let mut cert_data = Vec::new();
        collect_x509(child, &mut cert_data);
        if let (Some(id), Some(der)) = (child.id_attr(), cert_data.first())
            && let Ok(cert) = osci_crypto::Certificate::from_der(der)
        {
            out.insert(id.to_string(), cert);
        }
        collect_certificates(child, out);
    }
}

fn collect_x509(element: &Element, out: &mut Vec<Vec<u8>>) {
    for child in element.elements() {
        if child.local == "X509Certificate"
            && let Ok(der) = base64::decode(child.text().trim())
        {
            out.push(der);
        }
        collect_x509(child, out);
    }
}

/// Signature elements in document order (internal carrier).
fn find_signatures<'a>(element: &'a Element, out: &mut Vec<SignatureView<'a>>) {
    for child in element.elements() {
        if child.local == "Signature" {
            out.push(SignatureView(child));
        }
        find_signatures(child, out);
    }
}

struct SignatureView<'a>(&'a Element);

impl SignatureView<'_> {
    fn attr(&self, name: &str) -> Option<String> {
        // RetrievalMethod sits inside ds:KeyInfo, SignatureMethod inside
        // ds:SignedInfo, SignatureValue next to SignedInfo: all nested,
        // none direct children of ds:Signature
        match name {
            "cert-id" => find_first_descendant(self.0, "RetrievalMethod")?
                .attr("URI")
                .and_then(|u| u.strip_prefix('#'))
                .map(str::to_string),
            "method" => find_first_descendant(self.0, "SignatureMethod")?
                .attr("Algorithm")
                .map(str::to_string),
            "value" => Some(find_first_descendant(self.0, "SignatureValue")?.text()),
            _ => None,
        }
    }

    fn references(&self) -> Vec<&Element> {
        find_first_descendant(self.0, "SignedInfo")
            .map(|si| si.elements().filter(|e| e.local == "Reference").collect())
            .unwrap_or_default()
    }
}

fn check_reference(
    reference: &Element,
    doc: &Document,
    canon: &Canonicalization,
    certs: &HashMap<String, osci_crypto::Certificate>,
    attachments: &[(String, Vec<u8>)],
) -> ReferenceResult {
    let uri = reference.attr("URI").unwrap_or_default().to_string();
    let algorithm = reference
        .elements()
        .find(|e| e.local == "DigestMethod")
        .and_then(|e| e.attr("Algorithm"))
        .unwrap_or_default()
        .to_string();
    let fail = |uri: String, algorithm: String| ReferenceResult {
        uri,
        algorithm,
        checked: Some(false),
    };
    let skip = |uri: String, algorithm: String| ReferenceResult {
        uri,
        algorithm,
        checked: None,
    };

    // Missing or malformed DigestValue: fail closed.
    let Some(expected) = reference
        .elements()
        .find(|e| e.local == "DigestValue")
        .map(|e| e.text())
        .and_then(|v| base64::decode(v.trim()).ok())
    else {
        return fail(uri, algorithm);
    };

    if let Some(id) = uri.strip_prefix('#') {
        // Digest the canonical region with THIS reference's declared
        // algorithm (the digest map picks its method at element start and
        // cannot see signatures appearing later in the document). An
        // unsupported algorithm fails closed.
        if let Some(region) = canon.canonical_regions.get(&uri) {
            return match digest_bytes(&algorithm, region) {
                Some(actual) => ReferenceResult {
                    uri,
                    algorithm,
                    checked: Some(actual == expected),
                },
                None => fail(uri, algorithm),
            };
        }
        if has_base64_transform(reference) {
            let Some(element) = doc.find_by_id(id) else {
                return fail(uri, algorithm); // target does not exist
            };
            let Ok(input) = base64::decode(element.text().trim()) else {
                return fail(uri, algorithm); // malformed base64 content
            };
            return match digest_bytes(&algorithm, &input) {
                Some(actual) => ReferenceResult {
                    uri,
                    algorithm,
                    checked: Some(actual == expected),
                },
                None => fail(uri, algorithm),
            };
        }
        // Skippable in-document classes (like the Java reference):
        // cert-element references (bound via RetrievalMethod), href-Content
        // references (attachment-backed, separately verified via their
        // cid: reference), and existing deep targets that carry a c14n
        // instead of a base64 transform (content-signature territory -
        // nested containers). Everything else in the document fails
        // closed: a transport-signed target without a canonical region is
        // the suppressed-digest attack shape, and a dangling reference
        // points at an element that should exist.
        let target = doc.find_by_id(id);
        let is_cert_ref = certs.contains_key(id);
        let is_href_content_ref = target
            .is_some_and(|element| element.local == "Content" && element.attr("href").is_some());
        if is_cert_ref || is_href_content_ref {
            return skip(uri, algorithm);
        }
        let Some(target) = target else {
            return fail(uri, algorithm); // dangling reference
        };
        let _ = target;
        if is_transport_signed_target(doc, id) {
            return fail(uri, algorithm); // suppressed digest region
        }
        return skip(uri, algorithm);
    }

    if let Some(cid) = uri.strip_prefix("cid:") {
        // Missing attachments fail closed.
        let Some(content) = attachments.iter().find(|(id, _)| id == cid) else {
            return fail(uri, algorithm);
        };
        return match digest_bytes(&algorithm, &content.1) {
            Some(actual) => ReferenceResult {
                uri,
                algorithm,
                checked: Some(actual == expected),
            },
            None => fail(uri, algorithm),
        };
    }

    // External URL references cannot be resolved offline - skipped, like
    // the Java reference.
    skip(uri, algorithm)
}

/// First descendant with the given local name, document order.
fn find_first_descendant<'a>(element: &'a Element, local: &str) -> Option<&'a Element> {
    for child in element.elements() {
        if child.local == local {
            return Some(child);
        }
        if let Some(found) = find_first_descendant(child, local) {
            return Some(found);
        }
    }
    None
}

/// Whether `id` belongs to a direct child of the SOAP Header or the Body -
/// the elements the transport signature covers via canonical regions.
fn is_transport_signed_target(doc: &Document, id: &str) -> bool {
    doc.root.elements().any(|top| {
        (top.local == "Header" || top.local == "Body")
            && top.elements().any(|e| e.id_attr() == Some(id))
    })
}

fn has_base64_transform(reference: &Element) -> bool {
    reference.elements().any(|e| {
        e.local == "Transforms"
            && e.elements()
                .any(|t| t.attr("Algorithm") == Some(BASE64_TRANSFORM))
    })
}

/// Verify all signatures of a message XML part. `attachments` carries
/// transfer-decoded attachment content by content id (without `cid:`).
pub fn verify_message(
    xml: &str,
    attachments: &[(String, Vec<u8>)],
) -> Result<VerificationReport, SecurityError> {
    let doc = parser::parse(xml).map_err(|e| SecurityError::Xml(e.to_string()))?;
    let canon = canonicalize(&doc).map_err(|e| SecurityError::Canonicalization(e.to_string()))?;
    verify_document(&doc, &canon, attachments)
}

/// Verification over an already-parsed and canonicalized document.
pub fn verify_document(
    doc: &Document,
    canon: &Canonicalization,
    attachments: &[(String, Vec<u8>)],
) -> Result<VerificationReport, SecurityError> {
    let mut certs: HashMap<String, osci_crypto::Certificate> = HashMap::new();
    collect_certificates(&doc.root, &mut certs);

    let mut views = Vec::new();
    find_signatures(&doc.root, &mut views);
    if views.is_empty() {
        return Err(SecurityError::NoSignatures);
    }
    // Strict pairing: every ds:Signature element gets exactly its own
    // canonical capture (A1). A mismatch means the document structure was
    // manipulated - fail loudly, never silently drop a signature.
    if views.len() != canon.signature_captures.len() {
        return Err(SecurityError::Structure(format!(
            "{} signature elements but {} canonical captures",
            views.len(),
            canon.signature_captures.len()
        )));
    }

    let mut signatures = Vec::new();
    for (view, signed_info) in views.iter().zip(&canon.signature_captures) {
        let mut result = SignatureResult {
            certificate_id: view.attr("cert-id"),
            method: view.attr("method").unwrap_or_default(),
            signature_valid: false,
            references: Vec::new(),
        };
        // A signature without a (gated) SignedInfo capture is unverifiable
        // and stays in the report as invalid.
        let Some(signed_info) = signed_info else {
            signatures.push(result);
            continue;
        };
        let Some(value) = view.attr("value").and_then(|v| base64::decode(&v).ok()) else {
            signatures.push(result);
            continue;
        };
        let cert = result
            .certificate_id
            .as_deref()
            .and_then(|id| certs.get(id));
        let Some(cert) = cert else {
            signatures.push(result);
            continue;
        };
        let Ok(public) = cert.rsa_public_key() else {
            signatures.push(result);
            continue;
        };
        result.signature_valid = verify_rsa(&public, signed_info, &value, &result.method).is_ok();

        for reference in view.references() {
            result
                .references
                .push(check_reference(reference, doc, canon, &certs, attachments));
        }
        signatures.push(result);
    }
    Ok(VerificationReport { signatures })
}

// ------------------------------------------------------------------ decrypt

/// Decrypt one `xenc:EncryptedData` element (by document order index)
/// trying each decrypter for the session-key unwrap.
pub fn decrypt_encrypted_data(
    xml: &str,
    index: usize,
    decrypters: &[&dyn Decrypter],
) -> Result<DecryptedContent, SecurityError> {
    let doc = parser::parse(xml).map_err(|e| SecurityError::Xml(e.to_string()))?;
    let mut encrypted = Vec::new();
    find_encrypted_data(&doc.root, &mut encrypted);
    let element = encrypted
        .get(index)
        .ok_or_else(|| SecurityError::Decrypt(format!("no EncryptedData #{index}")))?;
    decrypt_element(element, decrypters)
}

/// Decrypt every EncryptedData element, returning the successfully
/// decrypted ones.
pub fn decrypt_all_encrypted_data(
    xml: &str,
    decrypters: &[&dyn Decrypter],
) -> Result<Vec<DecryptedContent>, SecurityError> {
    let doc = parser::parse(xml).map_err(|e| SecurityError::Xml(e.to_string()))?;
    let mut encrypted = Vec::new();
    find_encrypted_data(&doc.root, &mut encrypted);
    let mut out = Vec::new();
    for element in encrypted {
        if let Ok(content) = decrypt_element(element, decrypters) {
            out.push(content);
        }
    }
    Ok(out)
}

fn find_encrypted_data<'a>(element: &'a Element, out: &mut Vec<&'a Element>) {
    for child in element.elements() {
        if child.local == "EncryptedData" {
            out.push(child);
        }
        find_encrypted_data(child, out);
    }
}

fn decrypt_element(
    element: &Element,
    decrypters: &[&dyn Decrypter],
) -> Result<DecryptedContent, SecurityError> {
    // methods: first = content cipher, second = key transport
    let mut methods = Vec::new();
    find_methods(element, &mut methods);
    let Some(cipher_uri) = methods.first().and_then(|m| m.attr("Algorithm")) else {
        return Err(SecurityError::Decrypt("no EncryptionMethod".into()));
    };
    let cipher_uri = cipher_uri.to_string();
    let Some(cipher) = SymCipher::from_uri(&cipher_uri) else {
        return Err(SecurityError::Decrypt(format!(
            "unsupported cipher {cipher_uri}"
        )));
    };
    let transport_uri = methods
        .get(1)
        .and_then(|m| m.attr("Algorithm"))
        .unwrap_or(KEY_TRANSPORT_RSA_1_5)
        .to_string();
    let mgf = element.elements().find_map(|e| {
        (e.local == "MGF").then(|| e.attr("Algorithm").unwrap_or_default().to_string())
    });
    let oaep_digest = find_descendant_text(element, "DigestMethod");

    let mut values = Vec::new();
    find_cipher_values(element, &mut values);
    if values.len() < 2 {
        return Err(SecurityError::Decrypt("missing CipherValue data".into()));
    }
    let wrapped_key = values[0].clone();
    let ciphertext = values[1].clone();

    for decrypter in decrypters {
        let session_key = match transport_uri.as_str() {
            KEY_TRANSPORT_RSA_1_5 => decrypter.decrypt_pkcs1v15(&wrapped_key),
            _ => decrypter.decrypt_oaep(
                &wrapped_key,
                mgf.as_deref()
                    .unwrap_or("http://www.w3.org/2009/xmlenc11#mgf1sha256"),
                oaep_digest
                    .as_deref()
                    .unwrap_or("http://www.w3.org/2001/04/xmlenc#sha256"),
            ),
        };
        let Ok(session_key) = session_key else {
            continue;
        };
        if session_key.len() != cipher.key_length() {
            continue;
        }
        let mut plaintext = Vec::new();
        let reader = DecryptReader::new(&ciphertext[..], cipher, &session_key);
        let ok = match reader {
            Ok(mut reader) => {
                use std::io::Read as _;
                reader.read_to_end(&mut plaintext).is_ok()
            }
            Err(_) => false,
        };
        if ok && !plaintext.is_empty() {
            return Ok(DecryptedContent {
                cipher_uri,
                plaintext,
            });
        }
    }
    Err(SecurityError::Decrypt(
        "no decrypter could unwrap the session key".into(),
    ))
}

fn find_methods<'a>(element: &'a Element, out: &mut Vec<&'a Element>) {
    for child in element.elements() {
        if child.local == "EncryptionMethod" {
            out.push(child);
        }
        find_methods(child, out);
    }
}

fn find_cipher_values(element: &Element, out: &mut Vec<Vec<u8>>) {
    for child in element.elements() {
        if child.local == "CipherValue"
            && let Ok(bytes) = base64::decode(child.text().trim())
        {
            out.push(bytes);
        }
        find_cipher_values(child, out);
    }
}

fn find_descendant_text(element: &Element, local: &str) -> Option<String> {
    for child in element.elements() {
        if child.local == local {
            return child.attr("Algorithm").map(str::to_string);
        }
        if let Some(found) = find_descendant_text(child, local) {
            return Some(found);
        }
    }
    None
}
