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
use std::io::Read as _;

use osci_core::helper::base64;
use osci_core::message::compose::{
    KeyInfoRef, KeyTransportParams, OutContentContainer, OutEncryptedData, OutEncryptedKey,
};
use osci_core::xml::c14n::{Canonicalization, canonicalize, digest_bytes};
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
    /// RSA/EC verification over the canonical SignedInfo bytes.
    pub signature_valid: bool,
    pub references: Vec<ReferenceResult>,
    /// Signing key facts and the weak-policy verdicts (Java
    /// `SignatureCheckResult`): `key_weak` per `TestCrypto.isWeakKey`,
    /// `algorithm_outdated` per the algorithm out-dating table. Both use
    /// the pinned reference date (the OSCI "actual date"), `None` when
    /// the key/algorithm could not be determined.
    pub key_algorithm: Option<String>,
    pub key_size_bits: Option<usize>,
    pub key_weak: Option<bool>,
    pub algorithm_outdated: Option<bool>,
}

impl SignatureResult {
    pub fn all_valid(&self) -> bool {
        self.signature_valid && self.references.iter().all(|r| r.checked != Some(false))
    }

    /// True when the signature verifies AND key and algorithm are
    /// known and not flagged weak/outdated.
    pub fn strong_and_valid(&self) -> bool {
        self.all_valid() && self.key_weak == Some(false) && self.algorithm_outdated == Some(false)
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
            key_algorithm: None,
            key_size_bits: None,
            key_weak: None,
            algorithm_outdated: None,
        };
        // weak-policy verdicts (report-only; Java pins the signature
        // date to the reference "actual date")
        result.algorithm_outdated = Some(osci_crypto::weak::is_weak_algorithm(
            Some(osci_crypto::weak::actual_date()),
            &result.method,
        ));
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
        result.key_algorithm = Some(cert.key_algorithm().to_string());
        result.key_size_bits = Some(cert.key_size());
        result.key_weak = Some(osci_crypto::weak::is_weak_key(
            Some(osci_crypto::weak::actual_date()),
            cert.key_algorithm(),
            cert.key_size(),
        ));
        result.signature_valid = match cert.key_kind() {
            osci_crypto::KeyKind::Rsa { .. } => cert
                .rsa_public_key()
                .ok()
                .and_then(|public| verify_rsa(&public, signed_info, &value, &result.method).ok())
                .is_some(),
            osci_crypto::KeyKind::Ec { .. } => match cert.ec_public_key() {
                Ok(osci_crypto::EcPublicKey::P256(key)) => {
                    osci_crypto::software::verify_ec_p256(&key, signed_info, &value, &result.method)
                        .is_ok()
                }
                Ok(osci_crypto::EcPublicKey::P384(key)) => {
                    osci_crypto::software::verify_ec_p384(&key, signed_info, &value, &result.method)
                        .is_ok()
                }
                Err(_) => false,
            },
        };

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
    let mgf = find_descendant_text(element, "MGF");
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

/// First descendant with `local`, returning its `Algorithm` attribute.
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

// ---------------------------------------------------------- encrypt side

/// Recipient of an outbound content encryption: cipher certificate plus
/// the Id of its certificate element in the message header (the
/// EncryptedKey references it via RetrievalMethod).
#[derive(Debug, Clone)]
pub struct EncRecipient {
    pub cert: osci_crypto::Certificate,
    pub cert_element_id: String,
}

/// Configuration of one outbound encryption (content or transport).
#[derive(Debug, Clone)]
pub struct EncryptConfig {
    pub content_cipher: String,
    pub key_transport: KeyTransportParams,
}

impl Default for EncryptConfig {
    fn default() -> Self {
        Self {
            content_cipher: osci_crypto::algorithms::DEFAULT_SYMMETRIC_CIPHER.to_string(),
            key_transport: KeyTransportParams::oaep_sha256(),
        }
    }
}

/// Generate the session key and wrap it for every recipient. Returns the
/// key plus one wrapped-key blob per recipient (same order).
fn session_key_with_wraps(
    config: &EncryptConfig,
    recipients: &[EncRecipient],
) -> Result<(Vec<u8>, Vec<Vec<u8>>), SecurityError> {
    let session_key = osci_crypto::calc::create_sym_key(&config.content_cipher)
        .map_err(|e| SecurityError::Decrypt(e.to_string()))?;
    let mut wraps = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let public = recipient
            .cert
            .rsa_public_key()
            .map_err(|e| SecurityError::Decrypt(e.to_string()))?;
        let wrapped = match config.key_transport.algorithm.as_str() {
            a if a == osci_crypto::algorithms::KEY_TRANSPORT_RSA_1_5 => {
                use osci_crypto::rsa::Pkcs1v15Encrypt;
                let mut rng = rand::thread_rng();
                public
                    .encrypt(&mut rng, Pkcs1v15Encrypt, &session_key)
                    .map_err(|e| SecurityError::Decrypt(e.to_string()))?
            }
            _ => {
                let digest = config
                    .key_transport
                    .digest
                    .as_deref()
                    .unwrap_or(osci_crypto::algorithms::DIGEST_SHA256);
                let mut rng = rand::thread_rng();
                wrap_oaep(&public, &session_key, digest, &mut rng)?
            }
        };
        wraps.push(wrapped);
    }
    Ok((session_key, wraps))
}

/// OAEP wrap with MGF1 = the same hash (Java 2.6.x convention), SHA-3
/// digests mapped to their SHA-2 counterparts.
fn wrap_oaep(
    public: &osci_crypto::rsa::RsaPublicKey,
    data: &[u8],
    digest_uri: &str,
    rng: &mut (impl rand::CryptoRng + rand::RngCore),
) -> Result<Vec<u8>, SecurityError> {
    use osci_crypto::rsa::Oaep;
    let digest = match digest_uri {
        osci_crypto::algorithms::DIGEST_SHA3_256 => osci_crypto::algorithms::DIGEST_SHA256,
        osci_crypto::algorithms::DIGEST_SHA3_384 | osci_crypto::algorithms::DIGEST_SHA3_512 => {
            osci_crypto::algorithms::DIGEST_SHA512
        }
        uri => uri,
    };
    let padding = match digest {
        osci_crypto::algorithms::DIGEST_SHA256 => Oaep::new::<osci_crypto::rsa::sha2::Sha256>(),
        osci_crypto::algorithms::DIGEST_SHA384 => Oaep::new::<osci_crypto::rsa::sha2::Sha384>(),
        osci_crypto::algorithms::DIGEST_SHA512 => Oaep::new::<osci_crypto::rsa::sha2::Sha512>(),
        other => {
            return Err(SecurityError::Decrypt(format!(
                "unsupported OAEP digest {other}"
            )));
        }
    };
    public
        .encrypt(rng, padding, data)
        .map_err(|e| SecurityError::Decrypt(e.to_string()))
}

/// Encrypt one inner ContentContainer for the given recipients (port of
/// `EncryptedDataOSCI.encrypt`): produces the composed `OutEncryptedData`
/// for `OutMessage::encrypted_data`. The container's plain writeXML bytes
/// are session-key encrypted (`[IV][ciphertext]`), the session key is
/// wrapped once per recipient.
///
/// `iv` pins the IV for deterministic tests; pass `None` in production.
pub fn encrypt_container(
    inner: &OutContentContainer,
    recipients: &[EncRecipient],
    config: &EncryptConfig,
    enc_id: Option<String>,
    iv: Option<&[u8]>,
) -> Result<OutEncryptedData, SecurityError> {
    let cipher = SymCipher::from_uri(&config.content_cipher).ok_or_else(|| {
        SecurityError::Decrypt(format!("unsupported cipher {}", config.content_cipher))
    })?;

    // plaintext = the container's plain writeXML bytes
    let mut plain = Vec::new();
    osci_core::message::compose::write_container_xml(
        inner,
        &mut osci_core::xml::writer::XmlWriter::new(&mut plain),
    );

    let iv_owned = match iv {
        Some(iv) => iv.to_vec(),
        None => osci_crypto::calc::create_iv(&config.content_cipher, None)
            .map_err(|e| SecurityError::Decrypt(e.to_string()))?,
    };
    let (session_key, wraps) = session_key_with_wraps(config, recipients)?;

    let ciphertext =
        osci_crypto::symcipher::oneshot::encrypt(cipher, &session_key, &iv_owned, &plain)
            .map_err(|e| SecurityError::Decrypt(e.to_string()))?;

    let recipients = recipients
        .iter()
        .zip(wraps)
        .map(|(r, wrapped)| OutEncryptedKey {
            key_transport: config.key_transport.clone(),
            key_info: KeyInfoRef::CertElementId(r.cert_element_id.clone()),
            wrapped_key: wrapped,
        })
        .collect();

    Ok(OutEncryptedData {
        id: enc_id,
        mime_type: Some("text/xml".into()),
        content_cipher: config.content_cipher.clone(),
        iv_len: iv_owned.len(),
        ciphertext,
        key_transport: config.key_transport.clone(),
        recipients,
        cipher_reference: None,
    })
}

/// Encrypt a complete signed MIME message for the intermediary-side
/// transport envelope (port of `SOAPMessageEncrypted`): returns the outer
/// MIME stream whose Body is a single `xenc:EncryptedData` with
/// `CipherReference URI="cid:osci_enc"` and whose second MIME part
/// carries `base64(IV || ciphertext)` of the inner stream.
pub fn encrypt_message_for(
    signed_stream: &[u8],
    recipient_cert: &osci_crypto::Certificate,
    config: &EncryptConfig,
    boundary: &str,
) -> Result<Vec<u8>, SecurityError> {
    let cipher = SymCipher::from_uri(&config.content_cipher).ok_or_else(|| {
        SecurityError::Decrypt(format!("unsupported cipher {}", config.content_cipher))
    })?;

    // session key + IV; encrypt the whole inner stream
    let session_key = osci_crypto::calc::create_sym_key(&config.content_cipher)
        .map_err(|e| SecurityError::Decrypt(e.to_string()))?;
    let mut iv = vec![0u8; 12];
    use rand::RngCore as _;
    rand::thread_rng().fill_bytes(&mut iv);
    // oneshot output is already [IV][ciphertext+tag]
    let framed = osci_crypto::symcipher::oneshot::encrypt(cipher, &session_key, &iv, signed_stream)
        .map_err(|e| SecurityError::Decrypt(e.to_string()))?;

    // EncryptedKey wraps the session key for the recipient; the recipient
    // certificate travels INLINE in the EncryptedKey (fixture parity).
    let wrapped = {
        let public = recipient_cert
            .rsa_public_key()
            .map_err(|e| SecurityError::Decrypt(e.to_string()))?;
        let digest = config
            .key_transport
            .digest
            .as_deref()
            .unwrap_or(osci_crypto::algorithms::DIGEST_SHA256);
        let mut rng = rand::thread_rng();
        match config.key_transport.algorithm.as_str() {
            a if a == osci_crypto::algorithms::KEY_TRANSPORT_RSA_1_5 => {
                use osci_crypto::rsa::Pkcs1v15Encrypt;
                public
                    .encrypt(&mut rng, Pkcs1v15Encrypt, &session_key)
                    .map_err(|e| SecurityError::Decrypt(e.to_string()))?
            }
            _ => wrap_oaep(&public, &session_key, digest, &mut rng)?,
        }
    };

    let cert_b64 = osci_core::helper::base64::encode(recipient_cert.der());

    // outer envelope per SOAPMessageEncrypted: Body holds exactly one
    // EncryptedData (no Id, MimeType Multipart/Related, inline cert,
    // CipherReference to cid:osci_enc). The content EncryptionMethod
    // carries the Korrigenda-7 IvLength hint whenever the IV is not the
    // legacy 16 bytes (parity with the content-encryption path).
    let iv_len_hint = if iv.len() != 16 {
        format!(
            "<osci128:IvLength xmlns:osci128=\"http://xoev.de/transport/osci12/8\" Value=\"{}\"></osci128:IvLength>",
            iv.len()
        )
    } else {
        String::new()
    };
    let outer_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>

<soap:Envelope xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://schemas.xmlsoap.org/soap/envelope/ soapMessageEncrypted.xsd http://www.w3.org/2000/09/xmldsig# oscisig.xsd http://www.w3.org/2001/04/xmlenc# oscienc.xsd"><soap:Body><xenc:EncryptedData MimeType="Multipart/Related"><xenc:EncryptionMethod Algorithm="{content_cipher}">{iv_len_hint}</xenc:EncryptionMethod><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="{key_transport}">{mgf_digest}</xenc:EncryptionMethod><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{wrapped_b64}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherReference URI="cid:osci_enc"><xenc:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"></ds:Transform></xenc:Transforms></xenc:CipherReference></xenc:CipherData></xenc:EncryptedData></soap:Body></soap:Envelope>"#,
        content_cipher = config.content_cipher,
        iv_len_hint = iv_len_hint,
        key_transport = config.key_transport.algorithm,
        mgf_digest = match (
            config.key_transport.mgf.as_deref(),
            config.key_transport.digest.as_deref(),
        ) {
            (Some(mgf), Some(digest)) => format!(
                "<xenc11:MGF xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"{mgf}\"></xenc11:MGF><ds:DigestMethod Algorithm=\"{digest}\"></ds:DigestMethod>"
            ),
            _ => String::new(),
        },
        cert_b64 = cert_b64,
        wrapped_b64 = osci_core::helper::base64::encode(&wrapped),
    );

    // MIME framing: XML part + RAW binary ciphertext part (Java 2.6.1
    // dialect: the octets of IV || ciphertext || tag, no base64, no line
    // breaking - written in one write_all so nothing mangles them).
    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "MIME-Version: 1.0\r\nContent-Type: Multipart/Related; boundary={boundary}; type=text/xml\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Type: text/xml; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <osci@message>\r\nContent-Length: {}\r\n\r\n",
            outer_xml.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(outer_xml.as_bytes());
    out.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\nContent-ID: <osci_enc>\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(&framed);
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(out)
}

/// Decrypt a transport-encrypted envelope: unwraps the session key with
/// the given decrypter, decrypts the `cid:osci_enc` part and returns the
/// inner (already signed) MIME stream.
pub fn decrypt_transport_message(
    stored: &StoredMessageLike<'_>,
    decrypters: &[&dyn Decrypter],
) -> Result<Vec<u8>, SecurityError> {
    // locate the transport EncryptedData: Body-level, CipherReference
    let xml = std::str::from_utf8(stored.xml()).map_err(|e| SecurityError::Xml(e.to_string()))?;
    let doc = parser::parse(xml).map_err(|e| SecurityError::Xml(e.to_string()))?;
    let mut encrypted = Vec::new();
    find_encrypted_data(&doc.root, &mut encrypted);
    let element = encrypted
        .first()
        .ok_or_else(|| SecurityError::Decrypt("no transport EncryptedData".into()))?;

    // methods: [0] content cipher, [1] key transport; MGF/digest recursive
    let mut methods = Vec::new();
    find_methods(element, &mut methods);
    let cipher_uri = methods
        .first()
        .and_then(|m| m.attr("Algorithm"))
        .ok_or_else(|| SecurityError::Decrypt("no EncryptionMethod".into()))?
        .to_string();
    let cipher = SymCipher::from_uri(&cipher_uri)
        .ok_or_else(|| SecurityError::Decrypt(format!("unsupported cipher {cipher_uri}")))?;
    let transport_uri = methods
        .get(1)
        .and_then(|m| m.attr("Algorithm"))
        .unwrap_or(KEY_TRANSPORT_RSA_1_5)
        .to_string();
    let mgf = find_descendant_text(element, "MGF");
    let oaep_digest = find_descendant_text(element, "DigestMethod");

    // wrapped key from the inline CipherValue, ciphertext from the
    // referenced MIME part
    let mut values = Vec::new();
    find_cipher_values(element, &mut values);
    let wrapped_key = values
        .first()
        .ok_or_else(|| SecurityError::Decrypt("missing wrapped key".into()))?;
    let reference = find_cipher_reference(element)
        .ok_or_else(|| SecurityError::Decrypt("no CipherReference".into()))?;
    let cid = reference
        .strip_prefix("cid:")
        .ok_or_else(|| SecurityError::Decrypt(format!("bad reference {reference}")))?;
    let content = stored
        .attachment(cid)
        .ok_or_else(|| SecurityError::Decrypt(format!("attachment {cid} not found")))?;

    // Dialect-aware ciphertext candidates: CTE-binary parts (Java 2.6.1)
    // and CTE-base64 parts (already decoded by StoredMessage::load) keep
    // the bytes as-is; legacy parts with base64 TEXT kept raw (CTE 7bit)
    // get decoded here. The GCM tag / CBC padding arbitrates.
    let mut candidates = vec![content.data.clone()];
    if let Ok(decoded) = osci_core::helper::base64::decode(&String::from_utf8_lossy(&content.data))
        && decoded != content.data
    {
        candidates.push(decoded);
    }

    for decrypter in decrypters {
        let session_key = match transport_uri.as_str() {
            KEY_TRANSPORT_RSA_1_5 => decrypter.decrypt_pkcs1v15(wrapped_key),
            _ => decrypter.decrypt_oaep(
                wrapped_key,
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

        // Full candidate first; legacy blobs can carry trailing bytes
        // after the PKCS#7 padding, so block-boundary truncations are
        // tried from the longest down (the GCM tag / padding arbitrates).
        for ciphertext in &candidates {
            let mut dr = match DecryptReader::new(&ciphertext[..], cipher, &session_key) {
                Ok(dr) => dr,
                Err(_) => continue,
            };
            let mut inner = Vec::new();
            if dr.read_to_end(&mut inner).is_ok()
                && !inner.is_empty()
                && (inner.starts_with(b"MIME-Version") || inner.starts_with(b"<?xml"))
            {
                return Ok(inner);
            }
        }

        // Legacy truncation fallback: for each base64-decoded candidate,
        // try CBC stream lengths from the longest block boundary down.
        // Only reached when the full-length attempts all failed.
        for ciphertext in candidates.iter().rev() {
            let blocks = ciphertext.len() / 16;
            for keep_blocks in (1..blocks).rev() {
                let ct = &ciphertext[..keep_blocks * 16];
                let mut dr = match DecryptReader::new(ct, cipher, &session_key) {
                    Ok(dr) => dr,
                    Err(_) => continue,
                };
                let mut inner = Vec::new();
                if dr.read_to_end(&mut inner).is_err() || inner.is_empty() {
                    continue;
                }
                if inner.starts_with(b"MIME-Version") || inner.starts_with(b"<?xml") {
                    return Ok(inner);
                }
            }
        }
    }
    Err(SecurityError::Decrypt(
        "no decrypter could open the transport envelope".into(),
    ))
}

/// Borrowing view over a loaded message for the decrypt helpers above.
pub struct StoredMessageLike<'a> {
    pub xml: &'a [u8],
    pub attachments: &'a [osci_core::message::stored::LoadedAttachment],
}

impl StoredMessageLike<'_> {
    pub fn xml(&self) -> &[u8] {
        self.xml
    }

    pub fn attachment(&self, cid: &str) -> Option<&osci_core::message::stored::LoadedAttachment> {
        self.attachments.iter().find(|a| a.content_id == cid)
    }
}

fn find_cipher_reference(element: &Element) -> Option<String> {
    for child in element.elements() {
        if child.local == "CipherReference" {
            return child.attr("URI").map(str::to_string);
        }
        if let Some(found) = find_cipher_reference(child) {
            return Some(found);
        }
    }
    None
}
