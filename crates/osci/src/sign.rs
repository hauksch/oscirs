//! Transport-signature composition for outbound messages
//! (the signing side of `OSCISignature` / `ClientSignature`):
//! compose unsigned, canonicalize, build the ds:Signature block with
//! per-reference digests over the canonical regions, sign the canonical
//! SignedInfo bytes, and inject the completed ClientSignature header.

use osci_core::helper::base64;
use osci_core::xml::c14n::{canonicalize, digest_bytes};
use osci_core::xml::parser;
use osci_crypto::algorithms::{
    DEFAULT_DIGEST, DIGEST_SHA256, SIGNATURE_RSA_SHA1, SIGNATURE_RSA_SHA256_PSS,
};
use osci_crypto::software::Signer;

pub const C14N_TRANSFORM: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("xml: {0}")]
    Xml(String),
    #[error("canonicalization: {0}")]
    Canonicalization(String),
    #[error("signing: {0}")]
    Signing(String),
    #[error("no canonical region for {0}")]
    MissingRegion(String),
}

/// Signing parameters.
pub struct SignParams<'a> {
    pub signer: &'a dyn Signer,
    /// Signature method URI (default: RSA-PSS SHA-256).
    pub method: Option<String>,
    /// Digest method URI for references (default SHA-256).
    pub digest: Option<String>,
    /// Id of the certificate element the signature's KeyInfo references
    /// (must exist in the message, e.g. the originator signature cert of
    /// NonIntermediaryCertificates).
    pub certificate_id: String,
    /// Transfer-decoded attachments by content id (for cid: references).
    pub attachments: &'a [(String, Vec<u8>)],
}

/// Sign a composed (unsigned) message XML part: returns the XML with the
/// ClientSignature header injected after the ControlBlock.
pub fn sign_message_xml(xml: &str, params: &SignParams<'_>) -> Result<String, SignError> {
    let method = params
        .method
        .clone()
        .unwrap_or_else(|| SIGNATURE_RSA_SHA256_PSS.to_string());
    let digest = params
        .digest
        .clone()
        .unwrap_or_else(|| DIGEST_SHA256.to_string());

    let doc = parser::parse(xml).map_err(|e| SignError::Xml(e.to_string()))?;

    // reference list: control block ALWAYS (the reference library rejects
    // messages without it), then languages, quality timestamps, the
    // message entry, attachments, certificates and body where present
    let mut references = vec!["#controlblock".to_string()];
    for id in [
        "desiredlanguages",
        "qualityoftimestamp_creation",
        "qualityoftimestamp_reception",
    ] {
        references.push(format!("#{id}"));
    }
    if let Some(entry_id) = find_entry_id(&doc) {
        references.push(entry_id);
    }
    for (cid, _) in params.attachments {
        references.push(format!("cid:{cid}"));
    }
    references.push("#nonintermediarycertificates".to_string());
    references.push("#body".to_string());

    // pass 1: inject a placeholder signature so the canonicalizer sees a
    // SignedInfo referencing the control block (its canonical region only
    // materializes once a transport signature references it), then read
    // the digest inputs from the placeholder-signed document
    let placeholder = build_signature_xml(&references, &method, &digest, &[], params, true)?;
    let placeholder_doc_xml = inject_after_control_block(xml, &placeholder)?;
    let placeholder_doc =
        parser::parse(&placeholder_doc_xml).map_err(|e| SignError::Xml(e.to_string()))?;
    let placeholder_canon =
        canonicalize(&placeholder_doc).map_err(|e| SignError::Canonicalization(e.to_string()))?;
    let digest_inputs: Vec<(String, Vec<u8>)> = references
        .iter()
        .map(|uri| {
            let input: Vec<u8> = if let Some(region) = placeholder_canon.canonical_regions.get(uri)
            {
                region.clone()
            } else if let Some(cid) = uri.strip_prefix("cid:") {
                params
                    .attachments
                    .iter()
                    .find(|(id, _)| id == cid)
                    .map(|(_, data)| data.clone())
                    .ok_or_else(|| SignError::MissingRegion(uri.clone()))?
            } else {
                return Err(SignError::MissingRegion(uri.clone()));
            };
            Ok((uri.clone(), input))
        })
        .collect::<Result<_, _>>()?;

    // pass 2: real signature block, final canonicalization, sign
    let signature_xml =
        build_signature_xml(&references, &method, &digest, &digest_inputs, params, false)?;
    let injected = inject_after_control_block(xml, &signature_xml)?;

    let signed_doc = parser::parse(&injected).map_err(|e| SignError::Xml(e.to_string()))?;
    let signed_canon =
        canonicalize(&signed_doc).map_err(|e| SignError::Canonicalization(e.to_string()))?;
    let signed_info = signed_canon
        .signed_infos
        .iter()
        .find_map(|si| si.clone())
        .ok_or_else(|| SignError::Canonicalization("SignedInfo not captured".into()))?;

    let signature = params
        .signer
        .sign(&signed_info, &method)
        .map_err(|e| SignError::Signing(e.to_string()))?;

    let encoded = base64::encode(&signature);
    Ok(injected.replace(
        "<ds:SignatureValue>PHMBOLFU5fQ==</ds:SignatureValue>",
        &format!("<ds:SignatureValue>{encoded}</ds:SignatureValue>"),
    ))
}

fn build_signature_xml(
    references: &[String],
    method: &str,
    digest: &str,
    digest_inputs: &[(String, Vec<u8>)],
    params: &SignParams<'_>,
    placeholder: bool,
) -> Result<String, SignError> {
    let mut out = String::new();
    out.push_str("<osci:ClientSignature Id=\"clientsignature\" soap:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" soap:mustUnderstand=\"1\"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"");
    out.push_str(C14N_TRANSFORM);
    out.push_str("\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"");
    out.push_str(method);
    out.push_str("\"></ds:SignatureMethod>");
    for uri in references {
        let value = if placeholder {
            Vec::new()
        } else {
            digest_bytes(
                digest,
                &digest_inputs
                    .iter()
                    .find(|(u, _)| u == uri)
                    .ok_or_else(|| SignError::MissingRegion(uri.clone()))?
                    .1,
            )
            .ok_or_else(|| SignError::Signing(format!("digest {digest} unsupported")))?
        };
        out.push_str("<ds:Reference URI=\"");
        out.push_str(uri);
        out.push_str("\"><ds:Transforms><ds:Transform Algorithm=\"");
        out.push_str(C14N_TRANSFORM);
        out.push_str("\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"");
        out.push_str(digest);
        out.push_str("\"></ds:DigestMethod><ds:DigestValue>");
        out.push_str(&base64::encode(&value));
        out.push_str("</ds:DigestValue></ds:Reference>");
    }
    out.push_str("</ds:SignedInfo><ds:SignatureValue>PHMBOLFU5fQ==</ds:SignatureValue><ds:KeyInfo><ds:RetrievalMethod URI=\"#");
    out.push_str(&params.certificate_id);
    out.push_str("\"></ds:RetrievalMethod></ds:KeyInfo></ds:Signature></osci:ClientSignature>");
    Ok(out)
}

fn find_entry_id(doc: &osci_core::xml::Document) -> Option<String> {
    // the message entry element: any direct header child with an Id that
    // is not one of the fixed header ids

    let header = osci_core::soap::find_header(doc)?;
    let fixed = [
        "controlblock",
        "desiredlanguages",
        "qualityoftimestamp_creation",
        "qualityoftimestamp_reception",
        "nonintermediarycertificates",
        "intermediarycertificates",
        "featuredescription",
    ];
    for child in header.elements() {
        if let Some(id) = child.id_attr()
            && !fixed.contains(&id)
        {
            return Some(format!("#{id}"));
        }
    }
    None
}

fn inject_after_control_block(xml: &str, block: &str) -> Result<String, SignError> {
    // find the closing tag of the first ControlBlock element
    let close = "</osci:ControlBlock>";
    let Some(pos) = xml.find(close) else {
        return Err(SignError::Xml("no ControlBlock".into()));
    };
    let insert_at = pos + close.len();
    Ok(format!(
        "{}{}{}",
        &xml[..insert_at],
        block,
        &xml[insert_at..]
    ))
}

/// The default signature method of the 2005-era fixtures (kept for
/// cross-era verification tests).
pub const LEGACY_METHOD: &str = SIGNATURE_RSA_SHA1;
pub const DEFAULT_METHOD: &str = SIGNATURE_RSA_SHA256_PSS;
pub const DEFAULT_DIGEST_URI: &str = DEFAULT_DIGEST;
