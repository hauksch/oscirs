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
    /// The wrapping OSCI header element: `ClientSignature` (requests,
    /// default) or `SupplierSignature` (responses - the soapResponseTo
    /// schemas only accept the supplier slot).
    pub header_element: Option<&'a str>,
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

    // pass 1: a MINIMAL placeholder signature materializes the control
    // block's canonical region (it only appears once a transport
    // SignedInfo references it); every other region is produced
    // regardless of signatures
    let minimal = vec!["#controlblock".to_string(), "#body".to_string()];
    let minimal_xml = build_signature_xml(&minimal, &method, &digest, &[], params, true)?;
    let minimal_doc_xml = inject_after_control_block(xml, &minimal_xml)?;
    let minimal_doc = parser::parse(&minimal_doc_xml).map_err(|e| SignError::Xml(e.to_string()))?;
    let placeholder_canon =
        canonicalize(&minimal_doc).map_err(|e| SignError::Canonicalization(e.to_string()))?;

    // reference list: control block ALWAYS (the reference library rejects
    // messages without it); everything else only when its region exists
    let mut references = vec!["#controlblock".to_string()];
    for id in [
        "desiredlanguages",
        "qualityoftimestamp_creation",
        "qualityoftimestamp_reception",
    ] {
        if placeholder_canon
            .canonical_regions
            .contains_key(&format!("#{id}"))
        {
            references.push(format!("#{id}"));
        }
    }
    if let Some(entry_id) = find_entry_id(&doc)
        && placeholder_canon.canonical_regions.contains_key(&entry_id)
    {
        references.push(entry_id);
    }
    for (cid, _) in params.attachments {
        references.push(format!("cid:{cid}"));
    }
    if placeholder_canon
        .canonical_regions
        .contains_key("#nonintermediarycertificates")
    {
        references.push("#nonintermediarycertificates".to_string());
    }
    if placeholder_canon.canonical_regions.contains_key("#body") {
        references.push("#body".to_string());
    }
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
    // single occurrence: the placeholder is written by this function and
    // must be unique in the document
    let replaced = injected.replacen(
        "<ds:SignatureValue>PHMBOLFU5fQ==</ds:SignatureValue>",
        &format!("<ds:SignatureValue>{encoded}</ds:SignatureValue>"),
        1,
    );
    if replaced == injected {
        return Err(SignError::Signing("placeholder not found".into()));
    }
    Ok(replaced)
}

fn build_signature_xml(
    references: &[String],
    method: &str,
    digest: &str,
    digest_inputs: &[(String, Vec<u8>)],
    params: &SignParams<'_>,
    placeholder: bool,
) -> Result<String, SignError> {
    let header_element = params.header_element.unwrap_or("ClientSignature");
    let id = header_element.to_lowercase();
    let mut out = String::new();
    out.push_str(&format!(
        "<osci:{header_element} Id=\"{id}\" soap:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" soap:mustUnderstand=\"1\"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\""
    ));
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
    out.push_str("\"></ds:RetrievalMethod></ds:KeyInfo></ds:Signature></osci:");
    out.push_str(header_element);
    out.push('>');
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
