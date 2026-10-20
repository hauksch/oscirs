//! Post-review security regression tests: each test pins one of the
//! attack shapes or hardening behaviors introduced by the review-fix
//! pass (signature binding, control-block depth, fail-closed references,
//! parser depth cap, escaping).

use std::io::Read as _;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use osci::security::verify_message;

fn corpus() -> std::path::PathBuf {
    std::env::var_os("OSCI_CORPUS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(2)
                .unwrap()
                .join("testcorpus")
        })
}

fn cert_der(pem: &str) -> Vec<u8> {
    let dump = std::fs::read_to_string(corpus().join("certs").join(pem)).unwrap();
    let start = dump.find("-----BEGIN CERTIFICATE-----").unwrap();
    let after = &dump[start + 27..];
    let end = after.find("-----END CERTIFICATE-----").unwrap();
    let b64: String = after[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    osci_core::helper::base64::decode(&b64).unwrap()
}

/// Build a minimal signed two-signature message: a transport signature in
/// the header plus a content signature in the body, both keyed to the
/// same cert element - the material the wrapping attacks play against.
fn signed_two_signature_xml() -> String {
    format!(
        r##"<soap:Envelope xmlns:soap="{soap}" xmlns:osci="{osci}" xmlns:ds="{ds}"><soap:Header><osci:ControlBlock Id="controlblock" SequenceNumber="0" soap:actor="http://schemas.xmlsoap.org/soap/actor/next" soap:mustUnderstand="1"><osci:Challenge>aGFsbG8=</osci:Challenge></osci:ControlBlock><osci:ClientSignature Id="clientsignature" soap:actor="http://schemas.xmlsoap.org/soap/actor/next" soap:mustUnderstand="1"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod><ds:Reference URI="#controlblock"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>QUJDREVGRw==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>dHJhbnNwb3J0LXNpZw==</ds:SignatureValue><ds:KeyInfo><ds:RetrievalMethod URI="#signingcert"></ds:RetrievalMethod></ds:KeyInfo></ds:Signature></osci:ClientSignature></soap:Header><soap:Body Id="body"><osci:ContentPackage><osci:ContentContainer Id="cc"><ds:Signature><ds:SignedInfo><ds:Reference URI="#content1"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>Q09OVEVOVA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Y29udGVudC1zaWc=</ds:SignatureValue><ds:KeyInfo><ds:RetrievalMethod URI="#signingcert"></ds:RetrievalMethod></ds:KeyInfo></ds:Signature><osci:Content Id="content1"><osci:Base64Content Id="contentdata">aGVsbG8=</osci:Base64Content></osci:Content></osci:ContentContainer></osci:ContentPackage></soap:Body></soap:Envelope>"##,
        soap = "http://schemas.xmlsoap.org/soap/envelope/",
        osci = "http://www.osci.de/2002/04/osci",
        ds = "http://www.w3.org/2000/09/xmldsig#",
    )
}

/// A1a: stripping the transport SignedInfo must NOT make the remaining
/// signature pair with the content capture - the counts mismatch and the
/// verification errors instead of passing.
#[test]
fn signedinfo_stripping_forgery_rejected() {
    let xml = signed_two_signature_xml();
    // baseline: structure is consistent, verification runs
    let _ = verify_message(&xml, &[]).unwrap();

    // strip the transport signature entirely but keep a decoy SignedInfo
    // inside the header (the classic wrap: one signature, two captures of
    // the OLD pipeline). The new pipeline binds captures per signature:
    // one Signature element remains, so one capture slot - the decoy
    // SignedInfo is NOT captured and the decoy value cannot be verified
    // against the content capture.
    let stripped = xml.replace(
        "<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"#controlblock\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>QUJDREVGRw==</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        "<ds:SignedInfo><ds:Reference URI=\"#content1\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>Q09OVEVOVA==</ds:DigestValue></ds:Reference></ds:SignedInfo>",
    );
    assert_ne!(stripped, xml);
    let report = verify_message(&stripped, &[]).unwrap();
    // the transport signature's references now point at content it never
    // covered; it must not pass
    assert!(
        !report.all_valid(),
        "SignedInfo substitution was accepted: {report:#?}"
    );
}

/// A2: a forged empty ControlBlock nested inside another header entry
/// must not suppress that entry's digest region.
#[test]
fn nested_control_block_does_not_suppress_digests() {
    // desiredlanguages entry wrapping a fake ControlBlock, followed by
    // the real ControlBlock; the transport signature references both.
    let xml = format!(
        r##"<soap:Envelope xmlns:soap="{soap}" xmlns:osci="{osci}" xmlns:ds="{ds}"><soap:Header><osci:DesiredLanguages Id="desiredlanguages" languages="de"><osci:ControlBlock Id="fakeinner" SequenceNumber="9"><osci:Challenge>ZmFrZQ==</osci:Challenge></osci:ControlBlock></osci:DesiredLanguages><osci:ControlBlock Id="controlblock" SequenceNumber="0"><osci:Challenge>aGFsbG8=</osci:Challenge></osci:ControlBlock><osci:ClientSignature Id="clientsignature"><ds:Signature><ds:SignedInfo><ds:Reference URI="#desiredlanguages"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>REVG</ds:DigestValue></ds:Reference><ds:Reference URI="#controlblock"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>REVG</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>c2lnbw==</ds:SignatureValue></ds:Signature></osci:ClientSignature></soap:Header></soap:Envelope>"##,
        soap = "http://schemas.xmlsoap.org/soap/envelope/",
        osci = "http://www.osci.de/2002/04/osci",
        ds = "http://www.w3.org/2000/09/xmldsig#",
    );
    let doc = osci_core::xml::parser::parse(&xml).unwrap();
    let canon = osci_core::xml::c14n::canonicalize(&doc).unwrap();

    // the REAL control block (challenge aGFsbG8=) must own the canonical
    // region, and the desiredlanguages entry (containing the fake) must
    // still have its digest region present.
    let region = String::from_utf8(canon.canonical_regions["#controlblock"].clone()).unwrap();
    assert!(
        region.contains("aGFsbG8=") && !region.contains("ZmFrZQ=="),
        "real control block region owns the digest: {region}"
    );
    assert!(
        canon.canonical_regions.contains_key("#desiredlanguages"),
        "the entry hosting the nested fake lost its digest region"
    );
}

/// A3: an in-document reference whose target region is missing fails
/// closed (not skipped) - the suppressed-digest attack shape.
#[test]
fn missing_region_reference_fails_closed() {
    // transport-style reference to a header entry that carries no
    // digest-generating content (its region is absent by construction)
    let xml = format!(
        r##"<soap:Envelope xmlns:soap="{soap}" xmlns:osci="{osci}" xmlns:ds="{ds}"><soap:Header><osci:ControlBlock Id="controlblock" SequenceNumber="0"><osci:Challenge>aGFsbG8=</osci:Challenge></osci:ControlBlock><osci:ClientSignature Id="clientsignature"><ds:Signature><ds:SignedInfo><ds:Reference URI="#controlblock"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>QUJDREVGRw==</ds:DigestValue></ds:Reference><ds:Reference URI="#nonintermediarycertificates"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>REVG</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>c2lnbw==</ds:SignatureValue><ds:KeyInfo><ds:RetrievalMethod URI="#signingcert"></ds:RetrievalMethod></ds:KeyInfo></ds:Signature></osci:ClientSignature><osci:NonIntermediaryCertificatesWarrant Id="signingcert" xmlns:osci2="http://www.osci.de/2002/04/osci"><dsig:X509Data xmlns:dsig="{ds}"><dsig:X509Certificate>{cert}</dsig:X509Certificate></dsig:X509Data></osci:NonIntermediaryCertificatesWarrant></soap:Header></soap:Envelope>"##,
        soap = "http://schemas.xmlsoap.org/soap/envelope/",
        osci = "http://www.osci.de/2002/04/osci",
        ds = "http://www.w3.org/2000/09/xmldsig#",
        cert = B64.encode(cert_der("alice_signature_4096.pem")),
    );
    let report = verify_message(&xml, &[]).unwrap();
    let signature = &report.signatures[0];
    // the reference targets a transport-signed element (direct Header
    // child) whose region is missing - it must be checked-and-failed,
    // not skipped
    let nic = signature
        .references
        .iter()
        .find(|r| r.uri == "#nonintermediarycertificates")
        .expect("reference present");
    assert_eq!(nic.checked, Some(false), "missing region must fail closed");
    assert!(!report.all_valid());
}

/// A4: deeply nested XML is rejected with an error instead of crashing.
#[test]
fn deep_nesting_rejected() {
    let depth = 5000;
    let mut xml = String::with_capacity(depth * 4 + 16);
    xml.push_str("<a>");
    for _ in 0..depth {
        xml.push_str("<d>");
    }
    for _ in 0..depth {
        xml.push_str("</d>");
    }
    xml.push_str("</a>");
    let err = osci_core::xml::parser::parse(&xml).unwrap_err();
    assert!(
        err.to_string().contains("nesting"),
        "depth cap error, got: {err}"
    );
}

/// B: hostile control-block values adopted from a response cannot
/// smuggle XML into the next signed request - the ConversationId is
/// rejected outright (the schema types it as a number), everything else
/// is escaped.
#[test]
fn hostile_control_block_values_are_escaped() {
    use osci_core::message::MessageType;
    use osci_core::message::compose::{OutMessage, compose_message};
    use osci_core::soap::ControlBlock;

    let hostile = r#"x" soap:evil="1" /><osci:Evil/><!"#;

    // ConversationId: rejected before anything is written (issue #3
    // schema enforcement - osci:Number)
    let rejected = OutMessage {
        kind: Some(MessageType::GetMessageId),
        control_block: ControlBlock {
            conversation_id: Some(hostile.into()),
            sequence_number: Some(1),
            challenge: Some("Y2hhbGxlbmdl".into()),
            response: None,
        },
        ..Default::default()
    };
    let err = compose_message(&rejected, "MIME_boundary").unwrap_err();
    assert!(err.to_string().contains("must be a number"), "{err}");

    // Challenge: any string is schema-legal, so it must come out escaped
    let escaped = OutMessage {
        kind: Some(MessageType::GetMessageId),
        control_block: ControlBlock {
            conversation_id: Some("42".into()),
            sequence_number: Some(1),
            challenge: Some(hostile.into()),
            response: None,
        },
        ..Default::default()
    };
    let stream = compose_message(&escaped, "MIME_boundary").unwrap();
    let mut mime = osci_core::helper::mime::MimeParser::new(&stream[..]).unwrap();
    let mut part = mime.next_part().unwrap().unwrap();
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    let xml = String::from_utf8(xml).unwrap();

    // the hostile payload appears only escaped; no smuggled element
    // (the payload sits in element text now - the attribute layer is
    // covered by the numeric ConversationId rejection above)
    assert!(!xml.contains("<osci:Evil/>"), "XML smuggled: {xml}");
    assert!(xml.contains("&lt;"), "element-text escaping missing");

    // and it re-parses to the same value
    let doc = osci_core::xml::parser::parse(&xml).unwrap();
    let header = osci_core::soap::find_header(&doc).unwrap();
    let cb = header
        .elements()
        .find(|e| e.local == "ControlBlock")
        .unwrap();
    assert_eq!(
        cb.elements()
            .find(|e| e.local == "Challenge")
            .unwrap()
            .text(),
        hostile
    );
}

/// C7: GCM encrypt rejects non-12-byte IVs (the decrypt side only reads
/// 12; asymmetric acceptance produced unreadable output).
#[test]
fn gcm_encrypt_rejects_16_byte_iv() {
    use osci_crypto::algorithms::SymCipher;
    let mut sink = Vec::new();
    let err = osci_crypto::symcipher::EncryptWriter::new(
        &mut sink,
        SymCipher::AesGcm { key_len: 32 },
        &[7u8; 32],
        Some(&[0u8; 16]),
    )
    .map(|_| ())
    .unwrap_err();
    assert!(err.to_string().contains("only 12"), "{err}");
}

/// SwapBuffer: length() must not double-count the swapped prefix.
#[test]
fn swap_buffer_length_after_spill() {
    use std::io::Write as _;
    let mut sb = osci_core::helper::swap_buffer::SwapBuffer::with_limit(10);
    sb.output().unwrap().write_all(b"0123456789").unwrap();
    sb.output().unwrap().write_all(b"ABC").unwrap();
    assert!(sb.spill_path().is_some(), "must have spilled");
    assert_eq!(sb.length(), 13, "length after spill must be the true total");
    let mut read_back = Vec::new();
    sb.input().unwrap().read_to_end(&mut read_back).unwrap();
    assert_eq!(read_back, b"0123456789ABC");
}
