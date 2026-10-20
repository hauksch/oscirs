//! XML layer tests: parser normalization rules, writer escaping, and the
//! byte-exact port of `de.osci.helper.TestCanonizer`.

use osci_core::xml::c14n::{Canonicalization, canonicalize_str};
use osci_core::xml::parser::{self, XmlError};
use osci_core::xml::writer::{escape_attr, escape_text};

const OSCI2017: &str = "http://xoev.de/transport/osci12/7";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const OSCI: &str = "http://www.osci.de/2002/04/osci";
const SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

// ---------------------------------------------------------------- parser

#[test]
fn parses_names_text_and_attrs() {
    let doc =
        parser::parse(r#"<?xml version="1.0"?><a b="1"><c>Hello &amp; bye</c><c/></a>"#).unwrap();
    assert_eq!(doc.root.local, "a");
    assert_eq!(doc.root.attr("b"), Some("1"));
    let children: Vec<_> = doc.root.elements().collect();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0].text(), "Hello & bye");
    assert!(children[1].children.is_empty());
}

#[test]
fn normalizes_line_endings_in_text_and_cdata() {
    // CRLF and lone CR become LF (XML 2.11), in text and CDATA alike.
    let doc = parser::parse("<a>t1\r\nt2\rt3\nt4<![CDATA[c1\r\nc2]]></a>").unwrap();
    assert_eq!(doc.root.text(), "t1\nt2\nt3\nt4c1\nc2");
}

#[test]
fn attribute_whitespace_and_entities() {
    // Literal tab/LF/CR in attribute values become spaces; character
    // references survive.
    let doc = parser::parse("<a v=\"x\ty\nz\rw\" w=\"a&#xD;b&quot;c\"/>").unwrap();
    assert_eq!(doc.root.attr("v"), Some("x y z w"));
    assert_eq!(doc.root.attr("w"), Some("a\rb\"c"));
}

#[test]
fn character_references_in_text_survive() {
    let doc = parser::parse("<a>r&#xD;s&#x9;t</a>").unwrap();
    assert_eq!(doc.root.text(), "r\rs\tt");
}

#[test]
fn rejects_doctype() {
    // The XXE gate: ParserHelper disallows DOCTYPE declarations entirely.
    assert!(matches!(
        parser::parse("<!DOCTYPE a [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><a/>"),
        Err(XmlError::Doctype)
    ));
}

#[test]
fn parses_with_leading_bom() {
    // A BOM is legal XML; quick-xml's offsets skip it, which used to
    // desynchronize the prolog slice (char-boundary panic, found by the
    // xml_parse_is_total proptest).
    let doc = parser::parse("\u{feff}<a/>").unwrap();
    assert_eq!(doc.root.local, "a");
}

#[test]
fn rejects_unknown_entities() {
    assert!(parser::parse("<a>&unknown;</a>").is_err());
}

#[test]
fn rejects_malformed_documents() {
    assert!(parser::parse("<a></b>").is_err());
    assert!(parser::parse("<a><b></a></b>").is_err());
    assert!(parser::parse("<a b=\"1\" b=\"2\"/>").is_err());
    assert!(parser::parse("<a><b/></a><c/>").is_err());
    assert!(parser::parse("").is_err());
}

#[test]
fn rejects_unbound_prefixes() {
    assert!(matches!(
        parser::parse("<a><foo:b/></a>"),
        Err(XmlError::UnboundPrefix(_))
    ));
}

#[test]
fn comments_dropped_and_pis_captured() {
    let doc = parser::parse("<?target data?><a><!-- hi --><b/></a>").unwrap();
    assert_eq!(doc.pis_before_root, vec![("target".into(), "data".into())]);
    let text = doc.root.text();
    assert!(text.is_empty());
}

// ---------------------------------------------------------------- writer

#[test]
fn escaping_rules() {
    let mut text = Vec::new();
    escape_text("&<>\r\n\t", &mut text).unwrap();
    assert_eq!(text, b"&amp;&lt;&gt;&#xD;\n\t");

    let mut attr = Vec::new();
    escape_attr("&<>\"\t\n\r", &mut attr).unwrap();
    assert_eq!(attr, b"&amp;&lt;&gt;&quot;&#x9;&#xA;&#xD;");
}

#[test]
fn writer_emits_exact_prefixes_and_order() {
    use osci_core::xml::writer::XmlWriter;
    let mut buf = Vec::new();
    {
        let mut w = XmlWriter::new(&mut buf);
        w.write_decl().unwrap();
        w.raw(b"\n").unwrap();
        w.start(
            "soap:Envelope",
            &[("xmlns:soap", SOAP), ("xmlns:osci", OSCI)],
        )
        .unwrap();
        w.start("soap:Body", &[("Id", "body")]).unwrap();
        w.text("1 < 2 & 3").unwrap();
        w.end("soap:Body").unwrap();
        w.end("soap:Envelope").unwrap();
    }
    let s = String::from_utf8(buf).unwrap();
    assert_eq!(
        s,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<soap:Envelope xmlns:soap=\"{SOAP}\" xmlns:osci=\"{OSCI}\"><soap:Body Id=\"body\">1 &lt; 2 &amp; 3</soap:Body></soap:Envelope>"
        )
    );
    // what we write must round-trip through our own parser
    let doc = parser::parse(&s).unwrap();
    assert_eq!(doc.root.elements().next().unwrap().text(), "1 < 2 & 3");
}

// ------------------------------------------------------- TestCanonizer port

fn canon(xml: &str) -> Canonicalization {
    canonicalize_str(xml).unwrap_or_else(|e| panic!("canonicalization failed: {e}"))
}

/// Port of `TestCanonizer.testCanonizer`: namespace declarations are
/// sorted, empty elements expand.
#[test]
fn test_canonizer_namespaces_sorted() {
    let xml = format!(
        "<test xmlns:osci=\"{OSCI}\" xmlns:ds=\"{DS}\" xmlns:osci2017=\"{OSCI2017}\" xmlns:soap=\"{SOAP}\" xmlns:xenc=\"{XENC}\" xmlns:xsi=\"{XSI}\"></test>"
    );
    let expected = format!(
        "<test xmlns:ds=\"{DS}\" xmlns:osci=\"{OSCI}\" xmlns:osci2017=\"{OSCI2017}\" xmlns:soap=\"{SOAP}\" xmlns:xenc=\"{XENC}\" xmlns:xsi=\"{XSI}\"></test>"
    );
    assert_eq!(String::from_utf8(canon(&xml).bytes).unwrap(), expected);
}

/// Port of `TestCanonizer.testPartialStoreDelCanonizer`: attributes sort
/// after namespace declarations, redundant declarations are dropped,
/// self-closing elements expand.
#[test]
fn test_partial_store_delivery_canonizer() {
    let xml = format!(
        "<osci2017:partialStoreDelivery xmlns:ds=\"{DS}\" xmlns:osci=\"{OSCI}\" xmlns:osci2017=\"{OSCI2017}\" xmlns:soap=\"{SOAP}\" xmlns:xenc=\"{XENC}\" xmlns:xsi=\"{XSI}\" Id=\"partialstoredelivery\" soap:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" soap:mustUnderstand=\"1\"><osci:MessageId>dGVzdE1zZ1ByZWZpeDE0OTM5ODM0NjAzOTU3OTkyNjU2NDU0ODgwMjA4OTczX1BhcnRpYWw=</osci:MessageId><osci:Subject>MySubject</osci:Subject><osci2017:ChunkInformation xmlns:osci2017=\"{OSCI2017}\" ChunkNumber=\"1\" ChunkSize=\"115410\" TotalChunkNumbers=\"12\" TotalMessageSize=\"10240\"/></osci2017:partialStoreDelivery>"
    );
    let expected = format!(
        "<osci2017:partialStoreDelivery xmlns:ds=\"{DS}\" xmlns:osci=\"{OSCI}\" xmlns:osci2017=\"{OSCI2017}\" xmlns:soap=\"{SOAP}\" xmlns:xenc=\"{XENC}\" xmlns:xsi=\"{XSI}\" Id=\"partialstoredelivery\" soap:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" soap:mustUnderstand=\"1\"><osci:MessageId>dGVzdE1zZ1ByZWZpeDE0OTM5ODM0NjAzOTU3OTkyNjU2NDU0ODgwMjA4OTczX1BhcnRpYWw=</osci:MessageId><osci:Subject>MySubject</osci:Subject><osci2017:ChunkInformation ChunkNumber=\"1\" ChunkSize=\"115410\" TotalChunkNumbers=\"12\" TotalMessageSize=\"10240\"></osci2017:ChunkInformation></osci2017:partialStoreDelivery>"
    );
    assert_eq!(String::from_utf8(canon(&xml).bytes).unwrap(), expected);
}

/// Port of `TestCanonizer.testCustomHeader`.
#[test]
fn test_custom_header_canonizer() {
    let xml = format!(
        "<ch:RequestSignatureMandatory xmlns:ch=\"http://gov.bos-bremen.de/osci/customHeader\" xmlns:ds=\"{DS}\" xmlns:osci=\"{OSCI}\" xmlns:soap=\"{SOAP}\" xmlns:xenc=\"{XENC}\" xmlns:xsi=\"{XSI}\" Id=\"RequestSignatureMandatory\"></ch:RequestSignatureMandatory>"
    );
    let expected = xml.clone();
    assert_eq!(String::from_utf8(canon(&xml).bytes).unwrap(), expected);
}

// ------------------------------------------- signed elements & digest capture

/// Header entries and Body get all namespaces in scope re-declared, and
/// their canonical bytes are digested under `#Id`.
#[test]
fn signed_elements_inherit_namespaces_and_digest() {
    let xml = format!(
        "<soap:Envelope xmlns:soap=\"{SOAP}\" xmlns:osci=\"{OSCI}\"><soap:Header><osci:DesiredLanguages Id=\"dl\" languages=\"de\"/><osci:ControlBlock Id=\"cb\"><osci:Challenge>3q2+7w==</osci:Challenge></osci:ControlBlock></soap:Header><soap:Body Id=\"body\"><osci:FeedBack/></soap:Body></soap:Envelope>"
    );
    let result = canon(&xml);
    let expected = format!(
        "<osci:DesiredLanguages xmlns:osci=\"{OSCI}\" xmlns:soap=\"{SOAP}\" Id=\"dl\" languages=\"de\"></osci:DesiredLanguages>"
    );
    let digest = osci_crypto::algorithms::digest_bytes(
        "http://www.w3.org/2001/04/xmlenc#sha256",
        expected.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        result.digest_values.get("#dl"),
        Some(&digest),
        "header entry digest over its self-contained canonical form"
    );

    let body_expected = format!(
        "<soap:Body xmlns:osci=\"{OSCI}\" xmlns:soap=\"{SOAP}\" Id=\"body\"><osci:FeedBack></osci:FeedBack></soap:Body>"
    );
    assert_eq!(
        result.digest_values.get("#body"),
        Some(
            &osci_crypto::algorithms::digest_bytes(
                "http://www.w3.org/2001/04/xmlenc#sha256",
                body_expected.as_bytes(),
            )
            .unwrap()
        )
    );
}

/// A transport signature's SignedInfo captures its canonical bytes with
/// the inherited namespace block, and the control block digest is computed
/// with the digest method the signature declares.
#[test]
fn signed_info_capture_and_control_block_digest() {
    let xml = format!(
        "<soap:Envelope xmlns:soap=\"{SOAP}\" xmlns:osci=\"{OSCI}\" xmlns:ds=\"{DS}\"><soap:Header><osci:ControlBlock Id=\"controlblock\"><osci:Challenge>3q2+7w==</osci:Challenge></osci:ControlBlock><osci:ClientSignature Id=\"clientsignature\"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:Reference URI=\"#controlblock\"><ds:DigestMethod Algorithm=\"{DS}sha1\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo></ds:Signature></osci:ClientSignature></soap:Header></soap:Envelope>"
    );
    let result = canon(&xml);

    // one transport SignedInfo, in second position semantics: transport
    // signature present, so no None placeholder
    assert_eq!(result.signed_infos.len(), 1);
    let signed_info = result.signed_infos[0].as_ref().unwrap();
    let si = String::from_utf8(signed_info.clone()).unwrap();
    assert!(
        si.starts_with(&format!(
            "<ds:SignedInfo xmlns:ds=\"{DS}\" xmlns:osci=\"{OSCI}\" xmlns:soap=\"{SOAP}\">"
        )),
        "capture begins with the element and its injected namespaces: {si}"
    );
    assert!(si.ends_with("</ds:SignedInfo>"));

    // control block digest: sha1 over the canonical control block
    // (namespace-injected, self-contained)
    let cb_expected = format!(
        "<osci:ControlBlock xmlns:ds=\"{DS}\" xmlns:osci=\"{OSCI}\" xmlns:soap=\"{SOAP}\" Id=\"controlblock\"><osci:Challenge>3q2+7w==</osci:Challenge></osci:ControlBlock>"
    );
    let expected_digest = osci_crypto::algorithms::digest_bytes(
        "http://www.w3.org/2000/09/xmldsig#sha1",
        cb_expected.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        result.digest_values.get("#controlblock"),
        Some(&expected_digest)
    );

    // the injected namespace block must NOT appear in the document stream
    // copy of SignedInfo's start tag
    let doc = String::from_utf8(result.bytes).unwrap();
    assert!(
        !doc.contains(&format!("<ds:SignedInfo xmlns:ds=\"{DS}\"")),
        "document stream must not duplicate the injected namespaces: {doc}"
    );
}

/// The transport SignedInfo's DigestMethod selections drive the digest of
/// the referenced header entries (default SHA-256 otherwise).
#[test]
fn transport_digest_method_selection() {
    let xml = format!(
        "<soap:Envelope xmlns:soap=\"{SOAP}\" xmlns:osci=\"{OSCI}\" xmlns:ds=\"{DS}\"><soap:Header><osci:ClientSignature Id=\"clientsignature\"><ds:Signature><ds:SignedInfo><ds:Reference URI=\"#desiredlanguages\"><ds:DigestMethod Algorithm=\"{DS}sha1\"/></ds:Reference></ds:SignedInfo></ds:Signature></osci:ClientSignature><osci:DesiredLanguages Id=\"desiredlanguages\" languages=\"de\"/></soap:Header></soap:Envelope>"
    );
    // NB: the digest method is selected when the entry STARTS, so the
    // signature (and its DigestMethod declarations) must precede the
    // referenced entry - exactly the CanParser semantics.
    let result = canon(&xml);
    let expected = format!(
        "<osci:DesiredLanguages xmlns:ds=\"{DS}\" xmlns:osci=\"{OSCI}\" xmlns:soap=\"{SOAP}\" Id=\"desiredlanguages\" languages=\"de\"></osci:DesiredLanguages>"
    );
    assert_eq!(
        result.digest_values.get("#desiredlanguages"),
        Some(
            &osci_crypto::algorithms::digest_bytes(
                "http://www.w3.org/2000/09/xmldsig#sha1",
                expected.as_bytes(),
            )
            .unwrap()
        )
    );
}

/// Duplicate Ids are rejected (signature-wrapping defense).
#[test]
fn duplicate_ids_rejected() {
    let xml = format!(
        "<soap:Envelope xmlns:soap=\"{SOAP}\"><soap:Header><a xmlns=\"x\" Id=\"dup\"/><b xmlns=\"x\" Id=\"dup\"/></soap:Header></soap:Envelope>"
    );
    assert!(canonicalize_str(&xml).is_err());
}

/// C14N text rules: CR stays escaped, whitespace preserved verbatim.
#[test]
fn text_normalization_in_output() {
    let doc = parser::parse("<a>line1\n   line2&#xD;</a>").unwrap();
    let result = canonicalize_str("<a>line1\n   line2&#xD;</a>").unwrap();
    let _ = doc;
    assert_eq!(result.bytes, b"<a>line1\n   line2&#xD;</a>");
}
