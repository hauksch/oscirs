//! M2 gate: canonicalize the golden corpus and verify the `ds:Reference`
//! digests against the `DigestValue` bytes recorded in each fixture - real
//! signed data as ground truth for the canonicalizer.
//!
//! Verifiable reference classes:
//! - `#id` of SOAP header entries, the message entry and the Body via the
//!   digest map computed during canonicalization,
//! - `#id` with the xmldsig base64 transform (Base64Content elements):
//!   digest of the decoded element text,
//! - `cid:` attachments: digest of the transfer-decoded MIME part content.
//!
//! Out of scope here (verified in the signature milestone): references to
//! certificate elements inside the certificate header entries and external
//! URLs.

mod common;

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use osci_core::helper::base64;
use osci_core::helper::mime::MimeParser;
use osci_core::xml::c14n::{Canonicalization, canonicalize, digest_bytes};
use osci_core::xml::parser;
use osci_core::xml::{Document, Element};

struct Fixture {
    xml: String,
    attachments: HashMap<String, Vec<u8>>,
}

/// Extract the XML part and all attachments of a CRLF fixture.
fn load(path: &Path) -> Option<Fixture> {
    let bytes = std::fs::read(path).ok()?;
    let mut parser = MimeParser::new(&bytes[..]).ok()?;
    let mut xml = None;
    let mut attachments = HashMap::new();
    while let Ok(Some(mut part)) = parser.next_part() {
        let mut content = Vec::new();
        if part.read_to_end(&mut content).is_err() {
            return None; // LF-only fixture: parts cannot be delimited
        }
        if part.content_id() == "osci@message" {
            xml = Some(String::from_utf8(content).ok()?);
        } else {
            let decoded = match part.encoding() {
                Some("base64") => base64::decode(&String::from_utf8_lossy(&content)).ok()?,
                _ => content,
            };
            attachments.insert(part.content_id().to_string(), decoded);
        }
    }
    Some(Fixture {
        xml: xml?,
        attachments,
    })
}

/// Extract the XML part of an LF-only fixture by byte surgery (attack
/// corpus files use LF line endings, so the MIME part scanner cannot
/// delimit them). The part content runs from the third blank-line section
/// to the next boundary; note some fixtures put a blank line after the
/// XML declaration, so everything up to the boundary belongs to the XML.
fn load_lf_xml(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let mut sections = text.split("\n\n");
    let _outer_headers = sections.next()?;
    let _boundary_and_part_headers = sections.next()?;
    let rest = sections.collect::<Vec<_>>().join("\n\n");
    let end = rest.find("\n--").map(|i| &rest[..i]).unwrap_or(&rest);
    Some(end.to_string())
}

fn find_references<'a>(element: &'a Element, out: &mut Vec<&'a Element>) {
    for child in element.elements() {
        if child.prefix == "ds" && child.local == "Reference" {
            out.push(child);
        }
        find_references(child, out);
    }
}

fn reference_digest_algorithm(reference: &Element) -> Option<&str> {
    for child in reference.elements() {
        if child.local == "DigestMethod" {
            return child.attr("Algorithm");
        }
    }
    None
}

fn reference_digest_value(reference: &Element) -> Option<Vec<u8>> {
    for child in reference.elements() {
        if child.local == "DigestValue" {
            return base64::decode(child.text().trim()).ok();
        }
    }
    None
}

fn has_base64_transform(reference: &Element) -> bool {
    for child in reference.elements() {
        if child.local == "Transforms" {
            for transform in child.elements() {
                if transform.attr("Algorithm") == Some("http://www.w3.org/2000/09/xmldsig#base64") {
                    return true;
                }
            }
        }
    }
    false
}

fn verify_reference(
    reference: &Element,
    doc: &Document,
    canon: &Canonicalization,
    attachments: &HashMap<String, Vec<u8>>,
) -> Result<bool, String> {
    let Some(uri) = reference.attr("URI") else {
        return Ok(false); // omission is legal in xmldsig; nothing to check
    };
    let Some(algorithm) = reference_digest_algorithm(reference) else {
        return Ok(false);
    };
    let Some(expected) = reference_digest_value(reference) else {
        return Ok(false);
    };

    let input: Vec<u8> = if let Some(id) = uri.strip_prefix('#') {
        if let Some(region) = canon.canonical_regions.get(uri) {
            // Transport-level signed element: digest its canonical bytes
            // with the algorithm THIS reference declares (the Java
            // digest map picks its method at element start, which cannot
            // see signatures appearing later in the document).
            return match digest_bytes(algorithm, region) {
                Some(actual) if actual == expected => Ok(true),
                Some(_) => Err(format!("digest mismatch for {uri} ({algorithm})")),
                None => Err(format!("unknown digest algorithm {algorithm}")),
            };
        }
        if has_base64_transform(reference) {
            let Some(element) = doc.find_by_id(id) else {
                return Err(format!("reference target {uri} not found"));
            };
            base64::decode(element.text().trim())
                .map_err(|e| format!("base64 content of {uri} invalid: {e}"))?
        } else {
            // certificate-element and other content-level references are
            // verified with the container signatures in a later milestone
            return Ok(false);
        }
    } else if let Some(cid) = uri.strip_prefix("cid:") {
        let Some(content) = attachments.get(cid) else {
            return Ok(false); // attachment not present in this fixture part set
        };
        content.clone()
    } else {
        return Ok(false); // external URL reference
    };

    let Some(actual) = digest_bytes(algorithm, &input) else {
        return Err(format!("unknown digest algorithm {algorithm}"));
    };
    if actual == expected {
        Ok(true)
    } else {
        Err(format!("digest mismatch for {uri} ({algorithm})"))
    }
}

#[test]
fn fixture_reference_digests_verify() {
    let dir = common::corpus().join("messages");
    let mut verified_total = 0usize;
    let mut skipped_total = 0usize;
    let mut checked_files = 0usize;
    let mut failures: Vec<String> = Vec::new();

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "osci"))
        .collect();
    entries.sort();

    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name == "StoreDelivery_XXE.osci" {
            // expected to be rejected, covered by its own test below
            continue;
        }
        // this fixture plants a broken control block digest on purpose
        let expect_mismatch = name == "ResponseToFetchDelivery_corrupt_sig.osci";
        // Hand-crafted vectors with stale transport digests: the Java
        // tests expect SoapClientException for the first (unsigned-content
        // detection) and only exercise weak-signature policy / partial
        // delivery parsing for the others - never transport verification.
        let stale_digests = matches!(
            name.as_str(),
            "MESSAGE_WITH_UNSIGNED_CONTENTS.osci"
                | "RIPEMD160test.osci"
                | "ResponseToPartialFetchDelivery.osci"
        );
        let mut this_file_mismatch = false;
        let Some(fixture) = load(&path) else {
            continue; // not a CRLF multipart fixture
        };
        let doc = match parser::parse(&fixture.xml) {
            Ok(doc) => doc,
            Err(e) => {
                failures.push(format!("{name}: XML rejected: {e}"));
                continue;
            }
        };
        let mut references = Vec::new();
        find_references(&doc.root, &mut references);
        if references.is_empty() {
            continue;
        }
        checked_files += 1;
        let canon = match canonicalize(&doc) {
            Ok(canon) => canon,
            Err(e) => {
                // Rsp2FetchDelSignedInnerCoco plants duplicate Ids (the
                // Java Canonizer rejects it likewise with "Unexpected
                // entry", verified by the oracle differential test)
                assert_eq!(
                    name, "Rsp2FetchDelSignedInnerCoco.osci",
                    "{name}: unexpected canonicalization failure: {e}"
                );
                continue;
            }
        };
        for reference in &references {
            match verify_reference(reference, &doc, &canon, &fixture.attachments) {
                Ok(true) => verified_total += 1,
                Ok(false) => skipped_total += 1,
                Err(e) => {
                    if expect_mismatch || stale_digests {
                        this_file_mismatch = true;
                    } else {
                        failures.push(format!("{name}: {e}"));
                    }
                }
            }
        }
        if expect_mismatch || stale_digests {
            assert!(
                this_file_mismatch,
                "{name}: the planted stale digests were not detected"
            );
        }
    }

    assert!(
        failures.is_empty(),
        "{} reference failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        verified_total >= 30,
        "suspiciously few references verified: {verified_total} verified, {skipped_total} skipped, {checked_files} files"
    );
}

/// The XXE attack fixture must be rejected at the XML parser gate.
#[test]
fn xxe_fixture_rejected() {
    let bytes = std::fs::read(common::message("StoreDelivery_XXE.osci")).unwrap();
    let mut parser = MimeParser::new(&bytes[..]).unwrap();
    let mut part = parser.next_part().unwrap().expect("xml part");
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    let err = parser::parse(&String::from_utf8(xml).unwrap()).unwrap_err();
    assert!(
        err.to_string().contains("DOCTYPE"),
        "expected DOCTYPE rejection, got: {err}"
    );
}

/// Signature-wrapping fixtures relocate or duplicate signed elements; the
/// attack must not silently verify (LF-only files: XML extracted by byte
/// surgery). Detection means either a duplicate-Id rejection or at least
/// one reference digest that no longer matches.
#[test]
fn signature_wrapping_attacks_detected() {
    for name in [
        "SignatureWrapping2.osci",
        "SignatureWrapping3.osci",
        "SignatureWrapping4.osci",
    ] {
        let Some(xml) = load_lf_xml(&common::message(name)) else {
            panic!("{name}: XML not extractable");
        };
        let result = parser::parse(&xml)
            .map_err(osci_core::xml::c14n::C14nError::Parse)
            .and_then(|doc| canonicalize(&doc));
        match result {
            Err(e) if e.to_string().contains("duplicate") => continue, // rejected outright
            Err(e) => panic!("{name}: unexpected error {e}"),
            Ok(canon) => {
                let doc = parser::parse(&xml).unwrap();
                let mut references = Vec::new();
                find_references(&doc.root, &mut references);
                let mut verifiable = 0;
                let mut mismatches = 0;
                for reference in &references {
                    if let Some(uri) = reference.attr("URI")
                        && canon.canonical_regions.contains_key(uri)
                    {
                        verifiable += 1;
                        if verify_reference(reference, &doc, &canon, &HashMap::new()).is_err() {
                            mismatches += 1;
                        }
                    }
                }
                assert!(
                    verifiable > 0 && mismatches > 0,
                    "{name}: signature wrapping was not detected ({verifiable} verifiable references, {mismatches} mismatches)"
                );
            }
        }
    }
}
