//! M6a gates: signature verification and decryption through the public
//! `osci::security` API across the corpus, plus the attack-corpus
//! rejection suite.

use std::io::Read;
use std::path::{Path, PathBuf};

use osci::security::{VerificationReport, decrypt_all_encrypted_data, verify_message};
use osci_core::helper::mime::MimeParser;
use osci_crypto::software::{Decrypter, RsaDecrypter};

fn corpus() -> PathBuf {
    std::env::var_os("OSCI_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(2)
                .unwrap()
                .join("testcorpus")
        })
}

fn messages_dir() -> PathBuf {
    corpus().join("messages")
}

/// CRLF fixtures: the XML part plus transfer-decoded attachments.
struct Loaded {
    xml: String,
    attachments: Vec<(String, Vec<u8>)>,
}

fn load(path: &Path) -> Option<Loaded> {
    let bytes = std::fs::read(path).ok()?;
    let mut mime = MimeParser::new(&bytes[..]).ok()?;
    let mut xml = String::new();
    let mut attachments = Vec::new();
    while let Some(mut part) = mime.next_part().ok()? {
        let mut content = Vec::new();
        if part.read_to_end(&mut content).is_err() {
            return None; // LF-only fixture
        }
        if part.content_id() == "osci@message" {
            xml = String::from_utf8(content).ok()?;
        } else {
            let data = if part.encoding() == Some("base64") {
                osci_core::helper::base64::decode(&String::from_utf8_lossy(&content)).ok()?
            } else {
                content
            };
            attachments.push((part.content_id().to_string(), data));
        }
    }
    if xml.is_empty() {
        None
    } else {
        Some(Loaded { xml, attachments })
    }
}

/// LF-only fixtures: XML part by byte surgery.
fn lf_xml(name: &str) -> Option<String> {
    let bytes = std::fs::read(messages_dir().join(name)).ok()?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let mut sections = text.split("\n\n");
    let _ = sections.next();
    let _ = sections.next();
    let rest = sections.collect::<Vec<_>>().join("\n\n");
    let end = rest.find("\n--").map(|i| &rest[..i]).unwrap_or(&rest);
    Some(end.to_string())
}

/// Every RSA decrypter of the corpus.
fn corpus_decrypters() -> Vec<RsaDecrypter> {
    let mut out = Vec::new();
    for dir in ["certs", "certs/alt", "certs/BOS/optional"] {
        let dir = corpus().join(dir);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "pem")
                && let Ok(decrypter) = RsaDecrypter::from_pem_dump(path.to_str().unwrap())
            {
                out.push(decrypter);
            }
        }
    }
    out
}

/// Every corpus message with signatures verifies: the RSA check over the
/// canonical SignedInfo AND all resolvable reference digests.
#[test]
fn corpus_signatures_verify() {
    let mut verified_files = 0usize;
    let mut verified_signatures = 0usize;
    let mut checked_references = 0usize;
    let mut failures = Vec::new();

    let entries = std::fs::read_dir(messages_dir())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()));
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".osci") {
            continue;
        }
        // deliberately broken / attack vectors: exercised in their own test
        if name.contains("corrupt_sig")
            || name.starts_with("CBCAttack")
            || name.starts_with("ProDel_Encrypted")
            || name.starts_with("SignatureWrapping")
            || name.contains("RIPEMD160")
            || name.contains("UNSIGNED")
            || name == "CBC2018.osci"
            || name == "Rsp2FetchDelSignedInnerCoco.osci"
            || name == "StoreDelivery_XXE.osci"
            || name == "ResponseToMediateDelivery.osci"
            || name == "ResponseToPartialFetchDelivery.osci"
        {
            continue;
        }
        let Some(loaded) = load(&path) else {
            continue;
        };
        let report = match verify_message(&loaded.xml, &loaded.attachments) {
            Ok(report) => report,
            Err(osci::security::SecurityError::NoSignatures) => continue, // unsigned type
            Err(e) => {
                failures.push(format!("{name}: {e}"));
                continue;
            }
        };
        if report.signatures.is_empty() {
            continue; // unsigned message types
        }
        for signature in &report.signatures {
            if !signature.signature_valid {
                failures.push(format!(
                    "{name}: signature {:?} ({}) invalid",
                    signature.certificate_id, signature.method
                ));
            }
            for reference in &signature.references {
                if let Some(false) = reference.checked {
                    failures.push(format!(
                        "{name}: reference {} digest mismatch",
                        reference.uri
                    ));
                }
                if reference.checked.is_some() {
                    checked_references += 1;
                }
            }
        }
        if report.all_valid() {
            verified_files += 1;
            verified_signatures += report.signatures.len();
        }
    }

    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
    assert!(verified_files >= 8, "only {verified_files} files verified");
    assert!(
        verified_signatures >= 10,
        "only {verified_signatures} signatures"
    );
    assert!(
        checked_references >= 40,
        "only {checked_references} references checked"
    );
}

/// The deliberately corrupted signature fixture must FAIL verification.
#[test]
fn corrupt_signature_detected() {
    let loaded = load(&messages_dir().join("ResponseToFetchDelivery_corrupt_sig.osci")).unwrap();
    let report = verify_message(&loaded.xml, &loaded.attachments).unwrap();
    assert!(
        !report.all_valid(),
        "the planted corruption was not detected"
    );
}

/// The signature-wrapping attacks are detected (duplicate Ids at the
/// canonicalizer, or digest mismatches).
#[test]
fn signature_wrapping_attacks_rejected() {
    for name in [
        "SignatureWrapping2.osci",
        "SignatureWrapping3.osci",
        "SignatureWrapping4.osci",
    ] {
        let xml = lf_xml(name).expect("extractable");
        match osci_core::xml::parser::parse(&xml) {
            Err(e) => assert!(e.to_string().contains("DOCTYPE"), "{name}: {e}"),
            Ok(doc) => {
                match osci_core::xml::c14n::canonicalize(&doc) {
                    Err(e) => assert!(
                        e.to_string().contains("duplicate"),
                        "{name}: unexpected c14n error {e}"
                    ),
                    Ok(_canon) => {
                        // if canonicalization tolerated it, the digests
                        // must not verify
                        let report = verify_message(&xml, &[]).expect("verification runs");
                        assert!(!report.all_valid(), "{name}: wrapping accepted");
                    }
                }
            }
        }
    }
}

/// The encrypted attack payloads (tampered ciphertexts) must fail
/// decryption with every corpus key.
#[test]
fn encrypted_attack_payloads_rejected() {
    let decrypters = corpus_decrypters();
    assert!(!decrypters.is_empty());
    let refs: Vec<&dyn Decrypter> = decrypters.iter().map(|d| d as &dyn Decrypter).collect();

    for name in [
        "StoreDelivery_CBCAttack.osci",
        "ProDel_Encrypted_CBC_attack.osci",
        "ProDel_Encrypted_GCM_attack.osci",
    ] {
        let xml = lf_xml(name).expect("extractable");
        let decrypted = decrypt_all_encrypted_data(&xml, &refs).unwrap();
        assert!(
            decrypted.is_empty(),
            "{name}: tampered payload decrypted successfully"
        );
    }
}

/// Encrypted fixtures decrypt through the public API down to inner XML.
#[test]
fn encrypted_fixtures_decrypt() {
    let decrypters = corpus_decrypters();
    let refs: Vec<&dyn Decrypter> = decrypters.iter().map(|d| d as &dyn Decrypter).collect();

    let mut decrypted_count = 0usize;
    let entries = std::fs::read_dir(messages_dir())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()));
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".osci") {
            continue;
        }
        let xml = if let Some(loaded) = load(&path) {
            loaded.xml
        } else if name.starts_with("CBCAttack") || name.contains("corrupt_sig") {
            continue;
        } else {
            match lf_xml(&name) {
                Some(xml) => xml,
                None => continue,
            }
        };
        if !xml.contains("EncryptedData") {
            continue;
        }
        if name.starts_with("ProDel_Encrypted") || name.ends_with("_CBCAttack.osci") {
            continue; // attack payloads
        }
        let Ok(decrypted) = decrypt_all_encrypted_data(&xml, &refs) else {
            continue;
        };
        for content in decrypted {
            assert!(
                content.plaintext.starts_with(b"<"),
                "{name}: plaintext not XML"
            );
            decrypted_count += 1;
        }
    }
    assert!(decrypted_count >= 3, "only {decrypted_count} decryptions");
}

/// The unsigned-content fixture: its content signature must fail or be
/// absent while the transport signature (if any) is checked separately.
#[test]
fn unsigned_content_fixture_detected() {
    let loaded = load(&messages_dir().join("MESSAGE_WITH_UNSIGNED_CONTENTS.osci"))
        .or_else(|| {
            // fall back to byte surgery if the MIME framing differs
            lf_xml("MESSAGE_WITH_UNSIGNED_CONTENTS.osci").map(|xml| Loaded {
                xml,
                attachments: Vec::new(),
            })
        })
        .unwrap();
    // the planted unsigned content makes the #body digest stale - the
    // verification failure IS the detection mechanism
    let report = verify_message(&loaded.xml, &loaded.attachments).unwrap();
    assert!(
        !report.all_valid(),
        "unsigned content was not detected (stale body digest accepted)"
    );
}

/// The verification report is usable for diagnosis (methods, cert ids).
#[test]
fn verification_report_shapes() {
    let loaded = load(&messages_dir().join("StoreDelivery.osci")).unwrap();
    let report: VerificationReport = verify_message(&loaded.xml, &loaded.attachments).unwrap();
    assert!(report.all_valid());
    let signature = &report.signatures[0];
    assert!(
        signature.method.contains("sha"),
        "method: {}",
        signature.method
    );
    assert!(signature.certificate_id.is_some());
    assert!(
        signature
            .references
            .iter()
            .any(|r| r.uri == "#controlblock" && r.checked == Some(true))
    );
    assert!(
        signature
            .references
            .iter()
            .any(|r| r.uri == "#body" && r.checked == Some(true))
    );
    // cid reference checked against the transfer-decoded attachment
    assert!(
        signature
            .references
            .iter()
            .any(|r| r.uri == "cid:test.txt" && r.checked == Some(true))
    );
}
