//! Compose-level differential against the REAL 2.6.1 reference writer
//! (issue #8 handoff): the Java oracle (`CryptoSpike composepartial`)
//! drives the vendored reference library to serialize a signed
//! PartialStoreDelivery with deterministic inputs; oscirs composes the
//! identical message and the test diffs the two wire streams
//! structurally - every element, attribute and digest value must match
//! (digest values are the strong signal: they only match when the
//! canonical bytes of every signed region are byte-identical). Only the
//! RSA-PSS signature value is volatile (random salt).
//!
//! Skips silently when the oracle is not built, like the other
//! Java-differential tests.

mod common;

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use osci_core::message::MessageType;
use osci_core::message::compose::{
    OutAttachment, OutCertEntry, OutContent, OutContentContainer, OutMessage, compose_message,
};
use osci_core::soap::{CertRole, CertUse, ControlBlock};
use osci_core::xml::Element;
use osci_core::xml::parser;

fn corpus() -> PathBuf {
    common::corpus()
}

/// Java convention for certificate entry ids: `<use>_<role>_<sha1-hex>`.
/// The sha1 hex is the certificate fingerprint; the live intermediary
/// resolves signature RetrievalMethods through these entries.
fn cert_entry_id(role: &str, use_: &str, pem: &str) -> String {
    let der = cert_der(pem);
    let sha256 = osci::digest_bytes("http://www.w3.org/2001/04/xmlenc#sha256", &der).unwrap();
    let hex: String = sha256.iter().map(|b| format!("{b:02x}")).collect();
    format!("{role}_{use_}_{hex}")
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

fn oracle_available() -> bool {
    std::env::var_os("OSCI_CORPUS")
        .map(|p| {
            PathBuf::from(&p)
                .parent()
                .map(|p| p.join("oracle/build/classpath.txt").exists())
                .unwrap_or(false)
        })
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(2)
                .unwrap()
                .join("oracle/build/classpath.txt")
                .exists()
        })
}

fn workspace_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

/// Run the Java compose oracle: the 2.6.1 reference library serializes a
/// signed PartialStoreDelivery (optionally transport-encrypted) with the
/// deterministic inputs both sides share.
fn oracle_compose(encrypted: bool) -> Vec<u8> {
    let root = workspace_root();
    let classpath = std::fs::read_to_string(root.join("oracle/build/classpath.txt")).unwrap();
    let classpath = format!(
        "{}:{}",
        root.join("oracle/build").display(),
        classpath.trim()
    );
    let java = root.join("tools/jdk11/bin/java");
    let child = Command::new(&java)
        .current_dir(&root)
        .env("OSCI_CORPUS", corpus())
        .arg("-cp")
        .arg(&classpath)
        .arg("osci.oracle.CryptoSpike")
        .arg("composepartial")
        .arg(if encrypted { "encrypted" } else { "plain" })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn java");
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "oracle compose failed");
    output.stdout
}

/// The oscirs side: identical fixed inputs to the oracle's.
fn oscirs_partial() -> OutMessage {
    let signature_entry_id = cert_entry_id("originator", "signature", "alice_signature_4096.pem");
    OutMessage {
        kind: Some(MessageType::PartialStoreDelivery),
        control_block: ControlBlock {
            conversation_id: Some("1516031926756497464904932674077".into()),
            sequence_number: Some(0),
            response: Some("cmVzcG9uc2U=".into()),
            challenge: Some("Y2hhbGxlbmdl".into()),
        },
        desired_languages: Some("de".into()),
        // live ground truth: a signed partial carries THREE entries, the
        // ClientSignature's RetrievalMethod points at the originator
        // signature certificate (issue #8: rosci dropped it -> dangling
        // signature reference)
        non_intermediary_certificates: vec![
            OutCertEntry {
                role: CertRole::Originator,
                use_: CertUse::Cipher,
                id: cert_entry_id("originator", "cipher", "carol_cipher_4096.pem"),
                der: cert_der("carol_cipher_4096.pem"),
            },
            OutCertEntry {
                role: CertRole::Addressee,
                use_: CertUse::Cipher,
                id: cert_entry_id("addressee", "cipher", "bob_cipher_4096.pem"),
                der: cert_der("bob_cipher_4096.pem"),
            },
            OutCertEntry {
                role: CertRole::Originator,
                use_: CertUse::Signature,
                id: signature_entry_id.clone(),
                der: cert_der("alice_signature_4096.pem"),
            },
        ],
        feature_description: Some(osci_core::soap::FeatureDescription {
            // the reference FD carries no chunk-size attributes (defaults)
            chunk_message_timeout: None,
            max_chunk_size: None,
            max_message_size: None,
            min_chunk_size: None,
            features: vec![
                ("DisableBase64".into(), "1.2.0".into()),
                ("OAEPEncryption".into(), "1.6.0".into()),
                ("SHA3HashAlgo".into(), "1.6.3".into()),
                ("GCMPaddingModus".into(), "1.7.0".into()),
                ("PartialMessageTransmission".into(), "1.8.0".into()),
                ("Support96Bit12ByteIV".into(), "1.9.0".into()),
            ],
        }),
        entry_inner: Some(
            // the reference appends "_Partial" to the MessageId and
            // base64-encodes the result
            "<osci:MessageId>WWxoT2JnPT1fUGFydGlhbA==</osci:MessageId>\
             <osci:Subject>S</osci:Subject>"
                .into(),
        ),
        chunk_information: Some(osci_core::message::ChunkInformation {
            chunk_number: 1,
            chunk_size: Some(64),
            total_chunk_numbers: Some(2),
            total_message_size: Some(128),
            received_chunks: Vec::new(),
        }),
        containers: vec![OutContentContainer {
            id: "ChunkContentContainer".into(),
            contents: vec![OutContent {
                id: "ChunkContent".into(),
                text: None,
                href: Some("cid:ChunkBlobStoreDelivery".into()),
            }],
            encrypted_attachments: Vec::new(),
        }],
        attachments: vec![OutAttachment {
            content_id: "ChunkBlobStoreDelivery".into(),
            content_type: "application/octet-stream".into(),
            base64_encoding: false,
            data: vec![b'A'; 64],
        }],
        ..Default::default()
    }
}

fn xml_part_of(stream: &[u8]) -> String {
    let mut mime = osci_core::helper::mime::MimeParser::new(stream).unwrap();
    let mut part = mime.next_part().unwrap().unwrap();
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    String::from_utf8(xml).unwrap()
}

#[test]
fn composed_partial_matches_the_reference_writer() {
    if !oracle_available() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    let oracle_plain = oracle_compose(false);
    assert!(oracle_plain.starts_with(b"MIME-Version"), "oracle wire");

    // oscirs compose + sign
    let msg = oscirs_partial();
    let stream = compose_message(&msg, "MIME_boundary").unwrap();
    let xml = xml_part_of(&stream);
    let signer = osci_crypto::software::RsaSigner::from_pem_dump(
        corpus()
            .join("certs")
            .join("alice_signature_4096.pem")
            .to_str()
            .unwrap(),
        None,
    )
    .unwrap();
    let attachments = vec![("ChunkBlobStoreDelivery".to_string(), vec![b'A'; 64])];
    let signed = osci::sign::sign_message_xml(
        &xml,
        &osci::sign::SignParams {
            signer: &signer,
            method: None,
            digest: None,
            certificate_id: cert_entry_id("originator", "signature", "alice_signature_4096.pem"),
            attachments: &attachments,
            header_element: None,
        },
    )
    .unwrap();

    let oracle_xml = xml_part_of(&oracle_plain);
    let a = parser::parse(&oracle_xml).unwrap();
    let b = parser::parse(&signed).unwrap();

    let mut diffs = Vec::new();
    diff_element(&a.root, &b.root, "/", &mut diffs);
    assert!(
        diffs.is_empty(),
        "oscirs compose diverges from the 2.6.1 reference writer:\n{}",
        diffs.join("\n")
    );
}

fn diff_element(a: &Element, b: &Element, path: &str, diffs: &mut Vec<String>) {
    if a.local != b.local {
        diffs.push(format!("{path}: element {} != {}", a.local, b.local));
        return;
    }
    // volatile mask: certificate entry Ids (the reference embeds cert
    // fingerprints, ours are caller-chosen) and RSA-PSS signature values
    // (random salt). DigestValues are NOT masked - they only match when
    // the canonical bytes of the signed regions are byte-identical.
    let mask = |k: &str, v: &str| -> String {
        let v = v.strip_prefix('#').unwrap_or(v);
        if (k == "Id" || k == "URI") && (v.starts_with("originator") || v.starts_with("addressee"))
        {
            "CERT".to_string()
        } else {
            v.to_string()
        }
    };
    let a_attrs: std::collections::BTreeMap<&str, String> = a
        .attrs
        .iter()
        .map(|(k, v)| (k.as_str(), mask(k, v)))
        .collect();
    let b_attrs: std::collections::BTreeMap<&str, String> = b
        .attrs
        .iter()
        .map(|(k, v)| (k.as_str(), mask(k, v)))
        .collect();
    if a_attrs != b_attrs {
        for (k, v) in &a_attrs {
            if b_attrs.get(k) != Some(v) {
                diffs.push(format!(
                    "{path}/{}@{}: {:?} vs {:?}",
                    a.local,
                    k,
                    v,
                    b_attrs.get(k)
                ));
            }
        }
        for k in b_attrs.keys() {
            if !a_attrs.contains_key(k) {
                diffs.push(format!("{path}/{}@{}: missing on oracle side", a.local, k));
            }
        }
    }
    let a_text = a.text();
    let b_text = b.text();
    if a_text != b_text && a.elements().count() == 0 && a.local != "SignatureValue" {
        diffs.push(format!(
            "{path}/{}: text {:?} vs {:?}",
            a.local,
            &a_text[..a_text.len().min(80)],
            &b_text[..b_text.len().min(80)]
        ));
    }
    let a_children: Vec<&Element> = a.elements().collect();
    let b_children: Vec<&Element> = b.elements().collect();
    // the reference signer collects SignedInfo references in JVM HashMap
    // order (random per run) - compare them as a URI-indexed set; the
    // reference ORDER is not part of the contract
    if a.local == "SignedInfo" {
        let key = |e: &Element| e.attr("URI").unwrap_or_default().to_string();
        let am: std::collections::BTreeMap<String, &Element> =
            a_children.iter().map(|e| (key(e), *e)).collect();
        let bm: std::collections::BTreeMap<String, &Element> =
            b_children.iter().map(|e| (key(e), *e)).collect();
        for k in am.keys() {
            if !bm.contains_key(k) {
                diffs.push(format!(
                    "{path}/SignedInfo: reference {k} missing on oscirs side"
                ));
            }
        }
        for k in bm.keys() {
            if !am.contains_key(k) {
                diffs.push(format!(
                    "{path}/SignedInfo: reference {k} missing on oracle side"
                ));
            }
        }
        for (k, ae) in &am {
            if let Some(be) = bm.get(k) {
                diff_element(ae, be, &format!("{path}/SignedInfo[{k}]"), diffs);
            }
        }
        return;
    }
    if a_children.len() != b_children.len() {
        diffs.push(format!(
            "{path}/{}: {} children vs {}",
            a.local,
            a_children.len(),
            b_children.len()
        ));
        return;
    }
    for (i, (ac, bc)) in a_children.iter().zip(b_children.iter()).enumerate() {
        diff_element(ac, bc, &format!("{path}/{}[{i}]", a.local), diffs);
    }
}

/// Bonus interop check: the oracle's TRANSPORT-ENCRYPTED partial must be
/// openable by our reader with the intermediary key, and the decrypted
/// inner stream must structurally match our inner signed stream.
#[test]
fn encrypted_oracle_partial_opens_and_matches() {
    if !oracle_available() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    let oracle_enc = oracle_compose(true);
    let stored = osci_core::message::stored::StoredMessage::load(&oracle_enc).unwrap();
    let manager = osci_crypto::software::RsaDecrypter::from_pem_dump(
        corpus()
            .join("certs")
            .join("osci_manager_cipher_4096.pem")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let view = osci::security::StoredMessageLike {
        xml: &stored.xml,
        attachments: &stored.attachments,
    };
    let inner = osci::security::decrypt_transport_message(&view, &[&manager]).unwrap();

    // the decrypted inner stream matches our inner signed stream
    let msg = oscirs_partial();
    let stream = compose_message(&msg, "MIME_boundary").unwrap();
    let xml = xml_part_of(&stream);
    let signer = osci_crypto::software::RsaSigner::from_pem_dump(
        corpus()
            .join("certs")
            .join("alice_signature_4096.pem")
            .to_str()
            .unwrap(),
        None,
    )
    .unwrap();
    let attachments = vec![("ChunkBlobStoreDelivery".to_string(), vec![b'A'; 64])];
    let signed = osci::sign::sign_message_xml(
        &xml,
        &osci::sign::SignParams {
            signer: &signer,
            method: None,
            digest: None,
            certificate_id: cert_entry_id("originator", "signature", "alice_signature_4096.pem"),
            attachments: &attachments,
            header_element: None,
        },
    )
    .unwrap();

    let a = parser::parse(&xml_part_of(&inner)).unwrap();
    let b = parser::parse(&signed).unwrap();
    let mut diffs = Vec::new();
    diff_element(&a.root, &b.root, "/", &mut diffs);
    assert!(
        diffs.is_empty(),
        "inner signed streams diverge:\n{}",
        diffs.join("\n")
    );
}

#[test]
fn debug_parse_dump() {
    let src = std::fs::read_to_string("/tmp/ours_composed.xml").unwrap();
    match osci_core::xml::parser::parse(&src) {
        Ok(_) => eprintln!("PARSE OK ({} bytes)", src.len()),
        Err(e) => {
            eprintln!("PARSE ERR: {e}");
            let i = src.find("<soap:Envelope").unwrap();
            eprintln!("ENV TAG: {:?}", &src[i..i + 120]);
        }
    }
}
