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

/// Sort the <ds:Reference>...</ds:Reference> blocks inside the
/// <ds:SignedInfo> region by URI: the reference client collects them in
/// JVM HashMap order (random per run) while the SET of references and
/// their digests are the contract.
fn sort_signed_info_references(xml: &str) -> String {
    let open = "<ds:SignedInfo>";
    let close = "</ds:SignedInfo>";
    let si = match xml.find(open) {
        Some(p) => p + open.len(),
        None => return xml.to_string(),
    };
    let si_end = match xml[si..].find(close) {
        Some(q) => si + q,
        None => return xml.to_string(),
    };
    let region = &xml[si..si_end];
    let mut blocks: Vec<(String, String)> = Vec::new();
    let mut prefix = String::new();
    let mut rest = region;
    while let Some(p) = rest.find("<ds:Reference") {
        let e = rest[p..]
            .find("</ds:Reference>")
            .map(|q| p + q + "</ds:Reference>".len())
            .unwrap_or(rest.len());
        let block = &rest[p..e];
        let uri_start = block.find("URI=\"").map(|q| q + 5).unwrap_or(0);
        let uri_end = block[uri_start..]
            .find('"')
            .map(|q| uri_start + q)
            .unwrap_or(uri_start);
        blocks.push((block[uri_start..uri_end].to_string(), block.to_string()));
        prefix.push_str(&rest[..p]);
        rest = &rest[e..];
    }
    blocks.sort_by(|x, y| x.0.cmp(&y.0));
    let mut sorted = prefix;
    for (_, block) in &blocks {
        sorted.push_str(block);
    }
    let mut out = String::with_capacity(xml.len());
    out.push_str(&xml[..si]);
    out.push_str(&sorted);
    out.push_str(&xml[si_end..]);
    out
}

/// Issue #7/#8 follow-up (rosci handoff): the manager reassembles the
/// chunk blobs into the FULL StoreDelivery wire stream - which on rosci's
/// stack is written by oscirs. Byte-for-byte differential against the
/// reference writer's `writeMessage` output for the same inputs: same
/// 300_001-byte binary attachment (with an embedded boundary-lookalike
/// sequence), same control block, same signature key. Only the MIME
/// boundary token and the RSA-PSS signature value are volatile.
#[test]
fn composed_delivery_matches_the_reference_writer() {
    if !oracle_available() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    let oracle = {
        let root = workspace_root();
        let classpath = std::fs::read_to_string(root.join("oracle/build/classpath.txt")).unwrap();
        let classpath = format!(
            "{}:{}",
            root.join("oracle/build").display(),
            classpath.trim()
        );
        let out = Command::new(root.join("tools/jdk11/bin/java"))
            .current_dir(&root)
            .env("OSCI_CORPUS", corpus())
            .arg("-cp")
            .arg(&classpath)
            .arg("osci.oracle.CryptoSpike")
            .arg("composedelivery")
            .output()
            .expect("spawn java");
        assert!(out.status.success(), "oracle composeDelivery failed");
        out.stdout
    };

    // oscirs side: identical inputs
    let blob = {
        let mut b = vec![b'A'; 300_001];
        let lookalike = b"\r\n--MIME_boundary\r\nContent-Type: text/xml";
        b[150_000..150_000 + lookalike.len()].copy_from_slice(lookalike);
        b
    };
    let msg = OutMessage {
        kind: Some(MessageType::StoreDelivery),
        control_block: ControlBlock {
            conversation_id: Some("1516031926756497464904932674077".into()),
            sequence_number: Some(1),
            response: Some("cmVzcG9uc2U=".into()),
            challenge: Some("Y2hhbGxlbmdl".into()),
        },
        desired_languages: Some("de".into()),
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
                id: cert_entry_id("originator", "signature", "alice_signature_4096.pem"),
                der: cert_der("alice_signature_4096.pem"),
            },
        ],
        feature_description: Some(osci_core::soap::FeatureDescription {
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
        // the reference writer base64-encodes the oscid into the
        // MessageId element content (oscid "bXNn" -> base64 -> base64);
        // entry_inner is written verbatim
        entry_inner: Some(
            "<osci:MessageId>WWxoT2JnPT0=</osci:MessageId><osci:Subject>S</osci:Subject>".into(),
        ),
        containers: vec![OutContentContainer {
            // the reference setChunkBlob counter convention
            id: "contentcontainer0".into(),
            contents: vec![OutContent {
                id: "content0".into(),
                text: None,
                href: Some("cid:ChunkBlobStoreDelivery".into()),
            }],
            encrypted_attachments: Vec::new(),
        }],
        attachments: vec![OutAttachment {
            content_id: "ChunkBlobStoreDelivery".into(),
            content_type: "application/octet-stream".into(),
            base64_encoding: false,
            data: blob.clone(),
        }],
        ..Default::default()
    };

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
    let attachments = vec![("ChunkBlobStoreDelivery".to_string(), blob.clone())];
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
    // splice the signed XML back, replacing the original XML part bytes
    // (compose_signed_stream's replace_xml_part flow)
    let marker = "Content-ID: <osci@message>\r\n\r\n";
    let pos = stream
        .windows(marker.len())
        .position(|w| w == marker.as_bytes())
        .unwrap()
        + marker.len();
    let xml_end = stream[pos..]
        .windows(4)
        .position(|w| w == b"\r\n--")
        .map(|p| pos + p)
        .unwrap_or(stream.len());
    let mut ours = stream[..pos].to_vec();
    ours.extend_from_slice(signed.as_bytes());
    ours.extend_from_slice(&stream[xml_end..]);

    // normalize volatile bits and compare the XML parts byte-for-byte:
    // boundary tokens, the PSS signature value (salted), and the
    // SignedInfo reference ORDER (JVM HashMap-random per run) are
    // normalized; everything else - element layout, digests, framing
    // bytes around them - must match
    // the reference writer's boundary is randomized - normalize the
    // tokens, sort the SignedInfo references, mask the PSS signature
    // value, then compare the XML parts byte-for-byte
    let oracle_boundary: Vec<u8> = {
        let head = String::from_utf8_lossy(&oracle);
        let start = head.find("boundary=").unwrap() + "boundary=".len();
        let end = head[start..].find(';').unwrap() + start;
        head[start..end].as_bytes().to_vec()
    };
    let mask_and_norm = |xml: &str, boundary: &[u8]| -> Vec<u8> {
        let sorted = sort_signed_info_references(xml);
        let mut out = sorted.into_bytes();
        let mut i = 0;
        while let Some(p) = out[i..]
            .windows(boundary.len())
            .position(|w| w == boundary)
            .map(|p| p + i)
        {
            out.splice(p..p + boundary.len(), b"MIME_boundary".iter().copied());
            i = p + "MIME_boundary".len();
        }
        let marker = b"<ds:SignatureValue>";
        if let Some(p) = out.windows(marker.len()).position(|w| w == marker) {
            let start = p + marker.len();
            let close = b"</ds:SignatureValue>";
            if let Some(e) = out.windows(close.len()).position(|w| w == close) {
                for byte in &mut out[start..e] {
                    *byte = b'S';
                }
            }
        }
        out
    };
    let oracle_xml = xml_part_of(&oracle);
    let ours_xml = xml_part_of(&ours);
    let a = mask_and_norm(&oracle_xml, &oracle_boundary);
    let b = mask_and_norm(&ours_xml, b"MIME_boundary");

    // MIME part headers must match byte-for-byte on both sides: the XML
    // part (first Content-ID) and the attachment part (last Content-ID,
    // where the Content-Length semantics live)
    let part_headers = |stream: &[u8], last: bool| -> String {
        let find_id = |hay: &[u8]| {
            if last {
                hay.windows(11)
                    .rposition(|w| w == b"Content-ID:")
                    .expect("part with Content-ID")
            } else {
                hay.windows(11)
                    .position(|w| w == b"Content-ID:")
                    .expect("part with Content-ID")
            }
        };
        let id = find_id(stream);
        let start = stream[..id]
            .windows(13)
            .rposition(|w| w == b"Content-Type:")
            .expect("part headers");
        let end = stream[id..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|q| id + q + 2)
            .unwrap();
        String::from_utf8_lossy(&stream[start..end]).into_owned()
    };
    assert_eq!(
        part_headers(&ours, false),
        part_headers(&oracle, false),
        "XML part headers diverge"
    );
    assert_eq!(
        part_headers(&ours, true),
        part_headers(&oracle, true),
        "attachment part headers diverge"
    );

    let len = a.len().max(b.len());
    let first = (0..len).find(|&i| a.get(i) != b.get(i));
    assert!(
        first.is_none(),
        "XML parts diverge from the reference writer, first at {:?} (len oracle={} oscirs={}): oracle={:?} oscirs={:?}",
        first,
        a.len(),
        b.len(),
        first.map(|i| &a[i.saturating_sub(80)..(i + 80).min(a.len())]),
        first.map(|i| &b[i.saturating_sub(80)..(i + 80).min(b.len())]),
    );
}
