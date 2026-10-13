//! Differential test: byte-exact comparison of the Rust canonicalizer
//! against the Java reference `Canonizer`, driven through the oracle CLI
//! over the golden fixtures.

mod common;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use osci_core::helper::mime::MimeParser;
use osci_core::xml::c14n::canonicalize;
use osci_core::xml::parser;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

/// Run the oracle; `Err(())` when the Java canonicalizer itself rejects
/// the input (exit code 3).
fn run_oracle(xml: &str) -> Result<String, ()> {
    let root = workspace_root();
    let classpath = std::fs::read_to_string(root.join("oracle/build/classpath.txt"))
        .expect("oracle not built - run scripts/build-oracle.sh");
    let classpath = format!(
        "{}:{}",
        root.join("oracle/build").display(),
        classpath.trim()
    );
    let java = std::env::var_os("OSCI_JAVA")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("tools/jdk11/bin/java"));
    let mut child = Command::new(&java)
        .arg("-cp")
        .arg(&classpath)
        .arg("osci.oracle.CryptoSpike")
        .arg("canonize")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn java oracle");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(xml.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("oracle run failed");
    if out.status.code() == Some(3) {
        return Err(()); // Java rejects this document
    }
    assert!(
        out.status.success(),
        "java oracle canonize failed on input of {} bytes",
        xml.len()
    );
    Ok(String::from_utf8(out.stdout).expect("oracle stdout"))
}

struct OracleResult {
    canon: Vec<u8>,
    digests: Vec<(String, Vec<u8>)>,
    signed_infos: Vec<Option<Vec<u8>>>,
}

fn parse_oracle(output: &str) -> OracleResult {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    let mut canon = Vec::new();
    let mut digests = Vec::new();
    let mut signed_infos = Vec::new();
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("CANON_B64 ") {
            canon = B64.decode(value).expect("canon b64");
        } else if let Some(rest) = line.strip_prefix("DIGEST ") {
            let (id, value) = rest.split_once(' ').expect("DIGEST line");
            digests.push((id.to_string(), B64.decode(value).expect("digest b64")));
        } else if let Some(value) = line.strip_prefix("SIGNEDINFO ") {
            signed_infos.push(if value == "-" {
                None
            } else {
                Some(B64.decode(value).expect("signedinfo b64"))
            });
        }
    }
    OracleResult {
        canon,
        digests,
        signed_infos,
    }
}

/// Load the XML part of a fixture with the Rust MIME parser.
fn fixture_xml(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut mime = MimeParser::new(&bytes[..]).ok()?;
    let mut part = mime.next_part().ok()??;
    if part.content_id() != "osci@message" {
        return None;
    }
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).ok()?;
    String::from_utf8(xml).ok()
}

fn first_divergence(a: &[u8], b: &[u8]) -> String {
    let pos = a.iter().zip(b.iter()).position(|(x, y)| x != y);
    match pos {
        Some(i) => format!(
            "at offset {i}\n  java: {:?}\n  rust: {:?}",
            String::from_utf8_lossy(&a[i.saturating_sub(40)..(i + 40).min(a.len())]),
            String::from_utf8_lossy(&b[i.saturating_sub(40)..(i + 40).min(b.len())]),
        ),
        None => format!("lengths differ: java {} vs rust {}", a.len(), b.len()),
    }
}

#[test]
fn canonical_output_matches_java_oracle() {
    if !workspace_root().join("oracle/build/classpath.txt").exists() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    let dir = common::corpus().join("messages");
    let mut compared = 0usize;

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension().is_some_and(|e| e == "osci")
                && p.file_name().is_some_and(|n| n != "StoreDelivery_XXE.osci")
        })
        .collect();
    entries.sort();

    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let Some(xml) = fixture_xml(&path) else {
            continue;
        };
        let rust = match parser::parse(&xml)
            .map_err(osci_core::xml::c14n::C14nError::Parse)
            .and_then(|doc| canonicalize(&doc))
        {
            Ok(rust) => rust,
            Err(e) => {
                // the reference rejects it too (e.g. Rsp2FetchDelSignedInnerCoco
                // plants duplicate Ids): error parity is the expectation
                assert_eq!(
                    run_oracle(&xml),
                    Err(()),
                    "{name}: Rust rejected the document ({e}) but Java accepted it"
                );
                continue;
            }
        };
        let java = parse_oracle(&run_oracle(&xml).unwrap_or_else(|()| {
            panic!("{name}: Java rejected the document but Rust accepted it")
        }));

        assert_eq!(
            java.canon,
            rust.bytes,
            "{name}: canonical form diverges {}",
            first_divergence(&java.canon, &rust.bytes)
        );

        let java_digests: std::collections::HashMap<_, _> = java.digests.into_iter().collect();
        let rust_digests: &std::collections::HashMap<_, _> = &rust.digest_values;
        assert_eq!(
            java_digests.len(),
            rust_digests.len(),
            "{name}: digest map size differs (java {:?} vs rust {:?})",
            java_digests.keys().collect::<Vec<_>>(),
            rust_digests.keys().collect::<Vec<_>>()
        );
        for (id, java_digest) in &java_digests {
            assert_eq!(
                rust_digests.get(id),
                Some(java_digest),
                "{name}: digest for {id} differs"
            );
        }

        assert_eq!(
            java.signed_infos.len(),
            rust.signed_infos.len(),
            "{name}: signed info count differs"
        );
        for (i, (java_si, rust_si)) in java.signed_infos.iter().zip(&rust.signed_infos).enumerate()
        {
            assert_eq!(java_si, rust_si, "{name}: signed info #{i} differs");
        }

        compared += 1;
    }

    assert!(
        compared >= 10,
        "suspiciously few fixtures compared: {compared}"
    );
}
