//! M0 spike: cross-verify the crypto primitives between BouncyCastle (Java
//! oracle, exact OSCI 1.2 library parameterization) and the RustCrypto `rsa`
//! crate, in both directions.
//!
//! Java -> Rust: a BouncyCastle RSA-PSS signature must verify with
//! `rsa::pss::VerifyingKey<Sha256>`, and a BouncyCastle RSA-OAEP key wrap
//! must open with `rsa::Oaep<Sha256>`.
//! Rust -> Java: an `rsa`-produced PSS signature must pass the oracle's
//! verify mode, and an `rsa`-produced OAEP wrap must pass its unwrap mode.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pss::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn corpus() -> PathBuf {
    let root = workspace_root();
    let via_env = std::env::var_os("OSCI_CORPUS").map(PathBuf::from);
    via_env.unwrap_or_else(|| root.join("testcorpus"))
}

/// Invoke the Java oracle; fails with a build hint when it is not compiled.
fn oracle_available() -> bool {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .join("oracle/build/classpath.txt")
        .exists()
}

fn oracle(args: &[&str], stdin: Option<&str>) -> String {
    let root = workspace_root();
    let build = root.join("oracle/build");
    let classpath_file = build.join("classpath.txt");
    if !build.join("osci/oracle/CryptoSpike.class").exists() || !classpath_file.exists() {
        panic!(
            "oracle not built - run {} first",
            root.join("scripts/build-oracle.sh").display()
        );
    }
    let classpath = format!(
        "{}:{}",
        build.display(),
        std::fs::read_to_string(&classpath_file).unwrap().trim()
    );
    let java = std::env::var_os("OSCI_JAVA")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("tools/jdk11/bin/java"));
    let mut cmd = Command::new(&java);
    cmd.arg("-cp")
        .arg(&classpath)
        .arg("osci.oracle.CryptoSpike")
        .args(args)
        .env("OSCI_CORPUS", corpus())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().expect("failed to spawn java oracle");
    if let Some(input) = stdin {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().expect("failed to wait for oracle");
    assert!(out.status.success(), "oracle {:?} failed", args);
    String::from_utf8(out.stdout).expect("oracle stdout not utf-8")
}

/// Pull the first `-----BEGIN PRIVATE KEY-----` block out of an openssl
/// keystore dump, so we never need PKCS#12 parsing on the Rust side.
fn first_private_key_pem(name: &str) -> String {
    let dump = std::fs::read_to_string(corpus().join("certs").join(name)).unwrap();
    let start = dump
        .find("-----BEGIN PRIVATE KEY-----")
        .unwrap_or_else(|| panic!("no private key block in {name}"));
    let end = dump[start..]
        .find("-----END PRIVATE KEY-----")
        .map(|i| start + i + "-----END PRIVATE KEY-----".len())
        .unwrap_or_else(|| panic!("unterminated private key block in {name}"));
    dump[start..end].to_string()
}

fn load_key(name: &str) -> RsaPrivateKey {
    let pem = first_private_key_pem(name);
    RsaPrivateKey::from_pkcs8_pem(&pem).unwrap_or_else(|e| panic!("bad pkcs8 pem in {name}: {e}"))
}

fn parse_kv(output: &str) -> HashMap<String, Vec<u8>> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| {
            (
                k.to_string(),
                B64.decode(v).expect("bad base64 from oracle"),
            )
        })
        .collect()
}

const PAYLOAD: &[u8] = b"osci-rust-rewrite crypto spike payload 0123456789";

#[test]
fn java_pss_signature_verifies_in_rust() {
    if !oracle_available() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    let vectors = parse_kv(&oracle(&["vectors"], None));
    assert_eq!(
        vectors["payload_b64"], PAYLOAD,
        "oracle payload constant out of sync with this test"
    );

    let signer_key = load_key("alice_signature_4096.pem");
    let public = RsaPublicKey::from(&signer_key);

    let vk = VerifyingKey::<Sha256>::new(public);
    let signature = Signature::try_from(vectors["pss_signature_b64"].as_slice())
        .expect("signature length mismatch");
    vk.verify(PAYLOAD, &signature)
        .expect("BouncyCastle SHA256withRSAandMGF1 signature must verify with rsa::pss");
}

#[test]
fn java_oaep_wrap_opens_in_rust() {
    if !oracle_available() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    let vectors = parse_kv(&oracle(&["vectors"], None));

    let cipher_key = load_key("alice_cipher_4096.pem");
    let session_key = &vectors["session_key_b64"];
    assert_eq!(session_key.len(), 32, "expected an AES-256 session key");

    let unwrapped = cipher_key
        .decrypt(Oaep::new::<Sha256>(), &vectors["wrapped_key_b64"])
        .expect("BouncyCastle RSA-OAEP wrap must open with rsa::Oaep<Sha256>");
    assert_eq!(
        unwrapped, *session_key,
        "unwrapped session key differs from the wrapped plaintext"
    );
}

#[test]
fn rust_pss_signature_verifies_in_java() {
    if !oracle_available() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    let signer_key = load_key("alice_signature_4096.pem");
    let mut rng = rand::thread_rng();
    let signature = SigningKey::<Sha256>::new(signer_key)
        .sign_with_rng(&mut rng, PAYLOAD)
        .to_vec();

    let stdin = format!(
        "payload_b64={}\nsignature_b64={}\n",
        B64.encode(PAYLOAD),
        B64.encode(&signature)
    );
    let out = oracle(&["verify"], Some(&stdin));
    assert!(
        out.trim().starts_with("VERIFY_OK"),
        "oracle rejected rsa::pss signature: {out}"
    );
}

#[test]
fn rust_oaep_wrap_opens_in_java() {
    if !oracle_available() {
        eprintln!("skipping: java oracle not built");
        return;
    }
    let cipher_key = load_key("alice_cipher_4096.pem");
    let public = RsaPublicKey::from(&cipher_key);
    let session_key: [u8; 32] = core::array::from_fn(|i| i as u8 ^ 0xA5);

    let mut rng = rand::thread_rng();
    let wrapped = public
        .encrypt(&mut rng, Oaep::new::<Sha256>(), &session_key)
        .expect("rsa OAEP encrypt failed");

    let stdin = format!("wrapped_key_b64={}\n", B64.encode(&wrapped));
    let out = oracle(&["unwrap"], Some(&stdin));
    let expected = format!("UNWRAP_OK {}", B64.encode(session_key));
    assert!(
        out.trim().starts_with(&expected),
        "oracle unwrap result mismatch: {out}"
    );
}
