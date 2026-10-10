//! Port of `TestCrypto` (calc length + weak matrix), `TestSymCipher*`
//! roundtrips, and registry roundtrips for every supported algorithm.

use std::io::{Read, Write};

use osci_crypto::algorithms::{
    self, CIPHER_AES128_CBC, CIPHER_AES128_GCM, CIPHER_AES192_CBC, CIPHER_AES192_GCM,
    CIPHER_AES256_CBC, CIPHER_AES256_GCM, CIPHER_TRIPLEDES_CBC, DEFAULT_KEY_TRANSPORT,
    DIGEST_SHA256, DIGEST_SHA512, KEY_TRANSPORT_RSA_1_5, SIGNATURE_RSA_RIPEMD160,
    SIGNATURE_RSA_SHA1, SIGNATURE_RSA_SHA3_256_PSS, SIGNATURE_RSA_SHA3_512_PSS,
    SIGNATURE_RSA_SHA256, SIGNATURE_RSA_SHA256_PSS, SIGNATURE_RSA_SHA512, SIGNATURE_RSA_SHA512_PSS,
    SymCipher,
};
use osci_crypto::calc::{calc_sym_enc_length, calc_sym_enc_length_default, create_sym_key};
use osci_crypto::software::{
    Decrypter, RsaDecrypter, RsaSigner, Signer, sign_rsa, unwrap_session_key, verify_rsa,
    wrap_session_key,
};
use osci_crypto::symcipher::{DecryptReader, EncryptWriter, oneshot};
use osci_crypto::weak::{is_weak_algorithm, is_weak_key};

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

fn test_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (900 + i).rem_euclid(256) as u8).collect()
}

// ------------------------------------------------------ TestCrypto port

/// Port of `testCalcSymEncLength`: the formula matches the actual
/// encrypted stream length for all ciphers and lengths 0..1000.
#[test]
fn calc_sym_enc_length_matches_streams() {
    let ciphers = [
        CIPHER_TRIPLEDES_CBC,
        CIPHER_AES128_CBC,
        CIPHER_AES192_CBC,
        CIPHER_AES256_CBC,
        CIPHER_AES128_GCM,
        CIPHER_AES192_GCM,
        CIPHER_AES256_GCM,
    ];
    for cipher_uri in ciphers {
        let cipher = SymCipher::from_uri(cipher_uri).unwrap();
        let key = create_sym_key(cipher_uri).unwrap();
        let mut data = Vec::new();
        for i in 0..1000usize {
            let mut sink = Vec::new();
            {
                let mut w = EncryptWriter::new(&mut sink, cipher, &key, None).expect("writer");
                w.write_all(&data).unwrap();
                w.finish().unwrap();
            }
            let actual = sink.len() as u64;
            assert_eq!(
                calc_sym_enc_length_default(i as u64, cipher_uri),
                Some(actual),
                "{cipher_uri} at {i} bytes"
            );
            if cipher_uri.ends_with("-gcm") {
                // 16-byte IV variant
                let mut sink = Vec::new();
                let iv = [7u8; 16];
                {
                    let mut w =
                        EncryptWriter::new(&mut sink, cipher, &key, Some(&iv)).expect("writer");
                    w.write_all(&data).unwrap();
                    w.finish().unwrap();
                }
                assert_eq!(
                    calc_sym_enc_length(i as u64, cipher_uri, 16),
                    Some(sink.len() as u64),
                    "{cipher_uri} (IV 16) at {i} bytes"
                );
            }
            data.push((i % 251) as u8);
        }
    }
}

fn date(y: i32, m: u32, d: u32) -> chrono::DateTime<chrono::Utc> {
    chrono::NaiveDate::from_ymd_opt(y, m, d)
        .unwrap()
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_utc()
}

/// Port of the six `testIsWeakDateStringInt*` cases.
#[test]
fn weak_key_matrix() {
    let cases: &[(&str, usize, Option<chrono::DateTime<chrono::Utc>>, bool)] = &[
        // RSA 1024: null-date weak; before 2008-04-01 strong; after weak
        ("RSA", 1024, None, true),
        ("RSA", 1024, Some(date(2008, 3, 31)), false),
        ("RSA", 1024, Some(date(2008, 4, 1)), true),
        // RSA 2008-bit keys behave like 1024 (the Java test uses 2008
        // as a size close to the boundary)
        ("RSA", 2008, None, true),
        ("RSA", 2008, Some(date(2008, 3, 31)), false),
        ("RSA", 2008, Some(date(2008, 4, 1)), true),
        // RSA above 2048 never weak (yet)
        ("RSA", 2049, None, false),
        ("RSA", 2049, Some(date(2020, 12, 31)), false),
        ("RSA", 2049, Some(date(2021, 1, 1)), false),
        // EC below 224 always weak
        ("EC", 159, None, true),
        ("EC", 159, Some(date(1899, 12, 31)), true),
        ("EC", 159, Some(date(1900, 1, 1)), true),
        ("EC", 160, None, true),
        ("EC", 160, Some(date(2006, 12, 31)), true),
        ("EC", 160, Some(date(2007, 1, 1)), true),
        // EC >= 224 fine
        ("EC", 250, None, false),
        ("EC", 250, Some(date(2020, 12, 31)), false),
        ("EC", 250, Some(date(2021, 1, 1)), false),
        ("EC", 251, None, false),
        ("EC", 251, Some(date(2030, 12, 31)), false),
        ("EC", 251, Some(date(2031, 1, 1)), false),
    ];
    for (algorithm, bits, when, expected_weak) in cases {
        assert_eq!(
            is_weak_key(*when, algorithm, *bits),
            *expected_weak,
            "{algorithm}/{bits} at {when:?}"
        );
    }
}

/// RIPEMD/SHA-1 algorithm out-dates (the semantics behind
/// `hasWeakSignature`, cross-checked with TestRIPEMD160 expectations).
#[test]
fn weak_algorithm_dates() {
    // ripemd160: strong on 31.12.2010, weak from 1.1.2011
    assert!(!is_weak_algorithm(
        Some(date(2010, 12, 31)),
        algorithms::DIGEST_RIPEMD160
    ));
    assert!(is_weak_algorithm(
        Some(date(2011, 1, 1)),
        algorithms::DIGEST_RIPEMD160
    ));
    assert!(is_weak_algorithm(None, algorithms::DIGEST_RIPEMD160));
    // sha1 weak from 1.7.2008
    assert!(!is_weak_algorithm(
        Some(date(2008, 6, 30)),
        algorithms::DIGEST_SHA1
    ));
    assert!(is_weak_algorithm(
        Some(date(2008, 7, 1)),
        algorithms::DIGEST_SHA1
    ));
    // modern algorithms never flagged
    assert!(!is_weak_algorithm(None, DIGEST_SHA256));
    assert!(!is_weak_algorithm(None, DIGEST_SHA512));
}

// ------------------------------------------------------- SymCipher ports

#[test]
fn sym_cipher_roundtrips_all_ciphers_chunked() {
    let ciphers = [
        (CIPHER_AES128_CBC, 16),
        (CIPHER_AES192_CBC, 24),
        (CIPHER_AES256_CBC, 32),
        (CIPHER_TRIPLEDES_CBC, 24),
        (CIPHER_AES128_GCM, 16),
        (CIPHER_AES256_GCM, 32),
    ];
    let data = test_data(7000); // multi-block, odd length
    for (uri, key_len) in ciphers {
        let cipher = SymCipher::from_uri(uri).unwrap();
        let key = vec![0x42; key_len];
        let mut sink = Vec::new();
        {
            let mut w = EncryptWriter::new(&mut sink, cipher, &key, None).unwrap();
            for chunk in data.chunks(997) {
                w.write_all(chunk).unwrap();
            }
            w.finish().unwrap();
        }
        let mut plain = Vec::new();
        DecryptReader::new(&sink[..], cipher, &key)
            .unwrap()
            .read_to_end(&mut plain)
            .unwrap_or_else(|e| panic!("{uri}: {e}"));
        assert_eq!(plain, data, "{uri} roundtrip");
    }
}

#[test]
fn gcm_matches_aes_gcm_crate() {
    use aes_gcm::aead::{Aead, KeyInit};
    let key = [3u8; 32];
    let iv = [9u8; 12];
    let data = test_data(1000);
    // ours
    let ours = oneshot::encrypt(SymCipher::AesGcm { key_len: 32 }, &key, &iv, &data).unwrap();
    // reference: aes-gcm 0.10 with the same key/nonce
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
    let expected = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&iv), data.as_slice())
        .unwrap();
    assert_eq!(
        &ours[12..],
        &expected[..],
        "ciphertext+tag identical to aes-gcm"
    );
    assert_eq!(&ours[..12], &iv);
    // and decrypt back
    let plain = oneshot::decrypt(SymCipher::AesGcm { key_len: 32 }, &key, &ours).unwrap();
    assert_eq!(plain, data);
}

#[test]
fn gcm_tampering_detected() {
    let key = [5u8; 32];
    let data = b"attack detection";
    let mut sink =
        oneshot::encrypt(SymCipher::AesGcm { key_len: 32 }, &key, &[1u8; 12], data).unwrap();
    let last = sink.len() - 1;
    sink[last] ^= 1;
    assert!(oneshot::decrypt(SymCipher::AesGcm { key_len: 32 }, &key, &sink).is_err());
}

// ------------------------------------------------------- signature registry

fn alice_signature_pem() -> std::path::PathBuf {
    corpus().join("certs").join("alice_signature_4096.pem")
}

#[test]
fn rsa_sign_verify_all_registry_algorithms() {
    let signer = RsaSigner::from_pem_dump(alice_signature_pem().to_str().unwrap(), None).unwrap();
    let data = b"registry roundtrip payload";
    let public = signer.certificate().rsa_public_key().unwrap();
    for algorithm in [
        SIGNATURE_RSA_SHA256_PSS,
        SIGNATURE_RSA_SHA512_PSS,
        SIGNATURE_RSA_SHA3_256_PSS,
        SIGNATURE_RSA_SHA3_512_PSS,
        SIGNATURE_RSA_SHA1,
        SIGNATURE_RSA_SHA256,
        SIGNATURE_RSA_SHA512,
        SIGNATURE_RSA_RIPEMD160,
    ] {
        let signature = sign_rsa(signer.private_key(), data, algorithm)
            .unwrap_or_else(|e| panic!("{algorithm}: {e}"));
        verify_rsa(&public, data, &signature, algorithm)
            .unwrap_or_else(|e| panic!("{algorithm}: {e}"));
        // tampering must fail
        let mut broken = signature.clone();
        broken[0] ^= 0xff;
        assert!(
            verify_rsa(&public, data, &broken, algorithm).is_err(),
            "{algorithm}"
        );
    }
}

#[test]
fn ecdsa_sign_verify() {
    use osci_crypto::software::{sign_ec_p256, verify_ec_p256};
    // generate a p-256 key (no fixture PEM needed for a pure roundtrip)
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let signing = p256::ecdsa::SigningKey::from(&secret);
    let verifying = p256::ecdsa::VerifyingKey::from(&signing);
    let data = b"ecdsa roundtrip";
    let sig = sign_ec_p256(&signing, data, algorithms::SIGNATURE_ECDSA_SHA256).unwrap();
    assert_eq!(sig.len(), 64, "raw r||s encoding");
    verify_ec_p256(&verifying, data, &sig, algorithms::SIGNATURE_ECDSA_SHA256).unwrap();
    let mut broken = sig.clone();
    broken[10] ^= 1;
    assert!(
        verify_ec_p256(
            &verifying,
            data,
            &broken,
            algorithms::SIGNATURE_ECDSA_SHA256
        )
        .is_err()
    );
}

// ----------------------------------------------------------- wrap / unwrap

#[test]
fn session_key_wrap_unwrap_roundtrips() {
    let decrypter = RsaDecrypter::from_pem_dump(
        corpus()
            .join("certs")
            .join("alice_cipher_4096.pem")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let public_cert = decrypter.certificate();
    let private = {
        use rsa::pkcs8::DecodePrivateKey;
        let dump =
            std::fs::read_to_string(corpus().join("certs").join("alice_cipher_4096.pem")).unwrap();
        let start = dump.find("-----BEGIN PRIVATE KEY-----").unwrap();
        let end = dump[start..].find("-----END PRIVATE KEY-----").unwrap()
            + start
            + "-----END PRIVATE KEY-----".len();
        rsa::RsaPrivateKey::from_pkcs8_pem(&dump[start..end]).unwrap()
    };
    for digest in [
        algorithms::DIGEST_SHA256,
        algorithms::DIGEST_SHA384,
        algorithms::DIGEST_SHA512,
    ] {
        let session_key = [77u8; 32];
        let wrapped =
            wrap_session_key(public_cert, &session_key, DEFAULT_KEY_TRANSPORT, digest).unwrap();
        let unwrapped = unwrap_session_key(
            &private,
            &wrapped,
            DEFAULT_KEY_TRANSPORT,
            None,
            Some(digest),
        )
        .unwrap_or_else(|e| panic!("oaep {digest}: {e}"));
        assert_eq!(unwrapped, session_key, "OAEP {digest}");
    }
    // legacy v1.5
    let session_key = [88u8; 16];
    let wrapped = wrap_session_key(
        public_cert,
        &session_key,
        KEY_TRANSPORT_RSA_1_5,
        DIGEST_SHA256,
    )
    .unwrap();
    assert_eq!(
        decrypter.decrypt_pkcs1v15(&wrapped).unwrap(),
        session_key,
        "v1.5 unwrap through the Decrypter SPI"
    );
}

#[test]
fn certificates_report_key_sizes() {
    let signer = RsaSigner::from_pem_dump(alice_signature_pem().to_str().unwrap(), None).unwrap();
    assert_eq!(signer.certificate().key_algorithm(), "RSA");
    assert_eq!(signer.certificate().key_size(), 4096);
    assert_eq!(signer.key_size(), 4096);

    let mut certs = osci_crypto::Certificate::from_pem_bundle(
        &std::fs::read_to_string(corpus().join("certs").join("ECDSA_NIST_p384.pem")).unwrap(),
    )
    .unwrap();
    let ec = certs.remove(0);
    assert_eq!(ec.key_algorithm(), "EC");
    assert_eq!(ec.key_size(), 384);

    // the legacy EC keystores of the corpus are weak by policy
    let mut weak = osci_crypto::Certificate::from_pem_bundle(
        &std::fs::read_to_string(corpus().join("certs").join("ECDSA_prime192v3_eec.pem")).unwrap(),
    )
    .unwrap();
    let weak_cert = weak.remove(0);
    assert_eq!(weak_cert.key_size(), 192);
    assert!(is_weak_key(
        None,
        weak_cert.key_algorithm(),
        weak_cert.key_size()
    ));
}
