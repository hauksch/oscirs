//! `Signer` / `Decrypter` SPI traits (port of
//! `de.osci.osci12.extinterfaces.crypto`) and a software implementation
//! over PEM keys - the Rust counterpart of the Java `PKCS12Signer` /
//! `PKCS12Decrypter` samples, minus PKCS#12 parsing (the test corpus ships
//! openssl PEM dumps of every keystore).

use rsa::sha2::{Sha256, Sha384, Sha512};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::traits::PublicKeyParts;

use crate::algorithms::{
    DEFAULT_KEY_TRANSPORT, KEY_TRANSPORT_RSA_1_5, MGF1_SHA256, MGF1_SHA384, MGF1_SHA512,
};
use crate::certificate::Certificate;
use crate::error::CryptoError;

/// Signs raw bytes under a signature-method URI; implementations choose
/// their own certificate and preferred algorithm.
pub trait Signer: Send + Sync {
    fn certificate(&self) -> &Certificate;
    /// Preferred signature algorithm URI, or `None` to use the context
    /// default.
    fn algorithm(&self) -> Option<String> {
        None
    }
    fn sign(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, CryptoError>;
}

/// Unwraps RSA-encrypted session keys (v1.5 or OAEP with the URIs the
/// message declares).
pub trait Decrypter: Send + Sync {
    fn certificate(&self) -> &Certificate;
    /// RSAES-PKCS1-v1_5 unwrap.
    fn decrypt_pkcs1v15(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// RSAES-OAEP unwrap with explicit MGF and digest algorithm URIs.
    fn decrypt_oaep(
        &self,
        data: &[u8],
        mgf_algorithm: &str,
        digest_algorithm: &str,
    ) -> Result<Vec<u8>, CryptoError>;
}

// ------------------------------------------------------------- signing ops

/// Sign with an RSA private key under the given signature-method URI.
/// PSS uses MGF1 with the same hash and salt length = hash length
/// (BouncyCastle's `SHAxxxwithRSAandMGF1` convention, cross-verified
/// against the Java oracle in M0).
pub fn sign_rsa(
    key: &rsa::RsaPrivateKey,
    data: &[u8],
    algorithm: &str,
) -> Result<Vec<u8>, CryptoError> {
    use rsa::pkcs1v15::SigningKey as V15SigningKey;
    use rsa::pss::SigningKey;
    use rsa::signature::Signer as _;

    macro_rules! pss_sign {
        ($digest:ty) => {{
            let signing_key: SigningKey<$digest> = SigningKey::new(key.clone());
            let mut rng = rand::thread_rng();
            signing_key.sign_with_rng(&mut rng, data).to_vec()
        }};
    }
    macro_rules! v15_sign {
        ($digest:ty) => {{
            let signing_key: V15SigningKey<$digest> = V15SigningKey::new(key.clone());
            signing_key.sign(data).to_vec()
        }};
    }

    match algorithm {
        crate::algorithms::SIGNATURE_RSA_SHA256_PSS => Ok(pss_sign!(Sha256)),
        crate::algorithms::SIGNATURE_RSA_SHA512_PSS => Ok(pss_sign!(Sha512)),
        crate::algorithms::SIGNATURE_RSA_SHA3_256_PSS => Ok(pss_sign!(sha3::Sha3_256)),
        crate::algorithms::SIGNATURE_RSA_SHA3_384_PSS => Ok(pss_sign!(sha3::Sha3_384)),
        crate::algorithms::SIGNATURE_RSA_SHA3_512_PSS => Ok(pss_sign!(sha3::Sha3_512)),
        crate::algorithms::SIGNATURE_RSA_SHA1 => Ok(v15_sign!(sha1::Sha1)),
        crate::algorithms::SIGNATURE_RSA_SHA256 => Ok(v15_sign!(Sha256)),
        crate::algorithms::SIGNATURE_RSA_SHA512 => Ok(v15_sign!(Sha512)),
        crate::algorithms::SIGNATURE_RSA_RIPEMD160 => Ok(v15_sign!(ripemd::Ripemd160)),
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Verify an RSA signature (PSS or v1.5, hash from the URI).
pub fn verify_rsa(
    key: &rsa::RsaPublicKey,
    data: &[u8],
    signature: &[u8],
    algorithm: &str,
) -> Result<(), CryptoError> {
    use rsa::pkcs1v15::{Signature as V15Signature, VerifyingKey as V15VerifyingKey};
    use rsa::pss::{Signature as PssSignature, VerifyingKey};

    macro_rules! pss_verify {
        ($digest:ty) => {{
            let vk: VerifyingKey<$digest> = VerifyingKey::new(key.clone());
            let sig = PssSignature::try_from(signature).map_err(|_| CryptoError::Verification)?;
            vk.verify(data, &sig).map_err(|_| CryptoError::Verification)
        }};
    }
    macro_rules! v15_verify {
        ($digest:ty) => {{
            let vk: V15VerifyingKey<$digest> = V15VerifyingKey::new(key.clone());
            let sig = V15Signature::try_from(signature).map_err(|_| CryptoError::Verification)?;
            vk.verify(data, &sig).map_err(|_| CryptoError::Verification)
        }};
    }

    match algorithm {
        crate::algorithms::SIGNATURE_RSA_SHA256_PSS => pss_verify!(Sha256),
        crate::algorithms::SIGNATURE_RSA_SHA512_PSS => pss_verify!(Sha512),
        crate::algorithms::SIGNATURE_RSA_SHA3_256_PSS => pss_verify!(sha3::Sha3_256),
        crate::algorithms::SIGNATURE_RSA_SHA3_384_PSS => pss_verify!(sha3::Sha3_384),
        crate::algorithms::SIGNATURE_RSA_SHA3_512_PSS => pss_verify!(sha3::Sha3_512),
        crate::algorithms::SIGNATURE_RSA_SHA1 => v15_verify!(sha1::Sha1),
        crate::algorithms::SIGNATURE_RSA_SHA256 => v15_verify!(Sha256),
        crate::algorithms::SIGNATURE_RSA_SHA512 => v15_verify!(Sha512),
        crate::algorithms::SIGNATURE_RSA_RIPEMD160 => v15_verify!(ripemd::Ripemd160),
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Sign with an EC key; the signature is emitted as raw r||s (the OSCI
/// convention Java spells `SHAxxxwithCVC-ECDSA`).
pub fn sign_ec_p256(
    key: &p256::ecdsa::SigningKey,
    data: &[u8],
    algorithm: &str,
) -> Result<Vec<u8>, CryptoError> {
    use p256::ecdsa::signature::Signer as _;
    match algorithm {
        crate::algorithms::SIGNATURE_ECDSA_SHA256 => {
            let sig: p256::ecdsa::Signature = key.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
    }
}

pub fn sign_ec_p384(
    key: &p384::ecdsa::SigningKey,
    data: &[u8],
    algorithm: &str,
) -> Result<Vec<u8>, CryptoError> {
    use p384::ecdsa::signature::Signer as _;
    match algorithm {
        crate::algorithms::SIGNATURE_ECDSA_SHA384 | crate::algorithms::SIGNATURE_ECDSA_SHA256 => {
            let sig: p384::ecdsa::Signature = key.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Verify a raw r||s P-256 ECDSA signature.
pub fn verify_ec_p256(
    key: &p256::ecdsa::VerifyingKey,
    data: &[u8],
    signature: &[u8],
    algorithm: &str,
) -> Result<(), CryptoError> {
    use p256::ecdsa::signature::Verifier as _;
    match algorithm {
        crate::algorithms::SIGNATURE_ECDSA_SHA256 => {
            let sig = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| CryptoError::Verification)?;
            key.verify(data, &sig)
                .map_err(|_| CryptoError::Verification)
        }
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Verify a raw r||s P-384 ECDSA signature (the digest the OSCI method
/// URIs name is the hash input; P-384 keys accept SHA-384 and SHA-256,
/// mirroring `sign_ec_p384`).
pub fn verify_ec_p384(
    key: &p384::ecdsa::VerifyingKey,
    data: &[u8],
    signature: &[u8],
    algorithm: &str,
) -> Result<(), CryptoError> {
    use p384::ecdsa::signature::Verifier as _;
    match algorithm {
        crate::algorithms::SIGNATURE_ECDSA_SHA384 | crate::algorithms::SIGNATURE_ECDSA_SHA256 => {
            let sig = p384::ecdsa::Signature::from_slice(signature)
                .map_err(|_| CryptoError::Verification)?;
            key.verify(data, &sig)
                .map_err(|_| CryptoError::Verification)
        }
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
    }
}

// ------------------------------------------------------------ wrap / unwrap

/// Wrap a session key for `cert` (Java `Crypto.doRSAEncryption`): OAEP by
/// default (SHA-2 family, MGF1 = same hash, SHA-3 mapped to its SHA-2
/// counterpart like the Java implementation), v1.5 for the legacy URI.
pub fn wrap_session_key(
    cert: &Certificate,
    session_key: &[u8],
    algorithm: &str,
    digest_algorithm: &str,
) -> Result<Vec<u8>, CryptoError> {
    let public = cert.rsa_public_key()?;
    let mut rng = rand::thread_rng();
    match algorithm {
        DEFAULT_KEY_TRANSPORT => {
            // Java: SHA-3 digests are mapped to SHA-256/512 for OAEP
            let digest = match digest_algorithm {
                crate::algorithms::DIGEST_SHA3_256 => crate::algorithms::DIGEST_SHA256.to_string(),
                crate::algorithms::DIGEST_SHA3_384 | crate::algorithms::DIGEST_SHA3_512 => {
                    crate::algorithms::DIGEST_SHA512.to_string()
                }
                uri => uri.to_string(),
            };
            match digest.as_str() {
                crate::algorithms::DIGEST_SHA256 => {
                    use rsa::Oaep;
                    public
                        .encrypt(&mut rng, Oaep::new::<Sha256>(), session_key)
                        .map_err(|e| CryptoError::Encryption(e.to_string()))
                }
                crate::algorithms::DIGEST_SHA384 => {
                    use rsa::Oaep;
                    public
                        .encrypt(&mut rng, Oaep::new::<Sha384>(), session_key)
                        .map_err(|e| CryptoError::Encryption(e.to_string()))
                }
                crate::algorithms::DIGEST_SHA512 => {
                    use rsa::Oaep;
                    public
                        .encrypt(&mut rng, Oaep::new::<Sha512>(), session_key)
                        .map_err(|e| CryptoError::Encryption(e.to_string()))
                }
                other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
            }
        }
        KEY_TRANSPORT_RSA_1_5 => {
            use rsa::pkcs1v15::Pkcs1v15Encrypt;
            public
                .encrypt(&mut rng, Pkcs1v15Encrypt, session_key)
                .map_err(|e| CryptoError::Encryption(e.to_string()))
        }
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Unwrap a session key with a private key (Java `Crypto.doRSADecryption`).
pub fn unwrap_session_key(
    key: &rsa::RsaPrivateKey,
    data: &[u8],
    algorithm: &str,
    mgf_algorithm: Option<&str>,
    digest_algorithm: Option<&str>,
) -> Result<Vec<u8>, CryptoError> {
    // mirror wrap_session_key's SHA-3 -> SHA-2 mapping: the Java
    // convention encrypts with the SHA-2 primitives while the wire keeps
    // the original URI - without it such envelopes can never be opened
    let digest_algorithm = digest_algorithm.map(|digest| match digest {
        crate::algorithms::DIGEST_SHA3_256 => crate::algorithms::DIGEST_SHA256,
        crate::algorithms::DIGEST_SHA3_384 | crate::algorithms::DIGEST_SHA3_512 => {
            crate::algorithms::DIGEST_SHA512
        }
        other => other,
    });
    match algorithm {
        DEFAULT_KEY_TRANSPORT => {
            let digest = digest_algorithm.unwrap_or(crate::algorithms::DIGEST_SHA256);
            let mgf_hash = mgf_algorithm.unwrap_or(match digest {
                crate::algorithms::DIGEST_SHA256 => MGF1_SHA256,
                crate::algorithms::DIGEST_SHA384 => MGF1_SHA384,
                crate::algorithms::DIGEST_SHA512 => MGF1_SHA512,
                other => return Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
            });
            use rsa::Oaep;
            let padding = match (digest, mgf_hash) {
                (crate::algorithms::DIGEST_SHA256, MGF1_SHA256) => Oaep::new::<Sha256>(),
                (crate::algorithms::DIGEST_SHA384, MGF1_SHA384) => Oaep::new::<Sha384>(),
                (crate::algorithms::DIGEST_SHA512, MGF1_SHA512) => Oaep::new::<Sha512>(),
                _ => {
                    return Err(CryptoError::UnsupportedAlgorithm(format!(
                        "OAEP {digest} / {mgf_hash}"
                    )));
                }
            };
            key.decrypt(padding, data)
                .map_err(|e| CryptoError::Decryption(e.to_string()))
        }
        KEY_TRANSPORT_RSA_1_5 => {
            use rsa::pkcs1v15::Pkcs1v15Encrypt;
            key.decrypt(Pkcs1v15Encrypt, data)
                .map_err(|e| CryptoError::Decryption(e.to_string()))
        }
        other => Err(CryptoError::UnsupportedAlgorithm(other.to_string())),
    }
}

// ------------------------------------------------------- software provider

/// Extract the first `BEGIN PRIVATE KEY` block of a keystore PEM dump.
fn first_private_key_pem_str(dump: &str, name: &str) -> Result<String, CryptoError> {
    let start = dump
        .find("-----BEGIN PRIVATE KEY-----")
        .ok_or_else(|| CryptoError::InvalidKey(format!("no private key in {name}")))?;
    let end_marker = "-----END PRIVATE KEY-----";
    let end = dump[start..]
        .find(end_marker)
        .map(|i| start + i + end_marker.len())
        .ok_or_else(|| CryptoError::InvalidKey("unterminated key".into()))?;
    Ok(dump[start..end].to_string())
}

/// PEM-key software signer for RSA signature certificates.
pub struct RsaSigner {
    key: rsa::RsaPrivateKey,
    certificate: Certificate,
    preferred: Option<String>,
}

impl RsaSigner {
    pub fn from_pem_dump(name: &str, preferred: Option<String>) -> Result<Self, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey;
        let dump =
            std::fs::read_to_string(name).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let pem = first_private_key_pem_str(&dump, name)?;
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(&pem)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let mut certs = Certificate::from_pem_bundle(&dump)?;
        let certificate = certs.remove(0);
        Ok(Self {
            key,
            certificate,
            preferred,
        })
    }

    pub fn private_key(&self) -> &rsa::RsaPrivateKey {
        &self.key
    }

    pub fn key_size(&self) -> usize {
        self.key.size() * 8
    }
}

impl Signer for RsaSigner {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn algorithm(&self) -> Option<String> {
        self.preferred.clone()
    }

    fn sign(&self, data: &[u8], algorithm: &str) -> Result<Vec<u8>, CryptoError> {
        sign_rsa(&self.key, data, algorithm)
    }
}

/// PEM-key software decrypter for RSA cipher certificates.
pub struct RsaDecrypter {
    key: rsa::RsaPrivateKey,
    certificate: Certificate,
}

impl RsaDecrypter {
    pub fn from_pem_dump(name: &str) -> Result<Self, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey;
        let dump =
            std::fs::read_to_string(name).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let pem = first_private_key_pem_str(&dump, name)?;
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(&pem)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let mut certs = Certificate::from_pem_bundle(&dump)?;
        let certificate = certs.remove(0);
        Ok(Self { key, certificate })
    }
}

impl Decrypter for RsaDecrypter {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn decrypt_pkcs1v15(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        unwrap_session_key(&self.key, data, KEY_TRANSPORT_RSA_1_5, None, None)
    }

    fn decrypt_oaep(
        &self,
        data: &[u8],
        mgf_algorithm: &str,
        digest_algorithm: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        unwrap_session_key(
            &self.key,
            data,
            DEFAULT_KEY_TRANSPORT,
            Some(mgf_algorithm),
            Some(digest_algorithm),
        )
    }
}

/// Convenience: the cipher URI for a session key length (Java
/// `Crypto.getCipherAlgoID` behavior for AES keys).
pub fn cipher_for_key(key: &[u8]) -> Option<&'static str> {
    match key.len() {
        16 => Some(crate::algorithms::CIPHER_AES128_GCM),
        24 => Some(crate::algorithms::CIPHER_AES192_GCM),
        32 => Some(crate::algorithms::CIPHER_AES256_GCM),
        _ => None,
    }
}
