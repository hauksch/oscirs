//! XML algorithm identifiers and the URI registry
//! (port of `de.osci.osci12.common.Constants` algorithm constants and
//! `JCA_JCE_MAP`), with dispatch to RustCrypto implementations.
//!
//! Note: `osci-core::xml::c14n` keeps its own digest dispatch because the
//! canonicalizer must not depend on the crypto crate; the URIs there and
//! here are the same constants.

use rsa::sha2::{Sha256, Sha384, Sha512};

pub const SIGNATURE_RSA_SHA256_PSS: &str = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
pub const SIGNATURE_RSA_SHA512_PSS: &str = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1";
pub const SIGNATURE_RSA_SHA3_256_PSS: &str =
    "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1";
pub const SIGNATURE_RSA_SHA3_384_PSS: &str =
    "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1";
pub const SIGNATURE_RSA_SHA3_512_PSS: &str =
    "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1";
pub const SIGNATURE_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
pub const SIGNATURE_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const SIGNATURE_RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
pub const SIGNATURE_RSA_RIPEMD160: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
pub const SIGNATURE_RSA_RIPEMD160_RFC4051: &str =
    "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
pub const SIGNATURE_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
pub const SIGNATURE_ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
pub const SIGNATURE_ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

pub const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const DIGEST_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub const DIGEST_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
pub const DIGEST_RIPEMD160: &str = "http://www.w3.org/2001/04/xmlenc#ripemd160";
pub const DIGEST_SHA3_256: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-256";
pub const DIGEST_SHA3_384: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-384";
pub const DIGEST_SHA3_512: &str = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";

pub const CIPHER_AES128_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
pub const CIPHER_AES192_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
pub const CIPHER_AES256_CBC: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
pub const CIPHER_TRIPLEDES_CBC: &str = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
pub const CIPHER_AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
pub const CIPHER_AES192_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
pub const CIPHER_AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

pub const KEY_TRANSPORT_RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
pub const KEY_TRANSPORT_RSA_1_5: &str = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

pub const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
pub const MGF1_SHA384: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha384";
pub const MGF1_SHA512: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha512";

/// Default signature algorithm (`DialogHandler` default).
pub const DEFAULT_SIGNATURE: &str = SIGNATURE_RSA_SHA256_PSS;
/// Default digest algorithm (`DialogHandler` default).
pub const DEFAULT_DIGEST: &str = DIGEST_SHA256;
/// Default symmetric cipher (Korrigenda 7: AES-256-GCM).
pub const DEFAULT_SYMMETRIC_CIPHER: &str = CIPHER_AES256_GCM;
/// Default key transport.
pub const DEFAULT_KEY_TRANSPORT: &str = KEY_TRANSPORT_RSA_OAEP;
/// Default GCM IV length in bytes.
pub const DEFAULT_GCM_IV_LENGTH: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymCipher {
    AesCbc { key_len: usize },
    TripleDesCbc,
    AesGcm { key_len: usize },
}

impl SymCipher {
    /// Resolve a symmetric cipher URI (accepted: the seven OSCI URIs).
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            CIPHER_AES128_CBC => Some(Self::AesCbc { key_len: 16 }),
            CIPHER_AES192_CBC => Some(Self::AesCbc { key_len: 24 }),
            CIPHER_AES256_CBC => Some(Self::AesCbc { key_len: 32 }),
            CIPHER_TRIPLEDES_CBC => Some(Self::TripleDesCbc),
            CIPHER_AES128_GCM => Some(Self::AesGcm { key_len: 16 }),
            CIPHER_AES192_GCM => Some(Self::AesGcm { key_len: 24 }),
            CIPHER_AES256_GCM => Some(Self::AesGcm { key_len: 32 }),
            _ => None,
        }
    }

    /// IV length in bytes for this cipher (Java `SymCipherOutputStream`:
    /// 8 for 3DES, 12 or 16 for AES-GCM, 16 for AES-CBC).
    pub fn iv_length(&self) -> usize {
        match self {
            Self::AesCbc { .. } => 16,
            Self::TripleDesCbc => 8,
            Self::AesGcm { .. } => DEFAULT_GCM_IV_LENGTH,
        }
    }

    pub fn key_length(&self) -> usize {
        match self {
            Self::AesCbc { key_len } | Self::AesGcm { key_len } => *key_len,
            Self::TripleDesCbc => 24,
        }
    }
}

/// Digest `data` with the algorithm identified by a digest or signature
/// method URI.
pub fn digest_bytes(uri: &str, data: &[u8]) -> Option<Vec<u8>> {
    use rsa::sha2::Digest as _;
    match uri {
        DIGEST_SHA1 | SIGNATURE_RSA_SHA1 => Some(sha1::Sha1::digest(data).to_vec()),
        DIGEST_SHA256
        | SIGNATURE_RSA_SHA256
        | SIGNATURE_RSA_SHA256_PSS
        | SIGNATURE_ECDSA_SHA256 => Some(Sha256::digest(data).to_vec()),
        DIGEST_SHA384 => Some(Sha384::digest(data).to_vec()),
        DIGEST_SHA512
        | SIGNATURE_RSA_SHA512
        | SIGNATURE_RSA_SHA512_PSS
        | SIGNATURE_ECDSA_SHA512 => Some(Sha512::digest(data).to_vec()),
        DIGEST_RIPEMD160 | SIGNATURE_RSA_RIPEMD160 => {
            Some(ripemd::Ripemd160::digest(data).to_vec())
        }
        DIGEST_SHA3_256 | SIGNATURE_RSA_SHA3_256_PSS => Some(sha3::Sha3_256::digest(data).to_vec()),
        DIGEST_SHA3_384 | SIGNATURE_RSA_SHA3_384_PSS => Some(sha3::Sha3_384::digest(data).to_vec()),
        DIGEST_SHA3_512 | SIGNATURE_RSA_SHA3_512_PSS => Some(sha3::Sha3_512::digest(data).to_vec()),
        _ => None,
    }
}

/// SHA-1 for legacy digests/signatures (`rsa-sha1`, still parsed and
/// verified for interop; flagged weak by the policy module).
pub use sha1::Sha1;
