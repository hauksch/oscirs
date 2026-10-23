//! Error type for the crypto layer.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("signature verification failed")]
    Verification,
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("invalid certificate: {0}")]
    Certificate(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
