//! Symmetric key/IV creation and encrypted-stream length calculation
//! (port of `Crypto.createSymKey` / `calcSymEncLength`).

use crate::algorithms::{DEFAULT_GCM_IV_LENGTH, SymCipher};
use crate::error::CryptoError;
use rand::RngCore;

/// Generate a random session key for a cipher URI.
pub fn create_sym_key(cipher_uri: &str) -> Result<Vec<u8>, CryptoError> {
    let cipher = SymCipher::from_uri(cipher_uri)
        .ok_or_else(|| CryptoError::UnsupportedAlgorithm(cipher_uri.to_string()))?;
    let mut key = vec![0u8; cipher.key_length()];
    rand::thread_rng().fill_bytes(&mut key);
    Ok(key)
}

/// Random IV of the cipher's default length (GCM: 12 bytes unless
/// overridden).
pub fn create_iv(cipher_uri: &str, iv_length: Option<usize>) -> Result<Vec<u8>, CryptoError> {
    let cipher = SymCipher::from_uri(cipher_uri)
        .ok_or_else(|| CryptoError::UnsupportedAlgorithm(cipher_uri.to_string()))?;
    let len = match cipher {
        SymCipher::AesGcm { .. } => iv_length.unwrap_or(DEFAULT_GCM_IV_LENGTH),
        _ => cipher.iv_length(),
    };
    let mut iv = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut iv);
    Ok(iv)
}

/// Encrypted stream length for a plaintext of `len` bytes, byte-exact port
/// of `Crypto.calcSymEncLength` including its quirk that non-block-aligned
/// plaintext lengths round DOWN inside the formula (the resulting length
/// still matches the actual stream, because a full padding block follows).
pub fn calc_sym_enc_length(len: u64, cipher_uri: &str, iv_length: usize) -> Option<u64> {
    match cipher_uri {
        crate::algorithms::CIPHER_TRIPLEDES_CBC => Some(16 + (len / 8) * 8),
        _ if cipher_uri.ends_with("-cbc") => Some(32 + (len / 16) * 16),
        _ if cipher_uri.ends_with("-gcm") && iv_length == 12 => Some(28 + len),
        _ if cipher_uri.ends_with("-gcm") => Some(32 + len),
        _ => None,
    }
}

/// Legacy overload with the default GCM IV length.
pub fn calc_sym_enc_length_default(len: u64, cipher_uri: &str) -> Option<u64> {
    calc_sym_enc_length(len, cipher_uri, DEFAULT_GCM_IV_LENGTH)
}
