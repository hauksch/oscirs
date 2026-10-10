//! OSCI-Transport 1.2 crypto layer: `Signer`/`Decrypter` SPI traits, the
//! software implementation (RSA-PSS/PKCS#1v1.5, ECDSA raw r||s, AES-GCM/CBC,
//! 3DES, RSA-OAEP/v1.5 key transport), the XML algorithm registry and the
//! weak-crypto policy - mirroring `de.osci.osci12.encryption.Crypto` and
//! `de.osci.helper.SymCipher*` of the Java reference (tag 2.6.1).

pub mod algorithms;
pub mod calc;
pub mod certificate;
pub mod error;
pub mod software;
pub mod symcipher;
pub mod weak;

pub use certificate::Certificate;
pub use error::CryptoError;
