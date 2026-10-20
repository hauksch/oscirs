//! X.509 certificate wrapper: DER/PEM parsing, public-key kind and size
//! (Java `Crypto.getKeySize` equivalent), validity window.

use chrono::{DateTime, Utc};

use crate::error::CryptoError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Rsa { bits: usize },
    Ec { bits: usize },
}

/// Curve-resolved EC verifying key of a certificate.
#[derive(Debug, Clone)]
pub enum EcPublicKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

#[derive(Debug, Clone)]
pub struct Certificate {
    der: Vec<u8>,
    /// SubjectPublicKeyInfo DER (RSA public keys parse from this).
    spki_der: Vec<u8>,
    kind: KeyKind,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

impl Certificate {
    pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
        let (rem, cert) = x509_parser::parse_x509_certificate(der)
            .map_err(|e| CryptoError::Certificate(format!("parse: {e}")))?;
        if !rem.is_empty() {
            return Err(CryptoError::Certificate("trailing bytes".into()));
        }
        let spki = cert.public_key();
        let spki_der = spki.raw.to_vec();
        let parsed = spki
            .parsed()
            .map_err(|e| CryptoError::Certificate(format!("public key: {e}")))?;
        let kind = match parsed {
            x509_parser::public_key::PublicKey::RSA(rsa) => {
                // exact bit length like BigInteger.bitLength() (key_size
                // rounds down to bytes; recompute precisely)
                let mut bits = rsa.modulus.len() * 8;
                let mut i = 0;
                while i < rsa.modulus.len() && rsa.modulus[i] == 0 {
                    bits -= 8;
                    i += 1;
                }
                if i < rsa.modulus.len() {
                    let mut leading = rsa.modulus[i];
                    while leading & 0x80 == 0 {
                        bits -= 1;
                        leading <<= 1;
                    }
                }
                KeyKind::Rsa { bits }
            }
            x509_parser::public_key::PublicKey::EC(point) => KeyKind::Ec {
                bits: point.key_size(),
            },
            other => {
                return Err(CryptoError::Certificate(format!(
                    "unsupported public key: {other:?}"
                )));
            }
        };
        let not_before = chrono_secs(cert.validity().not_before.timestamp());
        let not_after = chrono_secs(cert.validity().not_after.timestamp());
        Ok(Self {
            der: der.to_vec(),
            spki_der,
            kind,
            not_before,
            not_after,
        })
    }

    /// All certificates in a PEM bundle (cert chains from keystore dumps).
    pub fn from_pem_bundle(pem: &str) -> Result<Vec<Self>, CryptoError> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;
        let mut out = Vec::new();
        let mut rest = pem;
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let after = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
            let Some(end) = after.find("-----END CERTIFICATE-----") else {
                break;
            };
            let b64: String = after[..end]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let der = B64
                .decode(b64)
                .map_err(|e| CryptoError::Certificate(format!("pem: {e}")))?;
            out.push(Self::from_der(&der)?);
            rest = &after[end + "-----END CERTIFICATE-----".len()..];
        }
        if out.is_empty() {
            return Err(CryptoError::Certificate("no certificate in PEM".into()));
        }
        Ok(out)
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    pub fn key_kind(&self) -> KeyKind {
        self.kind
    }

    /// `RSA` / `EC` like Java `PublicKey.getAlgorithm()`.
    pub fn key_algorithm(&self) -> &'static str {
        match self.kind {
            KeyKind::Rsa { .. } => "RSA",
            KeyKind::Ec { .. } => "EC",
        }
    }

    pub fn key_size(&self) -> usize {
        match self.kind {
            KeyKind::Rsa { bits } | KeyKind::Ec { bits } => bits,
        }
    }

    pub fn rsa_public_key(&self) -> Result<rsa::RsaPublicKey, CryptoError> {
        use rsa::pkcs8::DecodePublicKey;
        rsa::RsaPublicKey::from_public_key_der(self.spki_der())
            .map_err(|e| CryptoError::Certificate(format!("rsa key: {e}")))
    }

    /// The EC public key, curve-resolved by the certificate's key size
    /// (P-256 or P-384; other curves have no verifying-key mapping here).
    pub fn ec_public_key(&self) -> Result<EcPublicKey, CryptoError> {
        use x509_parser::prelude::FromDer as _;
        let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(self.spki_der())
            .map_err(|e| CryptoError::Certificate(format!("spki: {e}")))?;
        let point = match spki.parsed() {
            Ok(x509_parser::public_key::PublicKey::EC(point)) => point,
            other => {
                return Err(CryptoError::Certificate(format!(
                    "not an EC key: {other:?}"
                )));
            }
        };
        match self.kind {
            KeyKind::Ec { bits: 256 } => Ok(EcPublicKey::P256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(point.data())
                    .map_err(|e| CryptoError::Certificate(format!("p256 key: {e}")))?,
            )),
            KeyKind::Ec { bits: 384 } => Ok(EcPublicKey::P384(
                p384::ecdsa::VerifyingKey::from_sec1_bytes(point.data())
                    .map_err(|e| CryptoError::Certificate(format!("p384 key: {e}")))?,
            )),
            other => Err(CryptoError::Certificate(format!(
                "no verifying key for {other:?}"
            ))),
        }
    }

    pub fn not_before(&self) -> Option<DateTime<Utc>> {
        self.not_before
    }

    pub fn not_after(&self) -> Option<DateTime<Utc>> {
        self.not_after
    }
}

fn chrono_secs(secs: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(secs, 0)
}
