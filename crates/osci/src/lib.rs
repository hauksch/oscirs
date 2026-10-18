//! OSCI-Transport 1.2 client library.
//!
//! Facade crate wiring together the message core, crypto and transport SPIs:
//! dialogs, roles, message types and the dialog state machine, mirroring the
//! public API of `de.osci.osci-bibliothek` 2.6.x.
//!
//! The facade re-exports the types an integrator touches daily, so
//! applications can depend on `osci` alone.

pub mod dialog;
pub mod security;
pub mod sign;

// Facade re-exports: the daily-driver types from the inner crates.
pub use osci_core::helper::dates::{format_iso8601, parse_iso8601};
pub use osci_core::message::compose::{OutMessage, compose_message};
pub use osci_core::message::stored::StoredMessage;
pub use osci_core::message::{MessageType, OsciMessage, parse_message};
pub use osci_core::soap::ControlBlock;
pub use osci_crypto::algorithms::{SymCipher, digest_bytes};
pub use osci_crypto::software::{Decrypter, RsaDecrypter, RsaSigner, Signer};
pub use osci_crypto::{Certificate, CryptoError};
pub use osci_transport::{LoopbackTransport, Transport, TransportError};

/// Convenience prelude: `use osci::prelude::*;` pulls in everything an
/// OSCI client integration typically names.
pub mod prelude {
    pub use super::dialog::{Dialog, DialogError};
    pub use super::security::{
        DecryptedContent, SecurityError, SignatureResult, VerificationReport,
        decrypt_all_encrypted_data, verify_document, verify_message,
    };
    pub use super::sign::{SignError, SignParams, sign_message_xml};
    pub use super::{
        Certificate, ControlBlock, CryptoError, MessageType, OutMessage, RsaDecrypter, RsaSigner,
        Signer, StoredMessage, SymCipher, Transport, TransportError, compose_message,
        format_iso8601, parse_iso8601, parse_message,
    };
}
