//! OSCI-Transport 1.2 client library.
//!
//! Facade crate wiring together the message core, crypto and transport SPIs:
//! dialogs, roles, message types and the dialog state machine, mirroring the
//! public API of `de.osci.osci-bibliothek` 2.6.x.

pub mod dialog;
pub mod security;
pub mod sign;
