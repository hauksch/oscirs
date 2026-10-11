//! OSCI-Transport 1.2 transport layer: the `Transport` SPI (mirroring
//! `de.osci.osci12.extinterfaces.TransportI`) and an in-process loopback
//! transport with a mock intermediary for offline integration tests.

use std::sync::Mutex;

/// Transport SPI: sends a full MIME message stream and returns the
/// response stream.
pub trait Transport: Send + Sync {
    fn send(&self, message: &[u8]) -> Result<Vec<u8>, TransportError>;
}

#[derive(Debug, thiserror::Error)]
#[error("transport: {0}")]
pub struct TransportError(pub String);

/// The intermediary's reply to one message.
pub struct IntermediaryReply {
    pub message: Vec<u8>,
}

/// A scripted in-process intermediary: routes by message type and builds
/// response messages with correct control-block protocol (response =
/// request challenge, fresh challenge, same sequence and conversation).
pub trait MockIntermediary: Send + Sync {
    fn handle(&self, message: &[u8]) -> Result<Vec<u8>, TransportError>;
}

/// Loopback transport wiring a client to a mock intermediary.
pub struct LoopbackTransport {
    intermediary: Mutex<Box<dyn MockIntermediary>>,
    pub sent: Mutex<Vec<Vec<u8>>>,
}

impl LoopbackTransport {
    pub fn new(intermediary: Box<dyn MockIntermediary>) -> Self {
        Self {
            intermediary: Mutex::new(intermediary),
            sent: Mutex::new(Vec::new()),
        }
    }

    /// Handle to the raw sent messages (wire assertions in tests).
    pub fn sent_handle(&self) -> std::sync::MutexGuard<'_, Vec<Vec<u8>>> {
        match self.sent.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Transport for LoopbackTransport {
    fn send(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.sent.lock().unwrap().push(message.to_vec());
        self.intermediary.lock().unwrap().handle(message)
    }
}

/// Error collector helper for tests: FailReply replies with a SOAP-level
/// OSCI feedback code instead of a valid response.
pub struct TransportErrorCollector {
    pub failures: Mutex<Vec<String>>,
}

impl Default for TransportErrorCollector {
    fn default() -> Self {
        Self {
            failures: Mutex::new(Vec::new()),
        }
    }
}
