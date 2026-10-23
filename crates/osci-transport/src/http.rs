//! HTTP transport (port of the `samples.impl.HttpTransport` reference):
//! POSTs the MIME message as `text/xml; charset=utf-8` to the
//! intermediary endpoint, no redirects, no caches.

use crate::{Transport, TransportError};

/// Configuration for the HTTP transport.
#[derive(Debug, Clone)]
pub struct HttpTransportConfig {
    /// Intermediary endpoint, e.g. `http://intermed:8080/osci/externalentry`.
    pub endpoint: String,
    /// Total timeout per request in milliseconds (default 120s like the
    /// reference library's transport timeouts).
    pub timeout_ms: u64,
    /// Optional HTTP proxy URL.
    pub proxy: Option<String>,
    /// Additional User-Agent (default `osci-rust/0.1`).
    pub user_agent: String,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            timeout_ms: 120_000,
            proxy: None,
            user_agent: "osci-rust/0.1".into(),
        }
    }
}

/// `Transport` over HTTP(S) using `ureq`.
pub struct HttpTransport {
    config: HttpTransportConfig,
    agent: ureq::Agent,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("endpoint", &self.config.endpoint)
            .field("timeout_ms", &self.config.timeout_ms)
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    pub fn new(config: HttpTransportConfig) -> Result<Self, TransportError> {
        let mut builder = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_millis(config.timeout_ms)));
        if let Some(proxy) = &config.proxy {
            let proxy =
                ureq::Proxy::new(proxy).map_err(|e| TransportError::new(format!("proxy: {e}")))?;
            builder = builder.proxy(Some(proxy));
        }
        let agent: ureq::Agent = builder.build().into();
        Ok(Self { config, agent })
    }

    pub fn config(&self) -> &HttpTransportConfig {
        &self.config
    }
}

impl Transport for HttpTransport {
    fn send(&self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        let response = self
            .agent
            .post(&self.config.endpoint)
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("Cache-Control", "no-cache")
            .header("User-Agent", &self.config.user_agent)
            .send(message)
            .map_err(|e| TransportError::new(format!("http: {e}")))?;

        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(TransportError::new(format!(
                "http status {status} from intermediary"
            )));
        }
        let mut body = Vec::new();
        use std::io::Read as _;
        response
            .into_body()
            .into_reader()
            .read_to_end(&mut body)
            .map_err(|e| TransportError::new(format!("http body: {e}")))?;
        Ok(body)
    }
}
