//! HTTP transport (port of the `samples.impl.HttpTransport` reference):
//! POSTs the MIME message as `text/xml; charset=utf-8` to the
//! intermediary endpoint, no redirects, no caches.

use crate::{Transport, TransportError};

/// TLS knobs for the HTTP transport. Everything empty = the ureq
/// defaults (webpki/platform roots, no client certificate).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpTransportTls {
    /// Trust anchors as DER-encoded certificates. Non-empty REPLACES the
    /// default roots — for intermediary endpoints with their own CA.
    pub root_certs: Vec<Vec<u8>>,
    /// Client certificate chain (DER, leaf first) for mutual TLS.
    pub client_chain: Vec<Vec<u8>>,
    /// Client private key, PEM-encoded (the label selects the kind:
    /// `PRIVATE KEY` = PKCS#8, `RSA PRIVATE KEY` = PKCS#1, `EC PRIVATE
    /// KEY` = SEC1).
    pub client_key_pem: String,
}

impl HttpTransportTls {
    fn is_empty(&self) -> bool {
        self.root_certs.is_empty() && self.client_chain.is_empty() && self.client_key_pem.is_empty()
    }
}

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
    /// TLS trust anchors and mutual-TLS client identity.
    pub tls: HttpTransportTls,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            timeout_ms: 120_000,
            proxy: None,
            user_agent: "osci-rust/0.1".into(),
            tls: HttpTransportTls::default(),
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
        if !config.tls.is_empty() {
            builder = builder.tls_config(Self::tls_config(&config.tls)?);
        }
        let agent: ureq::Agent = builder.build().into();
        Ok(Self { config, agent })
    }

    /// Translate the TLS knobs into a ureq TLS configuration.
    fn tls_config(tls: &HttpTransportTls) -> Result<ureq::tls::TlsConfig, TransportError> {
        let mut builder = ureq::tls::TlsConfig::builder();
        if !tls.root_certs.is_empty() {
            let certs: Vec<ureq::tls::Certificate<'static>> = tls
                .root_certs
                .iter()
                .map(|der| ureq::tls::Certificate::from_der(der).to_owned())
                .collect();
            builder =
                builder.root_certs(ureq::tls::RootCerts::Specific(std::sync::Arc::new(certs)));
        }
        if !tls.client_chain.is_empty() {
            let chain: Vec<ureq::tls::Certificate<'static>> = tls
                .client_chain
                .iter()
                .map(|der| ureq::tls::Certificate::from_der(der).to_owned())
                .collect();
            let key = ureq::tls::PrivateKey::from_pem(tls.client_key_pem.as_bytes())
                .map_err(|e| TransportError::new(format!("tls client key: {e}")))?;
            builder = builder.client_cert(Some(ureq::tls::ClientCert::new_with_certs(&chain, key)));
        }
        Ok(builder.build())
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

#[cfg(test)]
mod tls_tests {
    use super::*;

    /// Empty TLS knobs: the agent builds with the ureq defaults.
    #[test]
    fn empty_tls_uses_defaults() {
        let config = HttpTransportConfig {
            endpoint: "https://gov.test.osci.de/osci-manager-entry/externalentry".into(),
            ..Default::default()
        };
        HttpTransport::new(config).expect("default transport builds");
    }

    /// A client chain without a parseable PEM key is rejected at
    /// construction, not at the first request.
    #[test]
    fn broken_client_key_fails_construction() {
        let config = HttpTransportConfig {
            endpoint: "https://gov.test.osci.de/osci-manager-entry/externalentry".into(),
            tls: HttpTransportTls {
                client_chain: vec![vec![0x30, 0x82, 0x01]],
                client_key_pem: "definitely not a pem key".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = HttpTransport::new(config).expect_err("broken key must fail");
        assert!(
            err.message().contains("tls client key"),
            "{}",
            err.message()
        );
    }
}
