//! M8: HttpTransport over a minimal in-process HTTP server (no external
//! dependencies, fully offline): request semantics (POST, content type,
//! no-cache), response streaming and error-status mapping.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use sync::Arc;

use osci_transport::Transport;
use osci_transport::http::{HttpTransport, HttpTransportConfig};

mod sync {
    pub use std::sync::*;
}

fn corpus() -> PathBuf {
    std::env::var_os("OSCI_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(2)
                .unwrap()
                .join("testcorpus")
        })
}

/// Minimal single-request HTTP server: captures the request, replies
/// with a fixed status and body.
type Captured = Arc<std::sync::Mutex<Option<Vec<u8>>>>;

fn serve_once(
    response_status: &str,
    response_body: &[u8],
) -> (String, Captured, std::thread::JoinHandle<u16>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured = Arc::new(std::sync::Mutex::new(None));
    let captured_handle = captured.clone();
    let body = response_body.to_vec();
    let status = response_status.to_string();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        // read until headers + body (body length from Content-Length)
        loop {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
            if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let text = String::from_utf8_lossy(&request[..header_end]).to_string();
                let content_length = text
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        *captured_handle.lock().unwrap() = Some(request);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        port
    });
    let url = format!("http://127.0.0.1:{port}/osci/externalentry");
    (url, captured, handle)
}

#[test]
fn http_transport_posts_and_reads_response() {
    // reply with a real corpus message: the intermediary-side response
    let response_body = std::fs::read(
        corpus()
            .join("messages")
            .join("ResponseToStoreDelivery.osci"),
    )
    .unwrap();
    let (url, captured, server) = serve_once("200 OK", &response_body);

    let transport = HttpTransport::new(HttpTransportConfig {
        endpoint: url,
        ..Default::default()
    })
    .unwrap();
    let request = std::fs::read(corpus().join("messages").join("StoreDelivery.osci")).unwrap();
    let response = transport.send(&request).unwrap();
    server.join().unwrap();

    assert_eq!(response, response_body, "body streams through verbatim");

    let request_bytes = captured.lock().unwrap().take().unwrap();
    let head = String::from_utf8_lossy(&request_bytes[..200]).to_string();
    assert!(
        head.starts_with("POST /osci/externalentry HTTP/1."),
        "POST verb"
    );
    assert!(
        head.to_ascii_lowercase().contains("content-type: text/xml"),
        "content type: {head}"
    );
    // the full message body arrived
    let header_end = request_bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap();
    assert_eq!(&request_bytes[header_end + 4..], &request[..]);
}

#[test]
fn http_error_status_maps_to_transport_error() {
    let (url, _captured, server) = serve_once("500 Internal Server Error", b"boom");
    let transport = HttpTransport::new(HttpTransportConfig {
        endpoint: url,
        ..Default::default()
    })
    .unwrap();
    let error = transport.send(b"MIME-Version: 1.0\r\n\r\nx").unwrap_err();
    server.join().unwrap();
    assert!(
        error.to_string().contains("500"),
        "status surfaces in the error: {error}"
    );
}

#[test]
fn connection_failure_maps_to_transport_error() {
    // bind then drop the listener: the port is closed
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let transport = HttpTransport::new(HttpTransportConfig {
        endpoint: format!("http://127.0.0.1:{port}/osci"),
        timeout_ms: 2000,
        ..Default::default()
    })
    .unwrap();
    assert!(transport.send(b"x").is_err(), "connection refused surfaces");
}

#[test]
fn invalid_proxy_rejected_at_construction() {
    let error = HttpTransport::new(HttpTransportConfig {
        endpoint: "http://127.0.0.1:1/x".into(),
        proxy: Some("not a url".into()),
        ..Default::default()
    })
    .unwrap_err();
    assert!(error.to_string().contains("proxy"));
}
