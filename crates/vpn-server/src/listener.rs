//! TLS listener with HTTP camouflage.
//!
//! The server serves a normal HTTPS landing page on `/` and accepts
//! VPN handshakes only via a specific HTTP upgrade path (e.g., `POST /ws`).
//! This makes the server look like a regular HTTPS website to passive DPI.

use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("failed to bind to {addr}: {source}")]
    Bind {
        addr: String,
        source: io::Error,
    },
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),
    #[error("failed to load certificate: {0}")]
    CertLoad(io::Error),
    #[error("failed to load private key: {0}")]
    KeyLoad(io::Error),
    #[error("no private key found in key file")]
    NoKey,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Load TLS server configuration from PEM files.
pub fn load_tls_config(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ServerConfig>, ListenerError> {
    // Load certificate chain
    let cert_file = std::fs::File::open(cert_path).map_err(ListenerError::CertLoad)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ListenerError::CertLoad)?;

    if certs.is_empty() {
        return Err(ListenerError::TlsConfig("no certificates found in cert file".into()));
    }

    // Load private key
    let key_file = std::fs::File::open(key_path).map_err(ListenerError::KeyLoad)?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(ListenerError::KeyLoad)?
        .ok_or(ListenerError::NoKey)?;

    // Build TLS 1.3 config
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ListenerError::TlsConfig(e.to_string()))?;

    Ok(Arc::new(config))
}

/// TLS-enabled TCP listener with camouflage support.
pub struct TlsListener {
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
}

impl TlsListener {
    /// Create a new TLS listener.
    pub async fn bind(
        addr: &str,
        tls_config: Arc<ServerConfig>,
    ) -> Result<Self, ListenerError> {
        let tcp_listener = TcpListener::bind(addr).await.map_err(|e| ListenerError::Bind {
            addr: addr.to_string(),
            source: e,
        })?;

        let local_addr = tcp_listener.local_addr()?;
        info!(addr = %local_addr, "TLS listener bound");

        let tls_acceptor = TlsAcceptor::from(tls_config);

        Ok(Self {
            tcp_listener,
            tls_acceptor,
        })
    }

    /// Accept the next TLS connection.
    ///
    /// Returns the TLS stream and the peer's address.
    pub async fn accept(
        &self,
    ) -> Result<(tokio_rustls::server::TlsStream<TcpStream>, SocketAddr), ListenerError> {
        let (tcp_stream, peer_addr) = self.tcp_listener.accept().await?;
        debug!(peer = %peer_addr, "TCP connection accepted, starting TLS handshake");

        let tls_stream = self.tls_acceptor.accept(tcp_stream).await.map_err(|e| {
            warn!(peer = %peer_addr, error = %e, "TLS handshake failed");
            ListenerError::Io(e)
        })?;

        debug!(peer = %peer_addr, "TLS handshake completed");
        Ok((tls_stream, peer_addr))
    }

    /// Get the local address the listener is bound to.
    #[allow(dead_code)]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp_listener.local_addr()
    }
}

/// HTTP request parsing result for camouflage routing.
#[derive(Debug)]
#[allow(dead_code)]
pub enum HttpRequest {
    /// A VPN upgrade request (matched the upgrade path).
    VpnUpgrade {
        /// Remaining bytes after the HTTP headers (start of VPN data).
        body: Vec<u8>,
    },
    /// A normal HTTP request to the landing page.
    LandingPage {
        method: String,
        path: String,
    },
    /// Invalid or unparseable request.
    Invalid,
}

/// Parse the initial HTTP request from a connection to determine routing.
///
/// If the request is `POST <upgrade_path>` or a WebSocket upgrade to the
/// upgrade path, it's treated as a VPN connection. Everything else gets
/// the camouflage landing page response.
pub fn parse_http_request(data: &[u8], upgrade_path: &str) -> HttpRequest {
    // Try to parse as HTTP
    let request_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return HttpRequest::Invalid,
    };

    let mut lines = request_str.lines();
    let request_line = match lines.next() {
        Some(line) => line,
        None => return HttpRequest::Invalid,
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return HttpRequest::Invalid;
    }

    let method = parts[0];
    let path = parts[1];

    // Check for VPN upgrade path
    if path == upgrade_path && (method == "POST" || method == "GET") {
        // Check for WebSocket upgrade header or just treat POST as VPN
        let is_upgrade = request_str
            .lines()
            .any(|line| {
                let lower = line.to_lowercase();
                lower.starts_with("upgrade:") && lower.contains("websocket")
            });

        if method == "POST" || is_upgrade {
            // Find the end of headers (double CRLF)
            let body_start = data
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|pos| pos + 4)
                .unwrap_or(data.len());

            return HttpRequest::VpnUpgrade {
                body: data[body_start..].to_vec(),
            };
        }
    }

    HttpRequest::LandingPage {
        method: method.to_string(),
        path: path.to_string(),
    }
}

/// Generate a camouflage HTTP response (landing page).
pub fn camouflage_response() -> Vec<u8> {
    let body = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif;
               max-width: 600px; margin: 50px auto; padding: 20px;
               color: #333; }
        h1 { color: #2563eb; }
    </style>
</head>
<body>
    <h1>Welcome</h1>
    <p>This server is running normally.</p>
    <p>For more information, please contact the administrator.</p>
</body>
</html>"#;

    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Server: nginx/1.24.0\r\n\
         \r\n\
         {}",
        body.len(),
        body
    )
    .into_bytes()
}

/// Generate an HTTP 101 Switching Protocols response for VPN upgrade.
pub fn upgrade_response() -> Vec<u8> {
    b"HTTP/1.1 101 Switching Protocols\r\n\
      Upgrade: websocket\r\n\
      Connection: Upgrade\r\n\
      \r\n"
        .to_vec()
}

/// Generate a 404 response.
pub fn not_found_response() -> Vec<u8> {
    let body = "404 Not Found";
    format!(
        "HTTP/1.1 404 Not Found\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Server: nginx/1.24.0\r\n\
         \r\n\
         {}",
        body.len(),
        body
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_post_vpn_upgrade() {
        let request = b"POST /ws HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n";
        match parse_http_request(request, "/ws") {
            HttpRequest::VpnUpgrade { body } => {
                assert!(body.is_empty());
            }
            other => panic!("Expected VpnUpgrade, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_websocket_upgrade() {
        let request = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        match parse_http_request(request, "/ws") {
            HttpRequest::VpnUpgrade { .. } => {}
            other => panic!("Expected VpnUpgrade, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_landing_page() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        match parse_http_request(request, "/ws") {
            HttpRequest::LandingPage { method, path } => {
                assert_eq!(method, "GET");
                assert_eq!(path, "/");
            }
            other => panic!("Expected LandingPage, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_invalid_request() {
        let request = b"\x00\x01\x02\x03";
        assert!(matches!(parse_http_request(request, "/ws"), HttpRequest::Invalid));
    }

    #[test]
    fn test_camouflage_response_is_valid_http() {
        let response = camouflage_response();
        let response_str = String::from_utf8(response).unwrap();
        assert!(response_str.starts_with("HTTP/1.1 200 OK"));
        assert!(response_str.contains("Content-Type: text/html"));
        assert!(response_str.contains("nginx")); // looks like nginx
    }
}
