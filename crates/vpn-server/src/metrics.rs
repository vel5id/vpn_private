//! Prometheus metrics for the VPN server.
//!
//! Exposes metrics on a localhost-only HTTP endpoint.

use prometheus::{
    IntCounter, IntGauge, Opts, Registry, TextEncoder,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("failed to create metric: {0}")]
    Create(#[from] prometheus::Error),
    #[error("failed to bind metrics server: {0}")]
    Bind(std::io::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Collection of server metrics.
pub struct Metrics {
    pub active_connections: IntGauge,
    pub bytes_in: IntCounter,
    pub bytes_out: IntCounter,
    pub handshake_failures: IntCounter,
    pub total_connections: IntCounter,
    registry: Registry,
}

impl Metrics {
    /// Create a new metrics collection.
    pub fn new() -> Result<Arc<Self>, MetricsError> {
        let registry = Registry::new();

        let active_connections = IntGauge::with_opts(
            Opts::new("vpn_active_connections", "Number of currently connected clients"),
        )?;
        let bytes_in = IntCounter::with_opts(
            Opts::new("vpn_bytes_in_total", "Total bytes received from clients"),
        )?;
        let bytes_out = IntCounter::with_opts(
            Opts::new("vpn_bytes_out_total", "Total bytes sent to clients"),
        )?;
        let handshake_failures = IntCounter::with_opts(
            Opts::new("vpn_handshake_failures_total", "Total handshake failures"),
        )?;
        let total_connections = IntCounter::with_opts(
            Opts::new("vpn_connections_total", "Total connections accepted"),
        )?;

        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(bytes_in.clone()))?;
        registry.register(Box::new(bytes_out.clone()))?;
        registry.register(Box::new(handshake_failures.clone()))?;
        registry.register(Box::new(total_connections.clone()))?;

        Ok(Arc::new(Self {
            active_connections,
            bytes_in,
            bytes_out,
            handshake_failures,
            total_connections,
            registry,
        }))
    }

    /// Render metrics in Prometheus text format.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode_to_string(&metric_families).unwrap_or_default()
    }
}

/// Run the metrics HTTP server.
///
/// Binds to `addr` (should be localhost-only) and serves:
/// - `GET /metrics` — Prometheus metrics
/// - `GET /health` — health check
pub async fn serve_metrics(
    addr: &str,
    metrics: Arc<Metrics>,
) -> Result<(), MetricsError> {
    let listener = TcpListener::bind(addr).await.map_err(MetricsError::Bind)?;
    info!(addr = %addr, "Metrics server listening");

    loop {
        let (mut stream, _peer) = listener.accept().await?;
        let metrics = metrics.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };

            let request = String::from_utf8_lossy(&buf[..n]);
            let response = if request.contains("GET /metrics") {
                let body = metrics.render();
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body
                )
            } else if request.contains("GET /health") {
                let body = r#"{"status":"ok"}"#;
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
            };

            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

use tokio::io::AsyncReadExt;
