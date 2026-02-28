mod auth;
mod config;
mod listener;
mod metrics;
mod session;
mod tun;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use clap::Parser;

use crate::auth::JwtTokenValidator;
use crate::config::{Cli, ServerConfig};
use crate::listener::{
    camouflage_response, not_found_response, parse_http_request, upgrade_response, HttpRequest,
    TlsListener,
};
use crate::metrics::Metrics;
use crate::session::SessionManager;
use crate::tun::{IpPool, TunDevice};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("VPN server starting...");

    // Load configuration from file specified by --config flag
    let cli = Cli::parse();
    let config = ServerConfig::load_from_file(&cli.config)
        .context("failed to load server configuration")?;

    // Initialize metrics
    let metrics = Metrics::new().context("failed to initialize metrics")?;

    // Start metrics server (background)
    let metrics_clone = metrics.clone();
    let metrics_addr = config.metrics_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = metrics::serve_metrics(&metrics_addr, metrics_clone).await {
            error!(error = %e, "Metrics server failed");
        }
    });

    // Create IP pool
    let ip_pool = Arc::new(IpPool::new(config.tunnel_ip_start, config.tunnel_ip_end));

    // Create TUN device
    let tun_device = Arc::new(
        TunDevice::create("vpn%d").context("failed to create TUN device (run as root?)")?,
    );
    info!(interface = tun_device.name(), "TUN device ready");

    // Set up session manager
    let session_manager = SessionManager::new(
        ip_pool.clone(),
        metrics.clone(),
        config.dns_servers.clone(),
        config.mtu,
        Duration::from_secs(config.idle_timeout_secs),
    );

    // Token validator
    let token_validator = Arc::new(JwtTokenValidator::new(&config.jwt_secret, &config.server_id));

    // Channel for sending packets from clients to TUN
    let (tun_tx, mut tun_rx) = mpsc::channel::<(std::net::Ipv4Addr, Vec<u8>)>(1024);

    // TUN → clients routing task
    let tun_read = tun_device.clone();
    let sm_for_tun = session_manager.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match tun_read.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    sm_for_tun.route_to_client(&buf[..n]).await;
                }
                Ok(_) => continue,
                Err(e) => {
                    error!(error = %e, "TUN read error");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    // Clients → TUN writing task
    let tun_write = tun_device.clone();
    tokio::spawn(async move {
        while let Some((_src_ip, packet)) = tun_rx.recv().await {
            if let Err(e) = tun_write.write(&packet).await {
                warn!(error = %e, "TUN write error");
            }
        }
    });

    // Load TLS config
    let tls_config = listener::load_tls_config(&config.tls_cert_path, &config.tls_key_path)
        .context("failed to load TLS certificates")?;

    // Start TLS listener
    let tls_listener = TlsListener::bind(&config.listen_addr, tls_config)
        .await
        .context("failed to bind TLS listener")?;

    info!(addr = %config.listen_addr, "VPN server ready, accepting connections");

    let upgrade_path = config.upgrade_path.clone();
    let max_connections = config.capacity.unwrap_or(1024) as usize;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_connections));

    // Graceful shutdown signal
    let shutdown = async {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
        };
        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::select! {
            _ = ctrl_c => info!("Received Ctrl+C, shutting down..."),
            _ = terminate => info!("Received SIGTERM, shutting down..."),
        }
    };
    tokio::pin!(shutdown);

    // Main accept loop
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Shutting down — no longer accepting connections");
                break;
            }
            result = tls_listener.accept() => {
                match result {
            Ok((mut tls_stream, peer_addr)) => {
                metrics.total_connections.inc();

                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(peer = %peer_addr, "Connection rejected: max connections reached ({max_connections})");
                        drop(tls_stream);
                        continue;
                    }
                };

                let sm = session_manager.clone();
                let validator = token_validator.clone();
                let tun_tx = tun_tx.clone();
                let upgrade_path = upgrade_path.clone();

                tokio::spawn(async move {
                    // Hold the semaphore permit for the lifetime of this connection
                    let _permit = permit;

                    // Read initial HTTP request for camouflage routing
                    let mut buf = vec![0u8; 4096];
                    let n = match tls_stream.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => n,
                        Err(e) => {
                            warn!(peer = %peer_addr, error = %e, "Failed to read initial data");
                            return;
                        }
                    };

                    match parse_http_request(&buf[..n], &upgrade_path) {
                        HttpRequest::VpnUpgrade { body: _ } => {
                            // Send upgrade response
                            if let Err(e) = tls_stream.write_all(&upgrade_response()).await {
                                warn!(peer = %peer_addr, error = %e, "Failed to send upgrade response");
                                return;
                            }
                            let _ = tls_stream.flush().await;

                            // Hand off to VPN session handler
                            sm.handle_client(tls_stream, peer_addr, validator.as_ref(), tun_tx)
                                .await;
                        }
                        HttpRequest::LandingPage { path, .. } => {
                            let response = if path == "/" || path == "/index.html" {
                                camouflage_response()
                            } else {
                                not_found_response()
                            };
                            let _ = tls_stream.write_all(&response).await;
                        }
                        HttpRequest::Invalid => {
                            let _ = tls_stream.write_all(&not_found_response()).await;
                        }
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "Failed to accept connection");
            }
        }
            }
        }
    }

    // Allow existing connections a grace period before exiting
    info!("Waiting up to 10s for active connections to finish...");
    tokio::time::sleep(Duration::from_secs(10)).await;
    info!("VPN server shut down");

    Ok(())
}
