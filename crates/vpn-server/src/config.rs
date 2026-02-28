//! VPN Server configuration.

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::PathBuf;

/// VPN Node Server
#[derive(Parser, Debug)]
#[command(name = "vpn-server", about = "VPN node server with TLS camouflage")]
pub struct Cli {
    /// Path to the configuration file
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,
}

/// Server configuration loaded from file or environment.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ServerConfig {
    /// TLS/HTTPS listen address (e.g., "0.0.0.0:443")
    pub listen_addr: String,

    /// Path to PEM-encoded TLS certificate chain
    pub tls_cert_path: String,

    /// Path to PEM-encoded TLS private key
    pub tls_key_path: String,

    /// Subnet for client IP assignment (e.g., "10.8.0.0/24")
    pub tunnel_subnet: String,

    /// Starting IP for the pool (e.g., "10.8.0.2")
    pub tunnel_ip_start: Ipv4Addr,

    /// Ending IP for the pool (e.g., "10.8.0.254")
    pub tunnel_ip_end: Ipv4Addr,

    /// Server's own tunnel IP (e.g., "10.8.0.1")
    pub tunnel_gateway: Ipv4Addr,

    /// DNS servers to push to clients
    pub dns_servers: Vec<String>,

    /// Tunnel MTU
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Shared secret for JWT validation (hex-encoded or raw)
    pub jwt_secret: String,

    /// Idle timeout in seconds before disconnecting a client
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Metrics listen address (localhost only for security)
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: String,

    /// HTTP upgrade path for VPN handshake (camouflage)
    #[serde(default = "default_upgrade_path")]
    pub upgrade_path: String,

    /// Unique server ID (UUID) — used to validate session tokens are for this server
    pub server_id: String,

    /// Maximum concurrent connections (DDoS protection)
    #[serde(default)]
    pub capacity: Option<u32>,

    /// Path to static files for the camouflage landing page
    #[serde(default)]
    pub landing_page_dir: Option<String>,
}

fn default_mtu() -> u16 {
    1400
}

fn default_idle_timeout() -> u64 {
    300 // 5 minutes
}

fn default_metrics_addr() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_upgrade_path() -> String {
    // IMPORTANT: Change this from the default "/ws" to a unique, hard-to-guess
    // path in production to avoid fingerprinting (e.g., "/api/v2/stream").
    "/ws".to_string()
}

impl ServerConfig {
    /// Load configuration from a TOML file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values.
    fn validate(&self) -> Result<()> {
        if self.jwt_secret == "change-me-in-production" || self.jwt_secret.len() < 32 {
            anyhow::bail!(
                "jwt_secret must be set to a secure value (at least 32 characters). \
                 Do NOT use the default value in production."
            );
        }
        if self.tls_cert_path.is_empty() || self.tls_key_path.is_empty() {
            anyhow::bail!("tls_cert_path and tls_key_path must be set");
        }
        if self.server_id.is_empty() {
            anyhow::bail!("server_id must be set (use a UUID)");
        }
        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".to_string(),
            tls_cert_path: "/etc/letsencrypt/live/vpn.example.com/fullchain.pem".to_string(),
            tls_key_path: "/etc/letsencrypt/live/vpn.example.com/privkey.pem".to_string(),
            tunnel_subnet: "10.8.0.0/24".to_string(),
            tunnel_ip_start: Ipv4Addr::new(10, 8, 0, 2),
            tunnel_ip_end: Ipv4Addr::new(10, 8, 0, 254),
            tunnel_gateway: Ipv4Addr::new(10, 8, 0, 1),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            mtu: default_mtu(),
            jwt_secret: "change-me-in-production".to_string(),
            idle_timeout_secs: default_idle_timeout(),
            metrics_addr: default_metrics_addr(),
            upgrade_path: default_upgrade_path(),
            server_id: "00000000-0000-0000-0000-000000000000".to_string(),
            capacity: Some(1024),
            landing_page_dir: None,
        }
    }
}
