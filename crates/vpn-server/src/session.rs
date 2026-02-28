//! Client session management and packet routing.
//!
//! Each connected client gets a session with an assigned tunnel IP.
//! The router dispatches packets between clients' tunnels and the TUN device.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use vpn_core::handshake::{
    ClientHello, ServerHandshake, TokenValidator, TunnelConfig,
};
use vpn_core::tunnel::{Tunnel, TunnelRole};

use crate::metrics::Metrics;
use crate::tun::IpPool;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum SessionError {
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("IP pool exhausted")]
    PoolExhausted,
    #[error("session expired")]
    Expired,
    #[error("tunnel error: {0}")]
    Tunnel(#[from] vpn_core::tunnel::TunnelError),
}

/// Unique identifier for a client session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session-{}", self.0)
    }
}

/// Information about an active client session.
#[derive(Debug)]
#[allow(dead_code)]
pub struct SessionInfo {
    pub id: SessionId,
    pub peer_addr: SocketAddr,
    pub assigned_ip: Ipv4Addr,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// Manages all active sessions and routes packets.
pub struct SessionManager {
    /// Map of assigned IP → channel to send packets to that client.
    client_senders: DashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>,
    /// Active session info.
    sessions: DashMap<SessionId, SessionInfo>,
    /// IP address pool.
    ip_pool: Arc<IpPool>,
    /// Metrics collector.
    metrics: Arc<Metrics>,
    /// Server-side tunnel config template.
    dns_servers: Vec<String>,
    mtu: u16,
    /// Idle timeout.
    idle_timeout: Duration,
}

impl SessionManager {
    pub fn new(
        ip_pool: Arc<IpPool>,
        metrics: Arc<Metrics>,
        dns_servers: Vec<String>,
        mtu: u16,
        idle_timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            client_senders: DashMap::new(),
            sessions: DashMap::new(),
            ip_pool,
            metrics,
            dns_servers,
            mtu,
            idle_timeout,
        })
    }

    /// Handle a new client connection.
    ///
    /// Performs the handshake, sets up the tunnel, and runs the packet
    /// forwarding loop. Returns when the client disconnects.
    pub async fn handle_client<T>(
        self: &Arc<Self>,
        transport: T,
        peer_addr: SocketAddr,
        token_validator: &dyn TokenValidator,
        tun_sender: mpsc::Sender<(Ipv4Addr, Vec<u8>)>,
    ) where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let session_id = SessionId::new();
        info!(session = %session_id, peer = %peer_addr, "New client connection");

        match self
            .setup_and_run(transport, peer_addr, session_id, token_validator, tun_sender)
            .await
        {
            Ok(()) => {
                info!(session = %session_id, "Client disconnected normally");
            }
            Err(e) => {
                warn!(session = %session_id, error = %e, "Client session ended with error");
                self.metrics.handshake_failures.inc();
            }
        }

        // Cleanup
        if let Some((_, info)) = self.sessions.remove(&session_id) {
            self.client_senders.remove(&info.assigned_ip);
            if let Err(e) = self.ip_pool.release(info.assigned_ip) {
                warn!(
                    session = %session_id,
                    ip = %info.assigned_ip,
                    error = %e,
                    "Failed to release IP"
                );
            }
            self.metrics.active_connections.dec();
            info!(
                session = %session_id,
                ip = %info.assigned_ip,
                duration_secs = info.connected_at.elapsed().as_secs(),
                bytes_up = info.bytes_up,
                bytes_down = info.bytes_down,
                "Session cleaned up"
            );
        }
    }

    async fn setup_and_run<T>(
        self: &Arc<Self>,
        mut transport: T,
        peer_addr: SocketAddr,
        session_id: SessionId,
        token_validator: &dyn TokenValidator,
        tun_sender: mpsc::Sender<(Ipv4Addr, Vec<u8>)>,
    ) -> Result<(), SessionError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // --- Step 1: Read ClientHello ---
        // First read the handshake frame
        let mut len_buf = [0u8; 2];
        transport
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| SessionError::Handshake(format!("failed to read length: {e}")))?;
        let body_len = u16::from_be_bytes(len_buf) as usize;

        let mut body = vec![0u8; body_len];
        transport
            .read_exact(&mut body)
            .await
            .map_err(|e| SessionError::Handshake(format!("failed to read body: {e}")))?;

        // Skip the type byte (0x04 = Handshake)
        if body.is_empty() || body[0] != 0x04 {
            return Err(SessionError::Handshake("expected handshake frame".into()));
        }
        let hello_bytes = &body[1..];

        let client_hello: ClientHello = serde_json::from_slice(hello_bytes)
            .map_err(|e| SessionError::Handshake(format!("invalid ClientHello: {e}")))?;

        // --- Step 2: Allocate IP and perform handshake ---
        let assigned_ip = self.ip_pool.allocate().map_err(|_| SessionError::PoolExhausted)?;

        let tunnel_config = TunnelConfig {
            assigned_ip: assigned_ip.to_string(),
            dns_servers: self.dns_servers.clone(),
            mtu: self.mtu,
        };

        let (server_hello, session_keys) =
            ServerHandshake::respond(&client_hello, token_validator, tunnel_config)
                .map_err(|e| {
                    // Release IP on handshake failure
                    let _ = self.ip_pool.release(assigned_ip);
                    SessionError::Handshake(e.to_string())
                })?;

        // --- Step 3: Send ServerHello ---
        let hello_response = serde_json::to_vec(&server_hello)
            .map_err(|e| SessionError::Handshake(format!("failed to serialize ServerHello: {e}")))?;

        // Frame it: [len: u16][type: 0x04][payload]
        let frame_body_len = (1 + hello_response.len()) as u16;
        transport
            .write_all(&frame_body_len.to_be_bytes())
            .await
            .map_err(|e| SessionError::Handshake(format!("failed to write: {e}")))?;
        transport
            .write_all(&[0x04])
            .await
            .map_err(|e| SessionError::Handshake(format!("failed to write: {e}")))?;
        transport
            .write_all(&hello_response)
            .await
            .map_err(|e| SessionError::Handshake(format!("failed to write: {e}")))?;
        transport
            .flush()
            .await
            .map_err(|e| SessionError::Handshake(format!("failed to flush: {e}")))?;

        info!(
            session = %session_id,
            peer = %peer_addr,
            ip = %assigned_ip,
            "Handshake completed"
        );

        // --- Step 4: Set up tunnel and session ---
        let mut tunnel = Tunnel::new(transport, &session_keys, TunnelRole::Server);

        let (client_tx, mut client_rx) = mpsc::channel::<Vec<u8>>(256);

        self.client_senders.insert(assigned_ip, client_tx);
        self.sessions.insert(
            session_id,
            SessionInfo {
                id: session_id,
                peer_addr,
                assigned_ip,
                connected_at: Instant::now(),
                last_activity: Instant::now(),
                bytes_up: 0,
                bytes_down: 0,
            },
        );
        self.metrics.active_connections.inc();

        // --- Step 5: Packet forwarding loop ---
        let idle_timeout = self.idle_timeout;

        loop {
            tokio::select! {
                // Encrypted packet from client → decrypt → route to TUN
                result = tunnel.recv() => {
                    match result {
                        Ok(plaintext) => {
                            // Validate source IP matches the assigned IP to prevent spoofing
                            if plaintext.len() < 20 {
                                debug!(session = %session_id, len = plaintext.len(), "Dropping runt packet");
                                continue;
                            }
                            let ip_version = plaintext[0] >> 4;
                            if ip_version != 4 {
                                debug!(session = %session_id, version = ip_version, "Dropping non-IPv4 packet");
                                continue;
                            }
                            let src_ip = Ipv4Addr::new(
                                plaintext[12], plaintext[13],
                                plaintext[14], plaintext[15],
                            );
                            if src_ip != assigned_ip {
                                warn!(
                                    session = %session_id,
                                    expected = %assigned_ip,
                                    got = %src_ip,
                                    "Dropping packet with spoofed source IP"
                                );
                                continue;
                            }

                            let len = plaintext.len() as u64;
                            // Update session stats
                            if let Some(mut info) = self.sessions.get_mut(&session_id) {
                                info.bytes_up += len;
                                info.last_activity = Instant::now();
                            }
                            self.metrics.bytes_in.inc_by(len);

                            // Send to TUN device
                            if tun_sender.send((assigned_ip, plaintext)).await.is_err() {
                                warn!(session = %session_id, "TUN sender closed");
                                break;
                            }
                        }
                        Err(vpn_core::tunnel::TunnelError::ConnectionClosed) => {
                            debug!(session = %session_id, "Client disconnected");
                            break;
                        }
                        Err(e) => {
                            warn!(session = %session_id, error = %e, "Tunnel recv error");
                            break;
                        }
                    }
                }

                // Packet from TUN destined for this client → encrypt → send
                Some(packet) = client_rx.recv() => {
                    let len = packet.len() as u64;
                    match tunnel.send(&packet).await {
                        Ok(()) => {
                            if let Some(mut info) = self.sessions.get_mut(&session_id) {
                                info.bytes_down += len;
                                info.last_activity = Instant::now();
                            }
                            self.metrics.bytes_out.inc_by(len);
                        }
                        Err(e) => {
                            warn!(session = %session_id, error = %e, "Tunnel send error");
                            break;
                        }
                    }
                }

                // Idle timeout check
                _ = tokio::time::sleep(idle_timeout) => {
                    let is_idle = self.sessions
                        .get(&session_id)
                        .map(|info| info.last_activity.elapsed() > idle_timeout)
                        .unwrap_or(true);

                    if is_idle {
                        info!(session = %session_id, "Idle timeout, disconnecting");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Route a packet from the TUN device to the appropriate client.
    ///
    /// Parses the destination IP from the IPv4/IPv6 header and dispatches
    /// to the corresponding client's send channel.
    pub async fn route_to_client(&self, packet: &[u8]) {
        if packet.is_empty() {
            return;
        }

        let ip_version = packet[0] >> 4;

        let dst_ip = match ip_version {
            4 => {
                if packet.len() < 20 {
                    return; // Too short for IPv4 header
                }
                // IPv4 destination is at offset 16-19
                Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])
            }
            6 => {
                // IPv6 not yet supported for routing — drop silently
                return;
            }
            _ => return,
        };

        if let Some(sender) = self.client_senders.get(&dst_ip) {
            if sender.send(packet.to_vec()).await.is_err() {
                debug!(dst = %dst_ip, "Client channel closed, removing");
                self.client_senders.remove(&dst_ip);
            }
        }
    }

    /// Get the number of active sessions.
    #[allow(dead_code)]
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get info about all active sessions (for metrics/admin).
    #[allow(dead_code)]
    pub fn session_infos(&self) -> Vec<(SessionId, SocketAddr, Ipv4Addr, u64, u64)> {
        self.sessions
            .iter()
            .map(|entry| {
                let info = entry.value();
                (info.id, info.peer_addr, info.assigned_ip, info.bytes_up, info.bytes_down)
            })
            .collect()
    }
}
