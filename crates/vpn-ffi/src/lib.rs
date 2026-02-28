//! FFI bridge exposing vpn-core to Swift via uniffi.
//!
//! The iOS VPN extension (NEPacketTunnelProvider) uses this crate to:
//! 1. Perform the VPN handshake (key exchange)
//! 2. Encrypt outgoing IP packets and frame them for the wire
//! 3. Decode incoming frames and decrypt the IP packets
//!
//! All types are thread-safe (`Send + Sync`) because the extension's
//! packet-forwarding loop may run on multiple threads.

use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use vpn_core::crypto::{self, NonceCounter, SessionKeys};
use vpn_core::framing::{self, Frame, FrameDecoder};
use vpn_core::handshake::{ClientHandshake, ServerHello, TunnelConfig};
#[cfg(test)]
use vpn_core::handshake::ClientHello;

uniffi::setup_scaffolding!();

// ── Error ────────────────────────────────────────────────────

/// Errors that can occur during VPN operations exposed to Swift.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VpnError {
    #[error("Handshake failed: {reason}")]
    Handshake { reason: String },
    #[error("Encryption failed: {reason}")]
    Encryption { reason: String },
    #[error("Decryption failed: {reason}")]
    Decryption { reason: String },
    #[error("Framing error: {reason}")]
    Framing { reason: String },
    #[error("Invalid state: {reason}")]
    InvalidState { reason: String },
}

// ── Handshake ────────────────────────────────────────────────

/// Client-side handshake state.
///
/// Usage:
/// 1. Create with `VpnHandshakeState(sessionToken:)`
/// 2. Send `clientHelloData()` to the VPN server over TLS
/// 3. Receive ServerHello bytes from the server
/// 4. Call `finish(serverHelloData:)` to obtain a `VpnSession`
#[derive(uniffi::Object)]
pub struct VpnHandshakeState {
    keypair: Mutex<Option<vpn_core::crypto::KeyPair>>,
    client_hello_bytes: Vec<u8>,
}

#[uniffi::export]
impl VpnHandshakeState {
    /// Start a new handshake.
    ///
    /// `session_token` is the JWT obtained from `POST /connect` on the API.
    #[uniffi::constructor]
    pub fn new(session_token: String) -> Result<Arc<Self>, VpnError> {
        let (hello, keypair) = ClientHandshake::initiate(session_token)
            .map_err(|e| VpnError::Handshake {
                reason: e.to_string(),
            })?;

        let data = serde_json::to_vec(&hello).map_err(|e| VpnError::Handshake {
            reason: e.to_string(),
        })?;

        // Prepend the 0x04 handshake type byte so the data is ready
        // for length-prefixed framing: [u16 len][0x04][JSON].
        let mut framed = Vec::with_capacity(1 + data.len());
        framed.push(0x04);
        framed.extend_from_slice(&data);

        Ok(Arc::new(Self {
            keypair: Mutex::new(Some(keypair)),
            client_hello_bytes: framed,
        }))
    }

    /// Serialized `ClientHello` message to send to the VPN server.
    pub fn client_hello_data(&self) -> Vec<u8> {
        self.client_hello_bytes.clone()
    }

    /// Complete the handshake with the server's response.
    ///
    /// Returns a ready-to-use `VpnSession`. This method can only be called once;
    /// a second call returns `VpnError::InvalidState`.
    pub fn finish(&self, server_hello_data: Vec<u8>) -> Result<Arc<VpnSession>, VpnError> {
        // Strip the 0x04 handshake type byte that the server prepends.
        let json_data = if server_hello_data.first() == Some(&0x04) {
            &server_hello_data[1..]
        } else {
            &server_hello_data
        };

        let server_hello: ServerHello =
            serde_json::from_slice(json_data).map_err(|e| VpnError::Handshake {
                reason: e.to_string(),
            })?;

        let keypair = self
            .keypair
            .lock()
            .map_err(|_| VpnError::InvalidState {
                reason: "internal lock poisoned".into(),
            })?
            .take()
            .ok_or_else(|| VpnError::InvalidState {
                reason: "Handshake already finalized".into(),
            })?;

        let (session_keys, tunnel_config) =
            ClientHandshake::finalize(server_hello, keypair).map_err(|e| VpnError::Handshake {
                reason: e.to_string(),
            })?;

        Ok(Arc::new(VpnSession::from_client_keys(
            session_keys,
            tunnel_config,
        )))
    }
}

// ── Session ──────────────────────────────────────────────────

/// Mutable state protected by a mutex.
struct SessionInner {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_nonce: NonceCounter,
    recv_nonce: NonceCounter,
    decoder: FrameDecoder,
}

/// An active VPN session.
///
/// Holds encryption keys, nonce counters, and the streaming frame decoder.
/// All public methods are thread-safe.
#[derive(uniffi::Object)]
pub struct VpnSession {
    inner: Mutex<SessionInner>,
    assigned_ip: String,
    dns_servers: Vec<String>,
    mtu: u16,
}

impl VpnSession {
    /// Create a client-side session from negotiated keys.
    /// Client sends with `client_key`, receives with `server_key`.
    ///
    /// recv_nonce starts at counter=1 because nonce 0 was already used
    /// during the handshake to encrypt the TunnelConfig.
    fn from_client_keys(keys: SessionKeys, config: TunnelConfig) -> Self {
        Self {
            inner: Mutex::new(SessionInner {
                send_key: keys.client_key,
                recv_key: keys.server_key,
                send_nonce: NonceCounter::new(keys.client_iv),
                recv_nonce: NonceCounter::new_with_counter(keys.server_iv, 1),
                decoder: FrameDecoder::new(),
            }),
            assigned_ip: config.assigned_ip,
            dns_servers: config.dns_servers,
            mtu: config.mtu,
        }
    }

    /// Create a server-side session (used in tests).
    /// send_nonce starts at counter=1 because nonce 0 was used in the handshake.
    #[cfg(test)]
    fn from_server_keys(keys: SessionKeys) -> Self {
        Self {
            inner: Mutex::new(SessionInner {
                send_key: keys.server_key,
                recv_key: keys.client_key,
                send_nonce: NonceCounter::new_with_counter(keys.server_iv, 1),
                recv_nonce: NonceCounter::new(keys.client_iv),
                decoder: FrameDecoder::new(),
            }),
            assigned_ip: "10.8.0.1".into(),
            dns_servers: vec![],
            mtu: 1400,
        }
    }
}

#[uniffi::export]
impl VpnSession {
    // ── Sending ──────────────────────────────────────────

    /// Encrypt an IP packet and wrap it in a protocol frame.
    ///
    /// Returns bytes ready to write to the TLS connection.
    pub fn send_packet(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, VpnError> {
        let mut inner = self.inner.lock().map_err(|_| VpnError::InvalidState {
            reason: "internal lock poisoned".into(),
        })?;

        let nonce = inner
            .send_nonce
            .next()
            .map_err(|e| VpnError::Encryption {
                reason: e.to_string(),
            })?;

        let ciphertext =
            crypto::encrypt(&inner.send_key, &nonce, &plaintext).map_err(|e| {
                VpnError::Encryption {
                    reason: e.to_string(),
                }
            })?;

        let frame = Frame::Data(ciphertext);
        let mut buf = BytesMut::new();
        framing::encode(&frame, &mut buf).map_err(|e| VpnError::Framing {
            reason: e.to_string(),
        })?;

        Ok(buf.to_vec())
    }

    /// Create a Ping keepalive frame (no encryption needed).
    pub fn create_ping_frame(&self) -> Result<Vec<u8>, VpnError> {
        let mut buf = BytesMut::new();
        framing::encode(&Frame::Ping, &mut buf).map_err(|e| VpnError::Framing {
            reason: e.to_string(),
        })?;
        Ok(buf.to_vec())
    }

    /// Create a Pong keepalive response frame.
    pub fn create_pong_frame(&self) -> Result<Vec<u8>, VpnError> {
        let mut buf = BytesMut::new();
        framing::encode(&Frame::Pong, &mut buf).map_err(|e| VpnError::Framing {
            reason: e.to_string(),
        })?;
        Ok(buf.to_vec())
    }

    // ── Receiving ────────────────────────────────────────

    /// Feed raw bytes received from the TLS connection into the decoder.
    ///
    /// After feeding, call `receivePacket()` in a loop until it returns `nil`.
    pub fn feed_data(&self, data: Vec<u8>) -> Result<(), VpnError> {
        let mut inner = self.inner.lock().map_err(|_| VpnError::InvalidState {
            reason: "internal lock poisoned".into(),
        })?;
        inner.decoder.feed(&data).map_err(|e| VpnError::Framing {
            reason: e.to_string(),
        })?;
        Ok(())
    }

    /// Decode and decrypt the next Data frame from the buffer.
    ///
    /// - Returns `Some(plaintext)` when a complete data frame is available.
    /// - Returns `None` when more bytes are needed (call `feedData` first).
    /// - Ping/Pong/Handshake frames are silently consumed.
    pub fn receive_packet(&self) -> Result<Option<Vec<u8>>, VpnError> {
        let mut inner = self.inner.lock().map_err(|_| VpnError::InvalidState {
            reason: "internal lock poisoned".into(),
        })?;

        loop {
            match inner.decoder.decode() {
                Ok(Some(Frame::Data(ciphertext))) => {
                    let nonce =
                        inner
                            .recv_nonce
                            .next()
                            .map_err(|e| VpnError::Decryption {
                                reason: e.to_string(),
                            })?;

                    let plaintext = crypto::decrypt(&inner.recv_key, &nonce, &ciphertext)
                        .map_err(|e| VpnError::Decryption {
                            reason: e.to_string(),
                        })?;

                    return Ok(Some(plaintext));
                }
                Ok(Some(_)) => {
                    // Skip Ping / Pong / Handshake control frames.
                    // The Swift layer manages keepalive timing independently.
                    continue;
                }
                Ok(None) => return Ok(None),
                Err(e) => {
                    return Err(VpnError::Framing {
                        reason: e.to_string(),
                    })
                }
            }
        }
    }

    /// Whether the internal buffer still contains un-decoded bytes.
    pub fn has_buffered_data(&self) -> bool {
        let inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        inner.decoder.buffered() > 0
    }

    // ── Tunnel config accessors ──────────────────────────

    /// IP address assigned to this client inside the tunnel.
    pub fn assigned_ip(&self) -> String {
        self.assigned_ip.clone()
    }

    /// DNS servers the client should use while the tunnel is active.
    pub fn dns_servers(&self) -> Vec<String> {
        self.dns_servers.clone()
    }

    /// Maximum Transmission Unit for the tunnel interface.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
}

// ── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_core::handshake::{ServerHandshake, TokenValidator};

    struct AcceptAll;
    impl TokenValidator for AcceptAll {
        fn validate(&self, _: &str) -> bool {
            true
        }
    }

    fn server_respond(
        client_hello_data: &[u8],
        ip: &str,
    ) -> (Vec<u8>, SessionKeys) {
        // Strip the 0x04 handshake type byte that client_hello_data() prepends
        let json_data = if client_hello_data.first() == Some(&0x04) {
            &client_hello_data[1..]
        } else {
            client_hello_data
        };
        let hello: ClientHello = serde_json::from_slice(json_data).unwrap();
        let config = TunnelConfig {
            assigned_ip: ip.to_string(),
            dns_servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            mtu: 1400,
        };
        let (server_hello, keys) =
            ServerHandshake::respond(&hello, &AcceptAll, config).unwrap();
        // Prepend 0x04 just like the real server does
        let mut framed = vec![0x04];
        framed.extend_from_slice(&serde_json::to_vec(&server_hello).unwrap());
        (framed, keys)
    }

    #[test]
    fn full_handshake_and_data_exchange() {
        // Client starts handshake
        let state = VpnHandshakeState::new("jwt-token".into()).unwrap();
        let hello = state.client_hello_data();

        // Server responds
        let (server_hello_data, server_keys) = server_respond(&hello, "10.8.0.42");

        // Client completes handshake
        let client = state.finish(server_hello_data).unwrap();
        assert_eq!(client.assigned_ip(), "10.8.0.42");
        assert_eq!(client.dns_servers(), vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(client.mtu(), 1400);

        // Create server-side session for verification
        let server = Arc::new(VpnSession::from_server_keys(server_keys));

        // Client → Server
        let msg = b"Hello from iOS!".to_vec();
        let wire = client.send_packet(msg.clone()).unwrap();
        server.feed_data(wire).unwrap();
        assert_eq!(server.receive_packet().unwrap().unwrap(), msg);

        // Server → Client
        let reply = b"Hello from server!".to_vec();
        let wire = server.send_packet(reply.clone()).unwrap();
        client.feed_data(wire).unwrap();
        assert_eq!(client.receive_packet().unwrap().unwrap(), reply);
    }

    #[test]
    fn multiple_packets() {
        let state = VpnHandshakeState::new("tok".into()).unwrap();
        let (sh, sk) = server_respond(&state.client_hello_data(), "10.8.0.2");
        let client = state.finish(sh).unwrap();
        let server = Arc::new(VpnSession::from_server_keys(sk));

        for i in 0u32..200 {
            let data = format!("pkt-{i}").into_bytes();
            let wire = client.send_packet(data).unwrap();
            server.feed_data(wire).unwrap();
        }

        for i in 0u32..200 {
            let p = server.receive_packet().unwrap().unwrap();
            assert_eq!(p, format!("pkt-{i}").as_bytes());
        }
        assert!(server.receive_packet().unwrap().is_none());
    }

    #[test]
    fn double_finish_is_error() {
        let state = VpnHandshakeState::new("tok".into()).unwrap();
        let (sh, _) = server_respond(&state.client_hello_data(), "10.8.0.2");
        let _session = state.finish(sh.clone()).unwrap();
        assert!(state.finish(sh).is_err());
    }

    #[test]
    fn ping_pong_frames() {
        let state = VpnHandshakeState::new("tok".into()).unwrap();
        let (sh, _) = server_respond(&state.client_hello_data(), "10.8.0.2");
        let session = state.finish(sh).unwrap();

        let ping = session.create_ping_frame().unwrap();
        assert!(!ping.is_empty());
        let pong = session.create_pong_frame().unwrap();
        assert!(!pong.is_empty());
    }

    #[test]
    fn control_frames_are_skipped() {
        let state = VpnHandshakeState::new("tok".into()).unwrap();
        let (sh, sk) = server_respond(&state.client_hello_data(), "10.8.0.2");
        let client = state.finish(sh).unwrap();
        let server = Arc::new(VpnSession::from_server_keys(sk));

        // Client sends: ping, data, pong
        let ping = client.create_ping_frame().unwrap();
        let data_wire = client.send_packet(b"real-data".to_vec()).unwrap();
        let pong = client.create_pong_frame().unwrap();

        // Server receives all at once
        server.feed_data(ping).unwrap();
        server.feed_data(data_wire).unwrap();
        server.feed_data(pong).unwrap();

        // Only the data frame should come through
        let received = server.receive_packet().unwrap().unwrap();
        assert_eq!(received, b"real-data");
        assert!(server.receive_packet().unwrap().is_none());
    }
}
