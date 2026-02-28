//! Encrypted tunnel I/O over any async transport.
//!
//! Wraps an `AsyncRead + AsyncWrite` stream with authenticated encryption,
//! framing, and keepalive support.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::{self, CryptoError, NonceCounter, SessionKeys};
use crate::framing::{self, Frame, FrameDecoder, FramingError};

use bytes::BytesMut;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("framing error: {0}")]
    Framing(#[from] FramingError),
    #[error("connection closed")]
    ConnectionClosed,
}

/// Determines the direction of the tunnel (affects which keys are used).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRole {
    /// Client sends with client_key, receives with server_key.
    Client,
    /// Server sends with server_key, receives with client_key.
    Server,
}

/// Encrypted bidirectional tunnel over an async transport.
pub struct Tunnel<T: AsyncRead + AsyncWrite + Unpin> {
    transport: T,
    /// Key used for encrypting outgoing packets.
    send_key: [u8; 32],
    /// Key used for decrypting incoming packets.
    recv_key: [u8; 32],
    /// Nonce counter for outgoing packets.
    send_nonce: NonceCounter,
    /// Nonce counter for incoming packets.
    recv_nonce: NonceCounter,
    /// Frame decoder with internal buffer.
    decoder: FrameDecoder,
    /// Read buffer for raw bytes from transport.
    read_buf: Vec<u8>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Tunnel<T> {
    /// Create a new tunnel.
    ///
    /// `role` determines which keys are used for send vs recv:
    /// - Client: send with client_key, recv with server_key
    /// - Server: send with server_key, recv with client_key
    ///
    /// The server_iv nonce counter starts at 1 (not 0) because nonce 0
    /// was already consumed during the handshake to encrypt TunnelConfig.
    pub fn new(transport: T, session_keys: &SessionKeys, role: TunnelRole) -> Self {
        let (send_key, recv_key, send_iv, recv_iv) = match role {
            TunnelRole::Client => (
                session_keys.client_key,
                session_keys.server_key,
                session_keys.client_iv,
                session_keys.server_iv,
            ),
            TunnelRole::Server => (
                session_keys.server_key,
                session_keys.client_key,
                session_keys.server_iv,
                session_keys.client_iv,
            ),
        };

        // The handshake consumed nonce 0 on the server_iv direction
        // (ServerHandshake::respond encrypts TunnelConfig with server_key + server_iv[0]).
        // Server sends with server_iv → start at 1.
        // Client receives with server_iv → start at 1.
        let (send_start, recv_start) = match role {
            TunnelRole::Server => (1, 0), // server sends on server_iv (used in handshake)
            TunnelRole::Client => (0, 1), // client recvs on server_iv (used in handshake)
        };

        Self {
            transport,
            send_key,
            recv_key,
            send_nonce: NonceCounter::new_with_counter(send_iv, send_start),
            recv_nonce: NonceCounter::new_with_counter(recv_iv, recv_start),
            decoder: FrameDecoder::new(),
            read_buf: vec![0u8; 4096],
        }
    }

    /// Send an encrypted data packet through the tunnel.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), TunnelError> {
        let nonce = self.send_nonce.next()?;
        let ciphertext = crypto::encrypt(&self.send_key, &nonce, data)?;

        let frame = Frame::Data(ciphertext);
        let mut buf = BytesMut::new();
        framing::encode(&frame, &mut buf)?;

        self.transport.write_all(&buf).await?;
        self.transport.flush().await?;

        Ok(())
    }

    /// Send a ping keepalive.
    pub async fn send_ping(&mut self) -> Result<(), TunnelError> {
        let frame = Frame::Ping;
        let mut buf = BytesMut::new();
        framing::encode(&frame, &mut buf)?;
        self.transport.write_all(&buf).await?;
        self.transport.flush().await?;
        Ok(())
    }

    /// Send a pong keepalive response.
    pub async fn send_pong(&mut self) -> Result<(), TunnelError> {
        let frame = Frame::Pong;
        let mut buf = BytesMut::new();
        framing::encode(&frame, &mut buf)?;
        self.transport.write_all(&buf).await?;
        self.transport.flush().await?;
        Ok(())
    }

    /// Receive the next event from the tunnel.
    ///
    /// Returns decrypted data packets. Handles Ping/Pong internally
    /// (auto-replies to pings, ignores pongs).
    pub async fn recv(&mut self) -> Result<Vec<u8>, TunnelError> {
        loop {
            // Try to decode a frame from buffered data first
            if let Some(frame) = self.decoder.decode()? {
                match frame {
                    Frame::Data(ciphertext) => {
                        let nonce = self.recv_nonce.next()?;
                        let plaintext = crypto::decrypt(&self.recv_key, &nonce, &ciphertext)?;
                        return Ok(plaintext);
                    }
                    Frame::Ping => {
                        // Auto-respond with pong
                        self.send_pong().await?;
                        continue;
                    }
                    Frame::Pong => {
                        // Keepalive acknowledged, continue waiting
                        continue;
                    }
                    Frame::Handshake(_) => {
                        // Handshake frames shouldn't appear after tunnel is established
                        // Ignore them
                        continue;
                    }
                }
            }

            // Need more data from the transport
            let n = self.transport.read(&mut self.read_buf).await?;
            if n == 0 {
                return Err(TunnelError::ConnectionClosed);
            }
            self.decoder.feed(&self.read_buf[..n])?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SessionKeys, NONCE_LEN};
    use tokio::io::duplex;

    fn test_session_keys() -> SessionKeys {
        SessionKeys {
            client_key: [0x01; 32],
            server_key: [0x02; 32],
            client_iv: [0x03; NONCE_LEN],
            server_iv: [0x04; NONCE_LEN],
        }
    }

    #[tokio::test]
    async fn test_roundtrip_over_duplex() {
        let keys = test_session_keys();
        let (client_stream, server_stream) = duplex(65536);

        let mut client_tunnel = Tunnel::new(client_stream, &keys, TunnelRole::Client);
        let mut server_tunnel = Tunnel::new(server_stream, &keys, TunnelRole::Server);

        let message = b"Hello through the tunnel!";

        // Client sends, server receives
        client_tunnel.send(message).await.unwrap();
        let received = server_tunnel.recv().await.unwrap();
        assert_eq!(received, message);

        // Server sends, client receives
        let response = b"Hello back!";
        server_tunnel.send(response).await.unwrap();
        let received = client_tunnel.recv().await.unwrap();
        assert_eq!(received, response);
    }

    #[tokio::test]
    async fn test_multiple_packets() {
        let keys = test_session_keys();
        let (client_stream, server_stream) = duplex(65536);

        let mut client_tunnel = Tunnel::new(client_stream, &keys, TunnelRole::Client);
        let mut server_tunnel = Tunnel::new(server_stream, &keys, TunnelRole::Server);

        for i in 0..100 {
            let data = format!("packet {i}");
            client_tunnel.send(data.as_bytes()).await.unwrap();
        }

        for i in 0..100 {
            let received = server_tunnel.recv().await.unwrap();
            let expected = format!("packet {i}");
            assert_eq!(received, expected.as_bytes());
        }
    }

    #[tokio::test]
    async fn test_bidirectional_concurrent() {
        let keys = test_session_keys();
        let (client_stream, server_stream) = duplex(65536);

        let mut client_tunnel = Tunnel::new(client_stream, &keys, TunnelRole::Client);
        let mut server_tunnel = Tunnel::new(server_stream, &keys, TunnelRole::Server);

        let send_handle = tokio::spawn(async move {
            for i in 0..50 {
                let data = format!("c2s-{i}");
                client_tunnel.send(data.as_bytes()).await.unwrap();

                // Also receive from server
                let received = client_tunnel.recv().await.unwrap();
                let expected = format!("s2c-{i}");
                assert_eq!(received, expected.as_bytes());
            }
        });

        let recv_handle = tokio::spawn(async move {
            for i in 0..50 {
                // Receive from client
                let received = server_tunnel.recv().await.unwrap();
                let expected = format!("c2s-{i}");
                assert_eq!(received, expected.as_bytes());

                // Send back to client
                let response = format!("s2c-{i}");
                server_tunnel.send(response.as_bytes()).await.unwrap();
            }
        });

        send_handle.await.unwrap();
        recv_handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_ping_pong() {
        let keys = test_session_keys();
        let (client_stream, server_stream) = duplex(65536);

        let mut client_tunnel = Tunnel::new(client_stream, &keys, TunnelRole::Client);
        let mut server_tunnel = Tunnel::new(server_stream, &keys, TunnelRole::Server);

        // Client sends ping
        client_tunnel.send_ping().await.unwrap();

        // Server should auto-reply with pong when it tries to recv
        // But first let's send some data after the ping so recv returns
        client_tunnel.send(b"after-ping").await.unwrap();

        // Server recv will process ping (auto-pong) then return the data frame
        let received = server_tunnel.recv().await.unwrap();
        assert_eq!(received, b"after-ping");
    }

    #[tokio::test]
    async fn test_connection_closed() {
        let keys = test_session_keys();
        let (client_stream, server_stream) = duplex(65536);

        let mut server_tunnel = Tunnel::new(server_stream, &keys, TunnelRole::Server);

        // Drop the client side
        drop(client_stream);

        let result = server_tunnel.recv().await;
        assert!(matches!(result, Err(TunnelError::ConnectionClosed)));
    }
}
