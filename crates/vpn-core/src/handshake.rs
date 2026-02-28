//! VPN handshake protocol.
//!
//! Simple 1-RTT handshake inside TLS:
//!
//! ```text
//! Client → Server: ClientHello { client_ephemeral_pubkey, session_token }
//! Server → Client: ServerHello { server_ephemeral_pubkey, encrypted_config }
//!
//! Both derive session keys from ECDH shared secret.
//! encrypted_config contains: assigned_ip, dns_servers, mtu
//! ```

use serde::{Deserialize, Serialize};

use crate::crypto::{self, CryptoError, KeyPair, NonceCounter, SessionKeys, PUBLIC_KEY_LEN};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid session token")]
    InvalidToken,
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("failed to decrypt server config")]
    ConfigDecryption,
}

/// Client hello message — sent to the server to initiate the handshake.
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHello {
    /// Client's ephemeral X25519 public key.
    pub client_pubkey: [u8; PUBLIC_KEY_LEN],
    /// JWT session token proving the subscription is active.
    pub session_token: String,
}

/// Server hello message — response to the client.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerHello {
    /// Server's ephemeral X25519 public key.
    pub server_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Encrypted tunnel configuration (ChaCha20-Poly1305 with derived key).
    pub encrypted_config: Vec<u8>,
    /// Nonce used for encrypting the config.
    pub config_nonce: [u8; 12],
}

/// Tunnel configuration sent inside ServerHello (encrypted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Assigned IP address for the client within the tunnel.
    pub assigned_ip: String,
    /// DNS servers the client should use.
    pub dns_servers: Vec<String>,
    /// Maximum transmission unit.
    pub mtu: u16,
}

/// Trait for validating session tokens.
/// The API backend provides JWTs; the VPN server validates them with a shared secret.
pub trait TokenValidator: Send + Sync {
    /// Validate a session token and return true if the subscription is active.
    fn validate(&self, token: &str) -> bool;
}

/// Client-side handshake state machine.
pub struct ClientHandshake;

impl ClientHandshake {
    /// Initiate a handshake by generating an ephemeral key pair and creating ClientHello.
    ///
    /// Returns the ClientHello message to send, plus the ephemeral private key
    /// (needed later in `finalize`).
    pub fn initiate(session_token: String) -> Result<(ClientHello, KeyPair), HandshakeError> {
        let keypair = KeyPair::generate()?;

        let hello = ClientHello {
            client_pubkey: *keypair.public_key_bytes(),
            session_token,
        };

        // We need a second keypair because the first is consumed during agree().
        // Actually, we return the keypair itself and generate the hello from it.
        // But KeyPair contains the private key... we need to separate.
        // Let's generate a new keypair for the hello, keeping the private key.

        // Wait — we already used keypair.public_key_bytes() above, and keypair
        // will be consumed by agree() later. This is fine.
        Ok((hello, keypair))
    }

    /// Finalize the handshake after receiving ServerHello.
    ///
    /// Derives session keys and decrypts the tunnel configuration.
    pub fn finalize(
        server_hello: ServerHello,
        client_keypair: KeyPair,
    ) -> Result<(SessionKeys, TunnelConfig), HandshakeError> {
        // Perform ECDH with server's public key
        let shared_secret = client_keypair.agree(&server_hello.server_pubkey)?;

        // Derive session keys
        let session_keys = shared_secret.derive_session_keys(b"vpn-handshake-v1")?;

        // Decrypt the config using the server key
        let config_bytes = crypto::decrypt(
            &session_keys.server_key,
            &server_hello.config_nonce,
            &server_hello.encrypted_config,
        )
        .map_err(|_| HandshakeError::ConfigDecryption)?;

        let config: TunnelConfig = serde_json::from_slice(&config_bytes)?;

        Ok((session_keys, config))
    }
}

/// Server-side handshake state machine.
pub struct ServerHandshake;

impl ServerHandshake {
    /// Respond to a ClientHello.
    ///
    /// Validates the session token, generates the server's ephemeral key pair,
    /// derives session keys, encrypts the tunnel config, and returns the
    /// ServerHello plus session keys.
    pub fn respond(
        client_hello: &ClientHello,
        token_validator: &dyn TokenValidator,
        config: TunnelConfig,
    ) -> Result<(ServerHello, SessionKeys), HandshakeError> {
        // Validate session token
        if !token_validator.validate(&client_hello.session_token) {
            return Err(HandshakeError::InvalidToken);
        }

        // Generate server ephemeral key pair
        let server_keypair = KeyPair::generate()?;
        let server_pubkey = *server_keypair.public_key_bytes();

        // Perform ECDH with client's public key
        let shared_secret = server_keypair.agree(&client_hello.client_pubkey)?;

        // Derive session keys
        let session_keys = shared_secret.derive_session_keys(b"vpn-handshake-v1")?;

        // Encrypt the config with server key
        let config_bytes = serde_json::to_vec(&config)?;
        let mut nonce_counter = NonceCounter::new(session_keys.server_iv);
        let config_nonce = nonce_counter.next()?;

        let encrypted_config = crypto::encrypt(
            &session_keys.server_key,
            &config_nonce,
            &config_bytes,
        )?;

        let server_hello = ServerHello {
            server_pubkey,
            encrypted_config,
            config_nonce,
        };

        Ok((server_hello, session_keys))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple token validator for testing — accepts any token that equals "valid".
    struct TestValidator;

    impl TokenValidator for TestValidator {
        fn validate(&self, token: &str) -> bool {
            token == "valid-token"
        }
    }

    fn test_config() -> TunnelConfig {
        TunnelConfig {
            assigned_ip: "10.8.0.2".to_string(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            mtu: 1400,
        }
    }

    #[test]
    fn test_successful_handshake() {
        let validator = TestValidator;
        let config = test_config();

        // Client initiates
        let (client_hello, client_keypair) =
            ClientHandshake::initiate("valid-token".to_string()).unwrap();

        // Server responds
        let (server_hello, server_session_keys) =
            ServerHandshake::respond(&client_hello, &validator, config.clone()).unwrap();

        // Client finalizes
        let (client_session_keys, received_config) =
            ClientHandshake::finalize(server_hello, client_keypair).unwrap();

        // Both sides should have the same session keys
        assert_eq!(client_session_keys.client_key, server_session_keys.client_key);
        assert_eq!(client_session_keys.server_key, server_session_keys.server_key);
        assert_eq!(client_session_keys.client_iv, server_session_keys.client_iv);
        assert_eq!(client_session_keys.server_iv, server_session_keys.server_iv);

        // Config should be decrypted correctly
        assert_eq!(received_config.assigned_ip, "10.8.0.2");
        assert_eq!(received_config.dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(received_config.mtu, 1400);
    }

    #[test]
    fn test_invalid_token_rejected() {
        let validator = TestValidator;
        let config = test_config();

        let (client_hello, _client_keypair) =
            ClientHandshake::initiate("invalid-token".to_string()).unwrap();

        let result = ServerHandshake::respond(&client_hello, &validator, config);
        assert!(matches!(result, Err(HandshakeError::InvalidToken)));
    }

    #[test]
    fn test_directional_keys() {
        let validator = TestValidator;
        let config = test_config();

        let (client_hello, _) = ClientHandshake::initiate("valid-token".to_string()).unwrap();
        let (_, session_keys) =
            ServerHandshake::respond(&client_hello, &validator, config).unwrap();

        // client→server key must differ from server→client key
        assert_ne!(session_keys.client_key, session_keys.server_key);
        assert_ne!(session_keys.client_iv, session_keys.server_iv);
    }
}
