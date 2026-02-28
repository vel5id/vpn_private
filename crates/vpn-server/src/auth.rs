//! JWT-based token validation for VPN sessions.
//!
//! The API backend issues JWTs with `{ user_id, server_id, exp }`.
//! The VPN server validates them using a shared HMAC secret.

use vpn_core::handshake::TokenValidator;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// JWT claims for a VPN session token.
///
/// Field types mirror `SessionTokenClaims` in the API crate to ensure
/// tokens issued by the API deserialize correctly here.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    /// User ID (UUID string).
    pub sub: String,
    /// Server ID this token is valid for.
    pub server_id: String,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued at time (Unix timestamp).
    pub iat: i64,
}

/// Validates session tokens using a shared HMAC-SHA256 secret.
pub struct JwtTokenValidator {
    secret: Vec<u8>,
    server_id: String,
}

impl JwtTokenValidator {
    /// Create a new validator with the given secret and expected server_id.
    pub fn new(secret: &str, server_id: &str) -> Self {
        Self {
            secret: secret.as_bytes().to_vec(),
            server_id: server_id.to_string(),
        }
    }

    /// Validate and decode a JWT, checking expiration.
    pub fn validate_and_decode(&self, token: &str) -> Option<SessionClaims> {
        // Simple JWT validation: split, decode, verify HMAC, check exp
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            warn!("Invalid JWT format: expected 3 parts, got {}", parts.len());
            return None;
        }

        // Decode header and payload
        use ring::hmac;

        let header_payload = format!("{}.{}", parts[0], parts[1]);

        // Verify signature
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
        let signature = base64_url_decode(parts[2])?;
        if hmac::verify(&key, header_payload.as_bytes(), &signature).is_err() {
            warn!("JWT signature verification failed");
            return None;
        }

        // Decode payload
        let payload_bytes = base64_url_decode(parts[1])?;
        let claims: SessionClaims = serde_json::from_slice(&payload_bytes).ok()?;

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if claims.exp < now {
            warn!(user = %claims.sub, "JWT expired");
            return None;
        }

        // Verify the token is for this server
        if claims.server_id != self.server_id {
            warn!(
                user = %claims.sub,
                expected = %self.server_id,
                got = %claims.server_id,
                "JWT server_id mismatch — token is for a different server"
            );
            return None;
        }

        debug!(user = %claims.sub, server = %claims.server_id, "JWT validated");
        Some(claims)
    }
}

impl TokenValidator for JwtTokenValidator {
    fn validate(&self, token: &str) -> bool {
        self.validate_and_decode(token).is_some()
    }
}

/// Base64 URL-safe decode (no padding).
fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    // Add padding
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        0 => input.to_string(),
        _ => return None,
    };

    // Replace URL-safe chars
    let standard = padded.replace('-', "+").replace('_', "/");

    // Decode using a simple implementation
    base64_decode_standard(&standard)
}

/// Simple base64 standard decode.
fn base64_decode_standard(input: &str) -> Option<Vec<u8>> {
    #[allow(dead_code)]
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0), // padding
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }

    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);

    for chunk in bytes.chunks(4) {
        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;
        let c_char = chunk[2];
        let d_char = chunk[3];
        let c = decode_char(c_char)?;
        let d = decode_char(d_char)?;

        let triple = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);

        output.push((triple >> 16) as u8);
        if c_char != b'=' {
            output.push((triple >> 8) as u8);
        }
        if d_char != b'=' {
            output.push(triple as u8);
        }
    }

    Some(output)
}

/// Create a test JWT for development/testing.
/// In production, these are issued by the API backend.
#[allow(dead_code)]
pub fn create_test_jwt(secret: &str, user_id: &str, server_id: &str, ttl_secs: u64) -> String {
    use ring::hmac;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let header = base64_url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);

    let claims = SessionClaims {
        sub: user_id.to_string(),
        server_id: server_id.to_string(),
        exp: now + ttl_secs as i64,
        iat: now,
    };
    let payload = base64_url_encode(&serde_json::to_vec(&claims).unwrap());

    let message = format!("{header}.{payload}");
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let signature = hmac::sign(&key, message.as_bytes());
    let sig_str = base64_url_encode(signature.as_ref());

    format!("{message}.{sig_str}")
}

/// Base64 URL-safe encode (no padding).
#[allow(dead_code)]
fn base64_url_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).map(|&b| b as u32).unwrap_or(0);
        let b2 = chunk.get(2).map(|&b| b as u32).unwrap_or(0);

        let triple = (b0 << 16) | (b1 << 8) | b2;

        output.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        output.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            output.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(triple & 0x3F) as usize] as char);
        }
    }

    // URL-safe: replace + with -, / with _
    output.replace('+', "-").replace('/', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_validate_jwt() {
        let secret = "test-secret-key";
        let token = create_test_jwt(secret, "user-123", "server-456", 3600);

        let validator = JwtTokenValidator::new(secret, "server-456");
        let claims = validator.validate_and_decode(&token).unwrap();

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.server_id, "server-456");
    }

    #[test]
    fn test_wrong_secret_fails() {
        let token = create_test_jwt("secret1", "user-123", "server-456", 3600);

        let validator = JwtTokenValidator::new("secret2", "server-456");
        assert!(validator.validate_and_decode(&token).is_none());
    }

    #[test]
    fn test_expired_token_fails() {
        // Create a token that's already expired
        let token = create_test_jwt("secret", "user-123", "server-456", 0);
        // Sleep a bit to ensure it's expired
        std::thread::sleep(std::time::Duration::from_secs(1));

        let validator = JwtTokenValidator::new("secret", "server-456");
        assert!(validator.validate_and_decode(&token).is_none());
    }

    #[test]
    fn test_token_validator_trait() {
        let secret = "test-secret";
        let token = create_test_jwt(secret, "user-123", "server-456", 3600);

        let validator = JwtTokenValidator::new(secret, "server-456");
        assert!(validator.validate(&token));
        assert!(!validator.validate("invalid-token"));
    }

    #[test]
    fn test_wrong_server_id_fails() {
        let secret = "test-secret";
        let token = create_test_jwt(secret, "user-123", "server-456", 3600);

        let validator = JwtTokenValidator::new(secret, "different-server");
        assert!(validator.validate_and_decode(&token).is_none());
    }

    #[test]
    fn test_base64_url_roundtrip() {
        let data = b"Hello, world! This is a test of base64 encoding.";
        let encoded = base64_url_encode(data);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
