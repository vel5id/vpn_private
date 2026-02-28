//! Cryptographic primitives for the VPN protocol.
//!
//! Uses X25519 for key exchange, HKDF-SHA256 for key derivation,
//! and ChaCha20-Poly1305 for authenticated encryption.
//! All crypto is delegated to the `ring` crate — no custom crypto.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::hkdf::{self, Salt, HKDF_SHA256};
use ring::rand::SystemRandom;
use thiserror::Error;
use zeroize::Zeroize;

/// Size of an X25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Size of ChaCha20-Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;

/// Size of a nonce for ChaCha20-Poly1305 (96 bits).
pub const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key generation failed")]
    KeyGeneration,
    #[error("key agreement failed")]
    KeyAgreement,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("encryption failed")]
    Encryption,
    #[error("decryption failed: ciphertext is invalid or tampered")]
    Decryption,
    #[error("nonce overflow: counter exhausted")]
    NonceOverflow,
}

/// An X25519 ephemeral key pair.
pub struct KeyPair {
    private_key: EphemeralPrivateKey,
    public_key_bytes: [u8; PUBLIC_KEY_LEN],
}

impl KeyPair {
    /// Generate a new random X25519 key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        let private_key =
            EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| CryptoError::KeyGeneration)?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| CryptoError::KeyGeneration)?;

        let mut public_key_bytes = [0u8; PUBLIC_KEY_LEN];
        public_key_bytes.copy_from_slice(public_key.as_ref());

        Ok(Self {
            private_key,
            public_key_bytes,
        })
    }

    /// Returns the public key bytes.
    pub fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key_bytes
    }

    /// Perform X25519 ECDH with a peer's public key, returning a shared secret.
    /// Consumes the key pair (ephemeral private key can only be used once).
    pub fn agree(self, peer_public_key: &[u8; PUBLIC_KEY_LEN]) -> Result<SharedSecret, CryptoError> {
        let peer_key = UnparsedPublicKey::new(&X25519, peer_public_key);
        agreement::agree_ephemeral(self.private_key, &peer_key, |shared_secret_bytes| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(shared_secret_bytes);
            SharedSecret { bytes }
        })
        .map_err(|_| CryptoError::KeyAgreement)
    }
}

/// Raw shared secret from X25519 ECDH.
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl SharedSecret {
    /// Derive session keys from the shared secret using HKDF-SHA256.
    ///
    /// Produces separate keys for client→server and server→client directions:
    /// `client_key`, `server_key`, `client_iv`, `server_iv`.
    pub fn derive_session_keys(self, info: &[u8]) -> Result<SessionKeys, CryptoError> {
        let salt = Salt::new(HKDF_SHA256, b"vpn-protocol-v1");
        let prk = salt.extract(&self.bytes);

        // We need 2 * 32-byte keys + 2 * 12-byte IVs = 88 bytes
        let info_refs: &[&[u8]] = &[info];
        let okm = prk
            .expand(info_refs, HkdfLen(88))
            .map_err(|_| CryptoError::KeyDerivation)?;

        let mut output = [0u8; 88];
        okm.fill(&mut output)
            .map_err(|_| CryptoError::KeyDerivation)?;

        let mut client_key = [0u8; 32];
        let mut server_key = [0u8; 32];
        let mut client_iv = [0u8; NONCE_LEN];
        let mut server_iv = [0u8; NONCE_LEN];

        client_key.copy_from_slice(&output[0..32]);
        server_key.copy_from_slice(&output[32..64]);
        client_iv.copy_from_slice(&output[64..76]);
        server_iv.copy_from_slice(&output[76..88]);

        Ok(SessionKeys {
            client_key,
            server_key,
            client_iv,
            server_iv,
        })
    }
}

/// Helper for HKDF output length.
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derived session keys for bidirectional encrypted communication.
///
/// Implements `Drop` to zeroize key material when no longer needed.
/// Not cloneable by design — keys should have a single owner.
pub struct SessionKeys {
    pub client_key: [u8; 32],
    pub server_key: [u8; 32],
    pub client_iv: [u8; NONCE_LEN],
    pub server_iv: [u8; NONCE_LEN],
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.client_key.zeroize();
        self.server_key.zeroize();
        self.client_iv.zeroize();
        self.server_iv.zeroize();
    }
}

/// Monotonically incrementing nonce counter.
/// ChaCha20-Poly1305 uses 96-bit nonces; we use the first 4 bytes as the
/// implicit IV and the remaining 8 bytes as a big-endian counter.
pub struct NonceCounter {
    /// Base IV (first 4 bytes of the nonce).
    iv: [u8; 4],
    /// Packet counter (remaining 8 bytes).
    counter: u64,
}

impl NonceCounter {
    /// Create a new nonce counter from a 12-byte IV.
    /// The first 4 bytes are the fixed part, the last 8 start at 0.
    pub fn new(iv: [u8; NONCE_LEN]) -> Self {
        Self::new_with_counter(iv, 0)
    }

    /// Create a nonce counter starting at a specific counter value.
    ///
    /// Use this when nonces have already been consumed (e.g., handshake used
    /// nonce 0 for encrypted config, so the tunnel must start at 1).
    pub fn new_with_counter(iv: [u8; NONCE_LEN], start_counter: u64) -> Self {
        let mut fixed = [0u8; 4];
        fixed.copy_from_slice(&iv[..4]);
        Self {
            iv: fixed,
            counter: start_counter,
        }
    }

    /// Generate the next nonce, incrementing the counter.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<[u8; NONCE_LEN], CryptoError> {
        if self.counter == u64::MAX {
            return Err(CryptoError::NonceOverflow);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&self.iv);
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        Ok(nonce)
    }

    /// Current counter value.
    pub fn current(&self) -> u64 {
        self.counter
    }
}

/// Encrypt plaintext with ChaCha20-Poly1305.
///
/// Returns ciphertext with the 16-byte authentication tag appended.
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let unbound_key =
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| CryptoError::Encryption)?;
    let sealing_key = LessSafeKey::new(unbound_key);
    let aead_nonce = Nonce::assume_unique_for_key(*nonce);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(aead_nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::Encryption)?;

    Ok(in_out)
}

/// Decrypt ciphertext (with appended tag) using ChaCha20-Poly1305.
///
/// Returns the original plaintext.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < TAG_LEN {
        return Err(CryptoError::Decryption);
    }

    let unbound_key =
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| CryptoError::Decryption)?;
    let opening_key = LessSafeKey::new(unbound_key);
    let aead_nonce = Nonce::assume_unique_for_key(*nonce);

    let mut in_out = ciphertext.to_vec();
    let plaintext = opening_key
        .open_in_place(aead_nonce, Aad::empty(), &mut in_out)
        .map_err(|_| CryptoError::Decryption)?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let plaintext = b"Hello, VPN tunnel!";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let plaintext = b"secret data";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let result = decrypt(&wrong_key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_nonce_fails_decryption() {
        let key = [0x42u8; 32];
        let nonce1 = [0u8; NONCE_LEN];
        let nonce2 = [1u8; NONCE_LEN];
        let plaintext = b"secret data";

        let ciphertext = encrypt(&key, &nonce1, plaintext).unwrap();
        let result = decrypt(&key, &nonce2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let plaintext = b"secret data";

        let mut ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        // Flip a bit in the ciphertext
        ciphertext[0] ^= 0xFF;
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_counter_increments() {
        let iv = [0u8; NONCE_LEN];
        let mut counter = NonceCounter::new(iv);

        let n1 = counter.next().unwrap();
        let n2 = counter.next().unwrap();
        assert_ne!(n1, n2);
        assert_eq!(counter.current(), 2);
    }

    #[test]
    fn test_nonce_counter_different_nonces_produce_different_ciphertexts() {
        let key = [0x42u8; 32];
        let iv = [0u8; NONCE_LEN];
        let mut counter = NonceCounter::new(iv);
        let plaintext = b"same plaintext";

        let n1 = counter.next().unwrap();
        let n2 = counter.next().unwrap();

        let ct1 = encrypt(&key, &n1, plaintext).unwrap();
        let ct2 = encrypt(&key, &n2, plaintext).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_keypair_generation_and_agreement() {
        let kp1 = KeyPair::generate().unwrap();
        let kp2 = KeyPair::generate().unwrap();

        let pub1 = *kp1.public_key_bytes();
        let pub2 = *kp2.public_key_bytes();

        // Both sides should derive the same shared secret
        // We can't directly compare SharedSecret, but we can verify
        // that both derive the same session keys
        let ss1 = kp1.agree(&pub2).unwrap();
        let ss2 = kp2.agree(&pub1).unwrap();

        let sk1 = ss1.derive_session_keys(b"test").unwrap();
        let sk2 = ss2.derive_session_keys(b"test").unwrap();

        assert_eq!(sk1.client_key, sk2.client_key);
        assert_eq!(sk1.server_key, sk2.server_key);
        assert_eq!(sk1.client_iv, sk2.client_iv);
        assert_eq!(sk1.server_iv, sk2.server_iv);
    }

    #[test]
    fn test_session_keys_directional() {
        let kp1 = KeyPair::generate().unwrap();
        let kp2 = KeyPair::generate().unwrap();
        let pub2 = *kp2.public_key_bytes();

        let ss = kp1.agree(&pub2).unwrap();
        let sk = ss.derive_session_keys(b"test").unwrap();

        // Client and server keys must be different (directional)
        assert_ne!(sk.client_key, sk.server_key);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let plaintext = b"";

        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        assert_eq!(ciphertext.len(), TAG_LEN); // Only tag, no data

        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let plaintext = vec![0xABu8; 65535];

        let ciphertext = encrypt(&key, &nonce, &plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
