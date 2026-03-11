// ============================================================
// MISAKA Network — Session Encryption (AES-256-GCM)
// ============================================================
//
// After the Kyber+Falcon handshake produces a 32-byte session_key,
// all subsequent P2P messages are encrypted with AES-256-GCM.
//
// Wire format per message:
//   [nonce: 12 bytes] [ciphertext: N bytes] [tag: 16 bytes]
//
// Nonce management:
//   Each direction (initiator→responder, responder→initiator) has
//   its own monotonic 96-bit nonce counter starting from 0.
//   Nonce reuse under AES-GCM is CATASTROPHIC — the counter
//   guarantees uniqueness.
//
// ============================================================

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Encryption failed")]
    EncryptFailed,
    #[error("Decryption failed (tampered or wrong key)")]
    DecryptFailed,
    #[error("Nonce overflow (session must be rekeyed)")]
    NonceOverflow,
    #[error("Message too short")]
    MessageTooShort,
}

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// An encrypted P2P session.
///
/// Created after a successful Kyber+Falcon handshake.
/// Each direction gets its own SessionCipher with independent nonces.
pub struct SessionCipher {
    cipher: Aes256Gcm,
    nonce_counter: u64,
    /// Derive directional keys from session_key + direction label
    direction: &'static str,
}

impl SessionCipher {
    /// Create a cipher for one direction of communication.
    ///
    /// `direction` must be either "initiator_to_responder" or
    /// "responder_to_initiator". This ensures each direction has
    /// independent key material (even though they share session_key).
    pub fn new(session_key: &[u8; 32], direction: &'static str) -> Self {
        // Derive directional key: H(SESSION || session_key || direction)
        let dk = crate::hash::domain_hash_multi(
            crate::hash::Domain::Session,
            &[session_key, direction.as_bytes()],
            32,
        );
        let key = Key::<Aes256Gcm>::from_slice(&dk);
        Self {
            cipher: Aes256Gcm::new(key),
            nonce_counter: 0,
            direction,
        }
    }

    /// Encrypt a plaintext message.
    ///
    /// Returns: [nonce(12)] [ciphertext(N)] [tag(16)]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let nonce_bytes = self.next_nonce()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SessionError::EncryptFailed)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a message (nonce || ciphertext || tag).
    pub fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>, SessionError> {
        if message.len() < NONCE_LEN + TAG_LEN {
            return Err(SessionError::MessageTooShort);
        }

        let nonce = Nonce::from_slice(&message[..NONCE_LEN]);
        let ciphertext = &message[NONCE_LEN..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| SessionError::DecryptFailed)
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN], SessionError> {
        if self.nonce_counter == u64::MAX {
            return Err(SessionError::NonceOverflow);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&self.nonce_counter.to_le_bytes());
        // Bytes 8-11 are zero (direction differentiation is in the key)
        self.nonce_counter += 1;
        Ok(nonce)
    }

    pub fn nonce_counter(&self) -> u64 { self.nonce_counter }
}

/// Create a bidirectional session from a handshake result.
///
/// Returns (send_cipher, recv_cipher) based on whether we are
/// the initiator or responder.
pub fn create_session_pair(
    session_key: &[u8; 32],
    is_initiator: bool,
) -> (SessionCipher, SessionCipher) {
    if is_initiator {
        (
            SessionCipher::new(session_key, "initiator_to_responder"),
            SessionCipher::new(session_key, "responder_to_initiator"),
        )
    } else {
        (
            SessionCipher::new(session_key, "responder_to_initiator"),
            SessionCipher::new(session_key, "initiator_to_responder"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let mut enc = SessionCipher::new(&key, "initiator_to_responder");
        let dec = SessionCipher::new(&key, "initiator_to_responder");

        let plaintext = b"Hello MISAKA Network!";
        let ciphertext = enc.encrypt(plaintext).unwrap();
        let decrypted = dec.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_different_directions_independent() {
        let key = [0x42u8; 32];
        let mut enc_a = SessionCipher::new(&key, "initiator_to_responder");
        let dec_b = SessionCipher::new(&key, "responder_to_initiator");

        let ct = enc_a.encrypt(b"msg").unwrap();
        // Decrypting with wrong direction key fails
        assert!(dec_b.decrypt(&ct).is_err());
    }

    #[test]
    fn test_session_pair() {
        let key = [0x42u8; 32];
        let (mut alice_send, alice_recv) = create_session_pair(&key, true);
        let (mut bob_send, bob_recv) = create_session_pair(&key, false);

        // Alice → Bob
        let ct = alice_send.encrypt(b"alice says hi").unwrap();
        let pt = bob_recv.decrypt(&ct).unwrap();
        assert_eq!(&pt, b"alice says hi");

        // Bob → Alice
        let ct2 = bob_send.encrypt(b"bob replies").unwrap();
        let pt2 = alice_recv.decrypt(&ct2).unwrap();
        assert_eq!(&pt2, b"bob replies");
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let key = [0x42u8; 32];
        let mut enc = SessionCipher::new(&key, "test");
        let dec = SessionCipher::new(&key, "test");

        let mut ct = enc.encrypt(b"secret").unwrap();
        ct[15] ^= 0xFF; // tamper
        assert!(dec.decrypt(&ct).is_err());
    }

    #[test]
    fn test_nonce_monotonic() {
        let key = [0x42u8; 32];
        let mut enc = SessionCipher::new(&key, "test");
        assert_eq!(enc.nonce_counter(), 0);
        enc.encrypt(b"a").unwrap();
        assert_eq!(enc.nonce_counter(), 1);
        enc.encrypt(b"b").unwrap();
        assert_eq!(enc.nonce_counter(), 2);
    }
}
