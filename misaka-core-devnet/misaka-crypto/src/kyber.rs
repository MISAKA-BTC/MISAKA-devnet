// ============================================================
// MISAKA Network — ML-KEM-768 (via PQClean)
// ============================================================
//
// This module wraps pqcrypto-kyber which compiles PQClean's
// audited C implementation of Kyber-768 / ML-KEM-768 (FIPS 203).
//
// AUDIT FIX: The PQClean implementation includes proper
// implicit rejection in decapsulation:
//   1. Decrypt m' from ciphertext
//   2. Re-encrypt m' → ct'
//   3. If ct == ct' → shared secret = H(K̄ || H(ct))
//   4. If ct != ct' → shared secret = H(z || H(ct))  (rejection)
//
// This is essential for CCA2 security. The previous JS implementation
// was missing step 2-4 (audit finding: "implicit rejection not met").
//
// ============================================================

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as PQCiphertext, PublicKey as PQPublicKey,
    SecretKey as PQSecretKey, SharedSecret as PQSharedSecret,
};
use zeroize::Zeroize;

/// ML-KEM-768 public key size: 1184 bytes
pub const KYBER_PK_SIZE: usize = 1184;
/// ML-KEM-768 secret key size: 2400 bytes
pub const KYBER_SK_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext size: 1088 bytes
pub const KYBER_CT_SIZE: usize = 1088;
/// ML-KEM-768 shared secret size: 32 bytes
pub const KYBER_SS_SIZE: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum KyberError {
    #[error("Kyber keygen failed")]
    KeyGenFailed,
    #[error("Kyber encaps failed")]
    EncapsFailed,
    #[error("Kyber decaps failed")]
    DecapsFailed,
    #[error("Invalid public key size: expected {KYBER_PK_SIZE}, got {0}")]
    InvalidPKSize(usize),
    #[error("Invalid secret key size: expected {KYBER_SK_SIZE}, got {0}")]
    InvalidSKSize(usize),
    #[error("Invalid ciphertext size: expected {KYBER_CT_SIZE}, got {0}")]
    InvalidCTSize(usize),
}

/// ML-KEM-768 keypair (PQClean-backed)
pub struct KyberKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,  // Zeroized on drop
}

impl Drop for KyberKeyPair {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

/// Generate an ML-KEM-768 keypair.
///
/// Uses PQClean's `PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair()`.
pub fn kyber_keygen() -> Result<KyberKeyPair, KyberError> {
    let (pk, sk) = kyber768::keypair();
    Ok(KyberKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    })
}

/// Encapsulate: generate (ciphertext, shared_secret) from a public key.
///
/// Uses PQClean's `crypto_kem_enc()`.
/// The shared secret is 32 bytes of high-entropy keying material.
pub fn kyber_encaps(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KyberError> {
    let pk = kyber768::PublicKey::from_bytes(public_key)
        .map_err(|_| KyberError::InvalidPKSize(public_key.len()))?;

    let (ss, ct) = kyber768::encapsulate(&pk);

    Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

/// Decapsulate: recover shared_secret from (secret_key, ciphertext).
///
/// Uses PQClean's `crypto_kem_dec()` which includes FULL implicit rejection:
///   1. Decrypt m' from ciphertext using secret key
///   2. Re-encrypt m' with public key → ct'
///   3. Compare ct == ct' in constant time
///   4. If match:    shared_secret = H(K̄ || H(ct))  — real secret
///   5. If mismatch: shared_secret = H(z || H(ct))  — rejection secret
///
/// This is the CCA2 security mechanism that was MISSING from the
/// previous JS implementation (audit finding).
///
/// The caller cannot distinguish acceptance from rejection,
/// which prevents adaptive chosen-ciphertext attacks.
pub fn kyber_decaps(
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KyberError> {
    let sk = kyber768::SecretKey::from_bytes(secret_key)
        .map_err(|_| KyberError::InvalidSKSize(secret_key.len()))?;

    let ct = kyber768::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| KyberError::InvalidCTSize(ciphertext.len()))?;

    let ss = kyber768::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

/// Compute domain-separated hash of a Kyber public key (for K₂ in Jamtis).
///
/// AUDIT FIX: Uses unified SHAKE256 with Domain::Fingerprint instead of raw SHA3-256.
pub fn kyber_pk_hash(public_key: &[u8]) -> [u8; 32] {
    crate::hash::domain_hash_32(crate::hash::Domain::Fingerprint, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_encaps_decaps() {
        let kp = kyber_keygen().unwrap();
        assert_eq!(kp.public_key.len(), KYBER_PK_SIZE);
        assert_eq!(kp.secret_key.len(), KYBER_SK_SIZE);

        let (ct, ss_enc) = kyber_encaps(&kp.public_key).unwrap();
        assert_eq!(ct.len(), KYBER_CT_SIZE);
        assert_eq!(ss_enc.len(), KYBER_SS_SIZE);

        let ss_dec = kyber_decaps(&kp.secret_key, &ct).unwrap();
        assert_eq!(ss_dec.len(), KYBER_SS_SIZE);
        assert_eq!(ss_enc, ss_dec, "Shared secrets must match");
    }

    #[test]
    fn test_kyber_implicit_rejection() {
        // Verify that tampered ciphertext produces a DIFFERENT shared secret
        // (not an error — this is implicit rejection)
        let kp = kyber_keygen().unwrap();
        let (mut ct, ss_enc) = kyber_encaps(&kp.public_key).unwrap();

        // Tamper with the ciphertext
        ct[0] ^= 0xFF;
        ct[100] ^= 0xFF;

        let ss_dec = kyber_decaps(&kp.secret_key, &ct).unwrap();
        assert_ne!(
            ss_enc, ss_dec,
            "Tampered ciphertext must produce different shared secret (implicit rejection)"
        );
    }
}
