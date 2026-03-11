// ============================================================
// MISAKA Network — Dilithium5 / ML-DSA-87 (PQClean)
// ============================================================
//
// Module-lattice signature (NIST FIPS 204, Level V).
// Used ONLY as the second half of hybrid: Falcon-1024 || Dilithium5.
//
// Falcon uses NTRU lattice trapdoor.
// Dilithium uses module-LWE Fiat-Shamir.
// Structurally different → simultaneous break is hard.
//
// PK: 2592B, SK: 4864B, Sig: 4627B
//
// ============================================================

use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PQPublicKey,
    SecretKey as PQSecretKey,
};
use zeroize::Zeroize;

pub const DILITHIUM_PK_SIZE: usize = 2592;
pub const DILITHIUM_SK_SIZE: usize = 4864;
pub const DILITHIUM_SIG_SIZE: usize = 4627;

#[derive(Debug, thiserror::Error)]
pub enum DilithiumError {
    #[error("Dilithium5 keygen failed")]
    KeyGenFailed,
    #[error("Dilithium5 sign failed")]
    SignFailed,
    #[error("Dilithium5 verify failed")]
    VerifyFailed,
    #[error("Invalid PK size: expected {DILITHIUM_PK_SIZE}, got {0}")]
    InvalidPKSize(usize),
    #[error("Invalid SK size: expected {DILITHIUM_SK_SIZE}, got {0}")]
    InvalidSKSize(usize),
}

pub struct DilithiumKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl Drop for DilithiumKeyPair {
    fn drop(&mut self) { self.secret_key.zeroize(); }
}

pub fn dilithium_keygen() -> Result<DilithiumKeyPair, DilithiumError> {
    let (pk, sk) = dilithium5::keypair();
    Ok(DilithiumKeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    })
}

pub fn dilithium_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, DilithiumError> {
    let sk = dilithium5::SecretKey::from_bytes(secret_key)
        .map_err(|_| DilithiumError::InvalidSKSize(secret_key.len()))?;
    let sig = dilithium5::detached_sign(message, &sk);
    Ok(sig.as_bytes().to_vec())
}

pub fn dilithium_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, DilithiumError> {
    let pk = dilithium5::PublicKey::from_bytes(public_key)
        .map_err(|_| DilithiumError::InvalidPKSize(public_key.len()))?;
    let sig = dilithium5::DetachedSignature::from_bytes(signature)
        .map_err(|_| DilithiumError::VerifyFailed)?;
    match dilithium5::verify_detached_signature(&sig, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium5_roundtrip() {
        let kp = dilithium_keygen().unwrap();
        assert_eq!(kp.public_key.len(), DILITHIUM_PK_SIZE);
        let msg = b"MISAKA Dilithium5";
        let sig = dilithium_sign(&kp.secret_key, msg).unwrap();
        assert!(dilithium_verify(&kp.public_key, msg, &sig).unwrap());
        assert!(!dilithium_verify(&kp.public_key, b"tampered", &sig).unwrap());
    }
}
