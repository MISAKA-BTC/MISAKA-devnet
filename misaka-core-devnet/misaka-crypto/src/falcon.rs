// ============================================================
// MISAKA Network — Falcon-512 (PQClean, NIST Level I)
// ============================================================
//
// ④ Deterministic signing: PQClean Falcon uses internal
//    deterministic nonce derivation. External DRBG removed.
//
// PK: 897B, SK: 1281B, Sig: ~690B
//
// ============================================================

use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PQPublicKey,
    SecretKey as PQSecretKey,
};
use zeroize::Zeroize;
use crate::hash::{Domain, domain_hash_32};

pub const FALCON_PK_SIZE: usize = 897;
pub const FALCON_SK_SIZE: usize = 1281;
pub const FALCON_SIG_MAX_SIZE: usize = 690;

#[derive(Debug, thiserror::Error)]
pub enum FalconError {
    #[error("Falcon-512 verify failed")]
    VerifyFailed,
    #[error("Invalid PK size: expected {FALCON_PK_SIZE}, got {0}")]
    InvalidPKSize(usize),
    #[error("Invalid SK size: expected {FALCON_SK_SIZE}, got {0}")]
    InvalidSKSize(usize),
}

pub struct FalconKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub fingerprint: [u8; 32],
}

impl Drop for FalconKeyPair {
    fn drop(&mut self) { self.secret_key.zeroize(); }
}

pub fn falcon_keygen() -> Result<FalconKeyPair, FalconError> {
    let (pk, sk) = falcon512::keypair();
    let pk_bytes = pk.as_bytes().to_vec();
    let sk_bytes = sk.as_bytes().to_vec();
    let fingerprint = falcon_fingerprint(&pk_bytes);
    Ok(FalconKeyPair { public_key: pk_bytes, secret_key: sk_bytes, fingerprint })
}

/// ④ Deterministic sign — no external DRBG needed.
pub fn falcon_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, FalconError> {
    let sk = falcon512::SecretKey::from_bytes(secret_key)
        .map_err(|_| FalconError::InvalidSKSize(secret_key.len()))?;
    Ok(falcon512::detached_sign(message, &sk).as_bytes().to_vec())
}

pub fn falcon_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, FalconError> {
    let pk = falcon512::PublicKey::from_bytes(public_key)
        .map_err(|_| FalconError::InvalidPKSize(public_key.len()))?;
    let sig = falcon512::DetachedSignature::from_bytes(signature)
        .map_err(|_| FalconError::VerifyFailed)?;
    match falcon512::verify_detached_signature(&sig, message, &pk) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn falcon_fingerprint(public_key: &[u8]) -> [u8; 32] {
    domain_hash_32(Domain::Fingerprint, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_falcon512_roundtrip() {
        let kp = falcon_keygen().unwrap();
        assert_eq!(kp.public_key.len(), FALCON_PK_SIZE);
        let msg = b"MISAKA Falcon-512";
        let sig = falcon_sign(&kp.secret_key, msg).unwrap();
        assert!(falcon_verify(&kp.public_key, msg, &sig).unwrap());
        assert!(!falcon_verify(&kp.public_key, b"tampered", &sig).unwrap());
    }
}
