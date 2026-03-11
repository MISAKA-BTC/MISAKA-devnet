// ============================================================
// MISAKA Network — Hybrid PQ Signature
// ============================================================
//
// sig = Falcon-512 || Dilithium5
//
// Falcon:    NTRU lattice trapdoor
// Dilithium: Module-LWE Fiat-Shamir with aborts
//
// Different lattice structures → simultaneous cryptanalytic
// break requires attacking BOTH:
//   - NTRU trapdoor inversion (Falcon)
//   - Module-LWE decisional problem (Dilithium)
//
// Verification rule:
//   verify_falcon(msg, falcon_sig) == true
//   AND
//   verify_dilithium(msg, dilithium_sig) == true
//
// If EITHER fails → reject.
//
// Wire format:
//   [falcon_sig_len(2 LE)] [falcon_sig(...)]
//   [dilithium_sig_len(2 LE)] [dilithium_sig(...)]
//
// ============================================================

use crate::falcon;
use crate::dilithium;
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum HybridError {
    #[error("Falcon error: {0}")]
    Falcon(#[from] falcon::FalconError),
    #[error("Dilithium error: {0}")]
    Dilithium(#[from] dilithium::DilithiumError),
    #[error("Hybrid signature too short")]
    TooShort,
}

/// Combined keypair: Falcon-512 + Dilithium5.
pub struct HybridKeyPair {
    pub falcon: falcon::FalconKeyPair,
    pub dilithium: dilithium::DilithiumKeyPair,
    /// Identity fingerprint (from Falcon PK — the primary)
    pub fingerprint: [u8; 32],
}

impl Drop for HybridKeyPair {
    fn drop(&mut self) {
        // FalconKeyPair and DilithiumKeyPair handle their own zeroize
    }
}

/// Generate hybrid keypair: Falcon-512 + Dilithium5.
pub fn hybrid_keygen() -> Result<HybridKeyPair, HybridError> {
    let falcon_kp = falcon::falcon_keygen()?;
    let dilithium_kp = dilithium::dilithium_keygen()?;
    let fingerprint = falcon_kp.fingerprint;
    Ok(HybridKeyPair { falcon: falcon_kp, dilithium: dilithium_kp, fingerprint })
}

/// Hybrid sign: produce Falcon sig || Dilithium sig.
///
/// Both algorithms sign the SAME message.
/// Both are deterministic (④ no DRBG).
pub fn hybrid_sign(
    falcon_sk: &[u8],
    dilithium_sk: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, HybridError> {
    let falcon_sig = falcon::falcon_sign(falcon_sk, message)?;
    let dilithium_sig = dilithium::dilithium_sign(dilithium_sk, message)?;

    // Wire format: [falcon_len(2)] [falcon_sig] [dilithium_len(2)] [dilithium_sig]
    let mut out = Vec::with_capacity(4 + falcon_sig.len() + dilithium_sig.len());
    out.extend_from_slice(&(falcon_sig.len() as u16).to_le_bytes());
    out.extend_from_slice(&falcon_sig);
    out.extend_from_slice(&(dilithium_sig.len() as u16).to_le_bytes());
    out.extend_from_slice(&dilithium_sig);
    Ok(out)
}

/// Hybrid verify: BOTH Falcon AND Dilithium must pass.
///
/// If either fails → reject. No partial acceptance.
pub fn hybrid_verify(
    falcon_pk: &[u8],
    dilithium_pk: &[u8],
    message: &[u8],
    hybrid_sig: &[u8],
) -> Result<bool, HybridError> {
    // Parse wire format
    if hybrid_sig.len() < 4 {
        return Err(HybridError::TooShort);
    }

    let falcon_len = u16::from_le_bytes([hybrid_sig[0], hybrid_sig[1]]) as usize;
    if hybrid_sig.len() < 2 + falcon_len + 2 {
        return Err(HybridError::TooShort);
    }
    let falcon_sig = &hybrid_sig[2..2 + falcon_len];

    let offset = 2 + falcon_len;
    let dilithium_len = u16::from_le_bytes([hybrid_sig[offset], hybrid_sig[offset + 1]]) as usize;
    if hybrid_sig.len() < offset + 2 + dilithium_len {
        return Err(HybridError::TooShort);
    }
    let dilithium_sig = &hybrid_sig[offset + 2..offset + 2 + dilithium_len];

    // BOTH must verify
    let falcon_ok = falcon::falcon_verify(falcon_pk, message, falcon_sig)?;
    if !falcon_ok {
        return Ok(false);
    }

    let dilithium_ok = dilithium::dilithium_verify(dilithium_pk, message, dilithium_sig)?;
    Ok(dilithium_ok)
}

/// Total hybrid signature size (approximate).
pub fn hybrid_sig_size() -> usize {
    // 2 + ~690 + 2 + 4627 ≈ 5321 bytes
    4 + falcon::FALCON_SIG_MAX_SIZE + dilithium::DILITHIUM_SIG_SIZE
}

/// Total hybrid public key size.
pub fn hybrid_pk_size() -> usize {
    // 897 + 2592 = 3489 bytes
    falcon::FALCON_PK_SIZE + dilithium::DILITHIUM_PK_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_sign_verify() {
        let kp = hybrid_keygen().unwrap();
        let msg = b"MISAKA hybrid test";

        let sig = hybrid_sign(
            &kp.falcon.secret_key,
            &kp.dilithium.secret_key,
            msg,
        ).unwrap();

        let valid = hybrid_verify(
            &kp.falcon.public_key,
            &kp.dilithium.public_key,
            msg,
            &sig,
        ).unwrap();
        assert!(valid, "Hybrid sig must verify");
    }

    #[test]
    fn test_hybrid_rejects_tampered_falcon() {
        let kp = hybrid_keygen().unwrap();
        let msg = b"test";
        let mut sig = hybrid_sign(&kp.falcon.secret_key, &kp.dilithium.secret_key, msg).unwrap();

        // Tamper Falcon portion (byte 3 is inside Falcon sig)
        sig[3] ^= 0xFF;

        let valid = hybrid_verify(&kp.falcon.public_key, &kp.dilithium.public_key, msg, &sig).unwrap();
        assert!(!valid, "Tampered Falcon → reject even if Dilithium is fine");
    }

    #[test]
    fn test_hybrid_rejects_tampered_dilithium() {
        let kp = hybrid_keygen().unwrap();
        let msg = b"test";
        let mut sig = hybrid_sign(&kp.falcon.secret_key, &kp.dilithium.secret_key, msg).unwrap();

        // Tamper Dilithium portion (last byte)
        let last = sig.len() - 1;
        sig[last] ^= 0xFF;

        let valid = hybrid_verify(&kp.falcon.public_key, &kp.dilithium.public_key, msg, &sig).unwrap();
        assert!(!valid, "Tampered Dilithium → reject even if Falcon is fine");
    }

    #[test]
    fn test_hybrid_rejects_wrong_message() {
        let kp = hybrid_keygen().unwrap();
        let sig = hybrid_sign(&kp.falcon.secret_key, &kp.dilithium.secret_key, b"msg1").unwrap();
        let valid = hybrid_verify(&kp.falcon.public_key, &kp.dilithium.public_key, b"msg2", &sig).unwrap();
        assert!(!valid);
    }
}
