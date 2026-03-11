// ============================================================
// MISAKA Network — Transaction Signature
// ============================================================
//
// Three-layer signature structure:
//
//   TX {
//     hybrid_sig:  Falcon-512 || Dilithium5   // MANDATORY (PQ)
//     ed25519_sig: Option<Ed25519>             // OPTIONAL  (classical)
//   }
//
// Verification:
//   verify_hybrid(falcon_pk, dilithium_pk, msg, hybrid_sig) == true
//   AND
//   (if ed25519_sig exists → verify_ed25519(ed25519_pk, msg, ed25519_sig) == true)
//
// Address:
//   address = SHAKE256("MISAKA_ADDR" || pk_commit(falcon_pk), 32)
//   → Falcon is the identity anchor (32 bytes, ⑤)
//
// ============================================================

use crate::falcon;
use crate::dilithium;
use crate::hybrid_sig;
use crate::ed25519;
use crate::hash::{Domain, domain_hash_32};
use crate::pk_commit::falcon_pk_commitment;
use crate::address::Address;

/// A signed transaction.
#[derive(Clone)]
pub struct SignedTransaction {
    pub payload: Vec<u8>,

    // === MANDATORY: Hybrid PQ (Falcon-512 || Dilithium5) ===
    pub falcon_pubkey: Vec<u8>,     // 897 bytes
    pub dilithium_pubkey: Vec<u8>,  // 2592 bytes
    pub hybrid_signature: Vec<u8>,  // ~5321 bytes

    // === OPTIONAL: Classical (Ed25519) ===
    pub ed25519_pubkey: Option<[u8; 32]>,
    pub ed25519_signature: Option<[u8; 64]>,
}

#[derive(Debug)]
pub struct TxVerifyResult {
    pub valid: bool,
    pub falcon_valid: bool,
    pub dilithium_valid: bool,
    pub ed25519_present: bool,
    pub ed25519_valid: Option<bool>,
    pub error: Option<String>,
}

/// Verify a transaction.
///
/// Rule:
///   1. Hybrid (Falcon || Dilithium) MUST both verify
///   2. If Ed25519 present, it MUST also verify
///   3. Missing Ed25519 is OK
///   4. Present-but-invalid Ed25519 → REJECT
pub fn verify_transaction(tx: &SignedTransaction) -> TxVerifyResult {
    let tx_hash = domain_hash_32(Domain::Sig, &tx.payload);

    // Step 1: Hybrid PQ verification (MANDATORY)
    let hybrid_ok = match hybrid_sig::hybrid_verify(
        &tx.falcon_pubkey,
        &tx.dilithium_pubkey,
        &tx_hash,
        &tx.hybrid_signature,
    ) {
        Ok(valid) => valid,
        Err(e) => {
            return TxVerifyResult {
                valid: false, falcon_valid: false, dilithium_valid: false,
                ed25519_present: tx.ed25519_signature.is_some(),
                ed25519_valid: None,
                error: Some(format!("Hybrid verify error: {e}")),
            };
        }
    };

    if !hybrid_ok {
        return TxVerifyResult {
            valid: false, falcon_valid: false, dilithium_valid: false,
            ed25519_present: tx.ed25519_signature.is_some(),
            ed25519_valid: None,
            error: Some("Hybrid PQ signature invalid".into()),
        };
    }

    // Step 2: Ed25519 (OPTIONAL but strict if present)
    let ed25519_present = tx.ed25519_signature.is_some();
    let ed25519_valid = if let (Some(pk), Some(sig)) = (&tx.ed25519_pubkey, &tx.ed25519_signature) {
        match ed25519::ed25519_verify(pk, &tx_hash, sig) {
            Ok(true) => Some(true),
            Ok(false) => {
                return TxVerifyResult {
                    valid: false, falcon_valid: true, dilithium_valid: true,
                    ed25519_present: true, ed25519_valid: Some(false),
                    error: Some("Ed25519 present but INVALID — rejected".into()),
                };
            }
            Err(e) => {
                return TxVerifyResult {
                    valid: false, falcon_valid: true, dilithium_valid: true,
                    ed25519_present: true, ed25519_valid: Some(false),
                    error: Some(format!("Ed25519 error: {e}")),
                };
            }
        }
    } else {
        None
    };

    TxVerifyResult {
        valid: true,
        falcon_valid: true,
        dilithium_valid: true,
        ed25519_present,
        ed25519_valid,
        error: None,
    }
}

/// Address from Falcon PK (⑤ 32 bytes).
pub fn tx_sender_address(tx: &SignedTransaction, testnet: bool) -> Address {
    let commitment = falcon_pk_commitment(&tx.falcon_pubkey);
    Address::from_commitment(&commitment, testnet)
}

/// Sign with hybrid PQ only (no Ed25519).
pub fn sign_tx_hybrid_only(
    payload: &[u8],
    falcon_pk: &[u8],
    falcon_sk: &[u8],
    dilithium_pk: &[u8],
    dilithium_sk: &[u8],
) -> Result<SignedTransaction, Box<dyn std::error::Error>> {
    let tx_hash = domain_hash_32(Domain::Sig, payload);
    let hybrid_sig = hybrid_sig::hybrid_sign(falcon_sk, dilithium_sk, &tx_hash)?;
    Ok(SignedTransaction {
        payload: payload.to_vec(),
        falcon_pubkey: falcon_pk.to_vec(),
        dilithium_pubkey: dilithium_pk.to_vec(),
        hybrid_signature: hybrid_sig,
        ed25519_pubkey: None,
        ed25519_signature: None,
    })
}

/// Sign with hybrid PQ + Ed25519.
pub fn sign_tx_full(
    payload: &[u8],
    falcon_pk: &[u8],
    falcon_sk: &[u8],
    dilithium_pk: &[u8],
    dilithium_sk: &[u8],
    ed25519_pk: &[u8; 32],
    ed25519_sk: &[u8; 32],
) -> Result<SignedTransaction, Box<dyn std::error::Error>> {
    let tx_hash = domain_hash_32(Domain::Sig, payload);
    let hybrid_sig = hybrid_sig::hybrid_sign(falcon_sk, dilithium_sk, &tx_hash)?;
    let ed_sig = ed25519::ed25519_sign(ed25519_sk, &tx_hash)?;
    Ok(SignedTransaction {
        payload: payload.to_vec(),
        falcon_pubkey: falcon_pk.to_vec(),
        dilithium_pubkey: dilithium_pk.to_vec(),
        hybrid_signature: hybrid_sig,
        ed25519_pubkey: Some(*ed25519_pk),
        ed25519_signature: Some(ed_sig),
    })
}

/// Wire format serialization.
pub fn serialize_signed_tx(tx: &SignedTransaction) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(3u8); // version 3 = hybrid

    // Payload
    buf.extend_from_slice(&(tx.payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(&tx.payload);

    // Falcon PK (897)
    buf.extend_from_slice(&tx.falcon_pubkey);
    // Dilithium PK (2592)
    buf.extend_from_slice(&tx.dilithium_pubkey);
    // Hybrid signature
    buf.extend_from_slice(&(tx.hybrid_signature.len() as u16).to_le_bytes());
    buf.extend_from_slice(&tx.hybrid_signature);

    // Ed25519 optional
    if let (Some(pk), Some(sig)) = (&tx.ed25519_pubkey, &tx.ed25519_signature) {
        buf.push(1u8);
        buf.extend_from_slice(pk);
        buf.extend_from_slice(sig);
    } else {
        buf.push(0u8);
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon;
    use crate::dilithium;
    use crate::ed25519;

    #[test]
    fn test_hybrid_only_tx() {
        let fkp = falcon::falcon_keygen().unwrap();
        let dkp = dilithium::dilithium_keygen().unwrap();
        let tx = sign_tx_hybrid_only(
            b"send 100", &fkp.public_key, &fkp.secret_key,
            &dkp.public_key, &dkp.secret_key,
        ).unwrap();
        let r = verify_transaction(&tx);
        assert!(r.valid);
        assert!(r.falcon_valid);
        assert!(r.dilithium_valid);
        assert!(!r.ed25519_present);
    }

    #[test]
    fn test_full_triple_sig_tx() {
        let fkp = falcon::falcon_keygen().unwrap();
        let dkp = dilithium::dilithium_keygen().unwrap();
        let ekp = ed25519::ed25519_keygen(&[0x42; 32]);
        let tx = sign_tx_full(
            b"send 100", &fkp.public_key, &fkp.secret_key,
            &dkp.public_key, &dkp.secret_key,
            &ekp.public_key, &ekp.secret_key,
        ).unwrap();
        let r = verify_transaction(&tx);
        assert!(r.valid);
        assert!(r.ed25519_present);
        assert_eq!(r.ed25519_valid, Some(true));
    }

    #[test]
    fn test_bad_hybrid_rejects() {
        let fkp = falcon::falcon_keygen().unwrap();
        let dkp = dilithium::dilithium_keygen().unwrap();
        let mut tx = sign_tx_hybrid_only(
            b"send", &fkp.public_key, &fkp.secret_key,
            &dkp.public_key, &dkp.secret_key,
        ).unwrap();
        tx.hybrid_signature[5] ^= 0xFF;
        assert!(!verify_transaction(&tx).valid);
    }

    #[test]
    fn test_bad_ed25519_rejects_with_good_hybrid() {
        let fkp = falcon::falcon_keygen().unwrap();
        let dkp = dilithium::dilithium_keygen().unwrap();
        let ekp = ed25519::ed25519_keygen(&[0x42; 32]);
        let mut tx = sign_tx_full(
            b"send", &fkp.public_key, &fkp.secret_key,
            &dkp.public_key, &dkp.secret_key,
            &ekp.public_key, &ekp.secret_key,
        ).unwrap();
        tx.ed25519_signature.as_mut().unwrap()[0] ^= 0xFF;
        let r = verify_transaction(&tx);
        assert!(!r.valid);
        assert!(r.falcon_valid); // hybrid was fine
        assert_eq!(r.ed25519_valid, Some(false));
    }

    #[test]
    fn test_address_is_falcon_derived_32bytes() {
        let fkp = falcon::falcon_keygen().unwrap();
        let dkp = dilithium::dilithium_keygen().unwrap();
        let tx = sign_tx_hybrid_only(
            b"test", &fkp.public_key, &fkp.secret_key,
            &dkp.public_key, &dkp.secret_key,
        ).unwrap();
        let addr = tx_sender_address(&tx, false);
        assert_eq!(addr.payload.len(), 32); // ⑤ 32 bytes
    }
}
