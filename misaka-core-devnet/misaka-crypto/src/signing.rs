// ============================================================
// MISAKA Network — Falcon Signing Hardening
// ============================================================
//
// Production-grade signing layer for all critical paths:
//   - Block header proposer signatures
//   - Consensus proposals
//   - Prevotes / precommits
//   - Wallet spend authorization
//
// Design:
//   1. Canonical sign-byte builders per signed object type
//   2. Explicit domain prefixes (versioned, unique per type)
//   3. Key role wrappers (validator vs wallet spend)
//   4. Unified sign/verify API
//
// DRBG:
//   PQClean Falcon-512 uses deterministic internal nonce derivation
//   (no external DRBG needed). This is documented in falcon.rs:
//   "④ Deterministic signing: PQClean Falcon uses internal
//    deterministic nonce derivation. External DRBG removed."
//   If a future Falcon implementation requires external randomness,
//   the SigningContext abstraction below provides the hook point.
//
// Persistence ordering:
//   For consensus votes: WAL write BEFORE anti-equivocation flag.
//   For wallet spend: signing failure must not partially mutate state.
//   These ordering rules are enforced at the call sites, not here.
//   This module provides the signing primitive; callers enforce ordering.
//
// ============================================================

use crate::falcon::{self, FalconError, FalconKeyPair, FALCON_PK_SIZE, FALCON_SK_SIZE};
use crate::hash::{Domain, domain_hash_multi};
use zeroize::Zeroize;

// ════════════════════════════════════════════
// Domain prefixes (versioned, unique per type)
// ════════════════════════════════════════════

/// Domain prefix bytes for each signed object type.
///
/// Requirements:
///   - Each type has a unique prefix
///   - Prefixes are versioned (V1 suffix)
///   - No prefix is a prefix of another
///   - Changing the version creates an incompatible signing domain
///
/// Note: These are payload-level prefixes passed to domain_hash_multi,
/// which already adds its own Domain:: tag. No null terminators needed.
pub mod domains {
    pub const BLOCK_HEADER_V1: &[u8] = b"MISAKA_BLOCK_HEADER_V1";
    pub const PROPOSAL_V1: &[u8] = b"MISAKA_PROPOSAL_V1";
    pub const PREVOTE_V1: &[u8] = b"MISAKA_PREVOTE_V1";
    pub const PRECOMMIT_V1: &[u8] = b"MISAKA_PRECOMMIT_V1";
    pub const WALLET_SPEND_AUTH_V1: &[u8] = b"MISAKA_WALLET_SPEND_AUTH_V1";
}

// ════════════════════════════════════════════
// Key roles
// ════════════════════════════════════════════

/// Role of a signing key. Prevents accidental cross-role usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// Validator consensus key — signs proposals, prevotes, precommits.
    ValidatorConsensus,
    /// Block proposer key — signs block headers.
    /// (Currently same physical key as ValidatorConsensus.)
    BlockProposer,
    /// Wallet spend authorization key — signs spend-auth messages.
    WalletSpend,
}

/// A Falcon secret key with an explicit role tag.
pub struct RoleTaggedSecretKey {
    pub role: KeyRole,
    pub secret_key: Vec<u8>,
    pub fingerprint: [u8; 32],
}

impl Drop for RoleTaggedSecretKey {
    fn drop(&mut self) { self.secret_key.zeroize(); }
}

impl RoleTaggedSecretKey {
    /// Create from a FalconKeyPair with a specific role.
    pub fn from_keypair(kp: &FalconKeyPair, role: KeyRole) -> Self {
        Self {
            role,
            secret_key: kp.secret_key.clone(),
            fingerprint: kp.fingerprint,
        }
    }

    /// Create from raw secret key bytes + fingerprint.
    pub fn from_raw(sk: Vec<u8>, fingerprint: [u8; 32], role: KeyRole) -> Self {
        Self { role, secret_key: sk, fingerprint }
    }
}

/// A Falcon public key with an explicit role tag.
#[derive(Debug, Clone)]
pub struct RoleTaggedPublicKey {
    pub role: KeyRole,
    pub public_key: Vec<u8>,
    pub fingerprint: [u8; 32],
}

impl RoleTaggedPublicKey {
    pub fn from_keypair(kp: &FalconKeyPair, role: KeyRole) -> Self {
        Self {
            role,
            public_key: kp.public_key.clone(),
            fingerprint: kp.fingerprint,
        }
    }
}

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("Falcon signing failed: {0}")]
    FalconSigningFailed(#[from] FalconError),
    #[error("Falcon verification failed")]
    FalconVerificationFailed,
    #[error("Wrong key role: expected {expected:?}, got {actual:?}")]
    WrongKeyRole { expected: KeyRole, actual: KeyRole },
    #[error("Invalid signing domain")]
    InvalidSigningDomain,
    #[error("Canonical encoding error: {0}")]
    CanonicalEncodingError(String),
    #[error("Wallet spend auth invalid: {0}")]
    WalletSpendAuthInvalid(String),
    #[error("Proposal signature invalid")]
    ProposalSignatureInvalid,
    #[error("Vote signature invalid")]
    VoteSignatureInvalid,
    #[error("Block signature invalid")]
    BlockSignatureInvalid,
}

// ════════════════════════════════════════════
// Canonical sign-byte builders
// ════════════════════════════════════════════

/// Canonical bytes for block header signing.
///
/// Fields: version, height, round, prev_hash, timestamp,
///         tx_merkle_root, utxo_root, link_tag_root, proposer_id
///
/// These are the content-addressed fields of the block header.
/// proposer_sig and bft_sigs are NOT included (they're the signatures themselves).
pub fn block_header_sign_bytes(
    version: u32,
    height: u64,
    round: u32,
    prev_hash: &[u8; 32],
    timestamp: u64,
    tx_merkle_root: &[u8; 32],
    utxo_root: &[u8; 32],
    link_tag_root: &[u8; 32],
    proposer_id: &[u8; 32],
) -> [u8; 32] {
    domain_hash_multi(
        Domain::Block,
        &[
            domains::BLOCK_HEADER_V1,
            &version.to_le_bytes(),
            &height.to_le_bytes(),
            &round.to_le_bytes(),
            prev_hash,
            &timestamp.to_le_bytes(),
            tx_merkle_root,
            utxo_root,
            link_tag_root,
            proposer_id,
        ],
        32,
    ).try_into().unwrap()
}

/// Canonical bytes for proposal signing.
///
/// Fields: height, round, block_hash
pub fn proposal_sign_bytes(height: u64, round: u32, block_hash: &[u8; 32]) -> [u8; 32] {
    domain_hash_multi(
        Domain::Block,
        &[
            domains::PROPOSAL_V1,
            &height.to_le_bytes(),
            &round.to_le_bytes(),
            block_hash,
        ],
        32,
    ).try_into().unwrap()
}

/// Canonical bytes for prevote signing.
///
/// Fields: height, round, block_hash (or nil sentinel)
pub fn prevote_sign_bytes(
    height: u64,
    round: u32,
    block_hash: Option<&[u8; 32]>,
) -> [u8; 32] {
    let nil_hash = [0u8; 32];
    let bh = block_hash.unwrap_or(&nil_hash);
    domain_hash_multi(
        Domain::Vote,
        &[
            domains::PREVOTE_V1,
            &height.to_le_bytes(),
            &round.to_le_bytes(),
            bh,
        ],
        32,
    ).try_into().unwrap()
}

/// Canonical bytes for precommit signing.
///
/// Fields: height, round, block_hash (or nil sentinel)
pub fn precommit_sign_bytes(
    height: u64,
    round: u32,
    block_hash: Option<&[u8; 32]>,
) -> [u8; 32] {
    let nil_hash = [0u8; 32];
    let bh = block_hash.unwrap_or(&nil_hash);
    domain_hash_multi(
        Domain::Vote,
        &[
            domains::PRECOMMIT_V1,
            &height.to_le_bytes(),
            &round.to_le_bytes(),
            bh,
        ],
        32,
    ).try_into().unwrap()
}

/// Canonical bytes for wallet spend authorization.
///
/// Fields: tx_binding_hash, input_index, chain_id, version
///
/// The wallet spend auth signs a commitment to the exact tx being authorized.
/// chain_id provides network-level replay protection.
pub fn wallet_spend_auth_sign_bytes(
    tx_binding_hash: &[u8; 32],
    input_index: u32,
    chain_id: &[u8],
    version: u32,
) -> [u8; 32] {
    domain_hash_multi(
        Domain::Sig,
        &[
            domains::WALLET_SPEND_AUTH_V1,
            tx_binding_hash,
            &input_index.to_le_bytes(),
            chain_id,
            &version.to_le_bytes(),
        ],
        32,
    ).try_into().unwrap()
}

// ════════════════════════════════════════════
// Unified sign/verify API
// ════════════════════════════════════════════

/// Sign canonical bytes with a domain-tagged Falcon key.
///
/// The caller MUST construct canonical bytes using the appropriate
/// sign-byte builder above. This function adds no additional domain
/// separation — the domain is embedded in the canonical bytes.
///
/// Returns the Falcon-512 detached signature.
pub fn falcon_sign_canonical(
    sk: &[u8],
    canonical_bytes: &[u8; 32],
) -> Result<Vec<u8>, SigningError> {
    Ok(falcon::falcon_sign(sk, canonical_bytes)?)
}

/// Verify a signature against canonical bytes.
///
/// Returns Ok(()) on valid signature, Err on invalid.
pub fn falcon_verify_canonical(
    pk: &[u8],
    canonical_bytes: &[u8; 32],
    signature: &[u8],
) -> Result<(), SigningError> {
    match falcon::falcon_verify(pk, canonical_bytes, signature)? {
        true => Ok(()),
        false => Err(SigningError::FalconVerificationFailed),
    }
}

// ════════════════════════════════════════════
// Role-checked signing helpers
// ════════════════════════════════════════════

/// Sign a proposal with a validator consensus key.
pub fn sign_proposal(
    key: &RoleTaggedSecretKey,
    height: u64,
    round: u32,
    block_hash: &[u8; 32],
) -> Result<Vec<u8>, SigningError> {
    check_role(key, KeyRole::ValidatorConsensus)?;
    let msg = proposal_sign_bytes(height, round, block_hash);
    falcon_sign_canonical(&key.secret_key, &msg)
}

/// Verify a proposal signature.
pub fn verify_proposal(
    pk: &[u8],
    height: u64,
    round: u32,
    block_hash: &[u8; 32],
    signature: &[u8],
) -> Result<(), SigningError> {
    let msg = proposal_sign_bytes(height, round, block_hash);
    falcon_verify_canonical(pk, &msg, signature)
}

/// Sign a block header with a block proposer key.
pub fn sign_block_header(
    key: &RoleTaggedSecretKey,
    version: u32,
    height: u64,
    round: u32,
    prev_hash: &[u8; 32],
    timestamp: u64,
    tx_merkle_root: &[u8; 32],
    utxo_root: &[u8; 32],
    link_tag_root: &[u8; 32],
    proposer_id: &[u8; 32],
) -> Result<Vec<u8>, SigningError> {
    // BlockProposer or ValidatorConsensus both acceptable
    if key.role != KeyRole::BlockProposer && key.role != KeyRole::ValidatorConsensus {
        return Err(SigningError::WrongKeyRole {
            expected: KeyRole::BlockProposer,
            actual: key.role,
        });
    }
    let msg = block_header_sign_bytes(
        version, height, round, prev_hash, timestamp,
        tx_merkle_root, utxo_root, link_tag_root, proposer_id,
    );
    falcon_sign_canonical(&key.secret_key, &msg)
}

/// Sign wallet spend authorization.
pub fn sign_wallet_spend_auth(
    key: &RoleTaggedSecretKey,
    tx_binding_hash: &[u8; 32],
    input_index: u32,
    chain_id: &[u8],
    version: u32,
) -> Result<Vec<u8>, SigningError> {
    check_role(key, KeyRole::WalletSpend)?;
    let msg = wallet_spend_auth_sign_bytes(tx_binding_hash, input_index, chain_id, version);
    falcon_sign_canonical(&key.secret_key, &msg)
}

/// Verify wallet spend authorization signature.
pub fn verify_wallet_spend_auth(
    pk: &[u8],
    tx_binding_hash: &[u8; 32],
    input_index: u32,
    chain_id: &[u8],
    version: u32,
    signature: &[u8],
) -> Result<(), SigningError> {
    let msg = wallet_spend_auth_sign_bytes(tx_binding_hash, input_index, chain_id, version);
    falcon_verify_canonical(pk, &msg, signature)
        .map_err(|_| SigningError::WalletSpendAuthInvalid("signature verification failed".into()))
}

fn check_role(key: &RoleTaggedSecretKey, expected: KeyRole) -> Result<(), SigningError> {
    if key.role != expected {
        Err(SigningError::WrongKeyRole { expected, actual: key.role })
    } else {
        Ok(())
    }
}

// ════════════════════════════════════════════
// DRBG note
// ════════════════════════════════════════════
//
// PQClean Falcon-512 uses fully deterministic internal nonce derivation.
// The signature for a given (secret_key, message) pair is always the same.
// No external DRBG, no nonce state, no persistence needed.
//
// If a future Falcon variant requires external randomness:
//   1. Add a SigningDrbg struct here
//   2. Thread it through falcon_sign_canonical
//   3. Add load_drbg_state / save_drbg_state_atomic helpers
//   4. Enforce state advance before signing completion
//
// For now, the signing module is DRBG-free by design.
//

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon::falcon_keygen;

    fn gen_key() -> FalconKeyPair { falcon_keygen().unwrap() }

    // ── Canonical bytes stability ──

    #[test]
    fn test_proposal_sign_bytes_deterministic() {
        let b1 = proposal_sign_bytes(10, 0, &[0xAA; 32]);
        let b2 = proposal_sign_bytes(10, 0, &[0xAA; 32]);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_prevote_sign_bytes_deterministic() {
        let b1 = prevote_sign_bytes(5, 1, Some(&[0xBB; 32]));
        let b2 = prevote_sign_bytes(5, 1, Some(&[0xBB; 32]));
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_precommit_sign_bytes_deterministic() {
        let b1 = precommit_sign_bytes(5, 1, Some(&[0xCC; 32]));
        let b2 = precommit_sign_bytes(5, 1, Some(&[0xCC; 32]));
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_block_header_sign_bytes_deterministic() {
        let b1 = block_header_sign_bytes(2, 0, 0, &[0; 32], 1000, &[0; 32], &[0; 32], &[0; 32], &[0xAA; 32]);
        let b2 = block_header_sign_bytes(2, 0, 0, &[0; 32], 1000, &[0; 32], &[0; 32], &[0; 32], &[0xAA; 32]);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_wallet_spend_auth_sign_bytes_deterministic() {
        let b1 = wallet_spend_auth_sign_bytes(&[0xDD; 32], 0, b"misaka-1", 2);
        let b2 = wallet_spend_auth_sign_bytes(&[0xDD; 32], 0, b"misaka-1", 2);
        assert_eq!(b1, b2);
    }

    // ── Field changes produce different bytes ──

    #[test]
    fn test_proposal_different_height_different_bytes() {
        let b1 = proposal_sign_bytes(10, 0, &[0xAA; 32]);
        let b2 = proposal_sign_bytes(11, 0, &[0xAA; 32]);
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_prevote_different_round_different_bytes() {
        let b1 = prevote_sign_bytes(5, 0, Some(&[0xBB; 32]));
        let b2 = prevote_sign_bytes(5, 1, Some(&[0xBB; 32]));
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_prevote_nil_vs_non_nil_different() {
        let b1 = prevote_sign_bytes(5, 0, None);
        let b2 = prevote_sign_bytes(5, 0, Some(&[0xBB; 32]));
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_wallet_spend_different_input_index() {
        let b1 = wallet_spend_auth_sign_bytes(&[0xDD; 32], 0, b"chain", 2);
        let b2 = wallet_spend_auth_sign_bytes(&[0xDD; 32], 1, b"chain", 2);
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_wallet_spend_different_chain_id() {
        let b1 = wallet_spend_auth_sign_bytes(&[0xDD; 32], 0, b"mainnet", 2);
        let b2 = wallet_spend_auth_sign_bytes(&[0xDD; 32], 0, b"testnet", 2);
        assert_ne!(b1, b2);
    }

    // ── Domain separation: cross-type non-verifiability ──

    #[test]
    fn test_proposal_sig_cannot_verify_as_prevote() {
        let kp = gen_key();
        let h = 10u64; let r = 0u32; let bh = [0xAA; 32];

        // Sign as proposal
        let proposal_msg = proposal_sign_bytes(h, r, &bh);
        let sig = falcon_sign_canonical(&kp.secret_key, &proposal_msg).unwrap();

        // Verify as prevote — must fail
        let prevote_msg = prevote_sign_bytes(h, r, Some(&bh));
        let result = falcon_verify_canonical(&kp.public_key, &prevote_msg, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_prevote_sig_cannot_verify_as_precommit() {
        let kp = gen_key();
        let h = 5u64; let r = 0u32; let bh = [0xBB; 32];

        let prevote_msg = prevote_sign_bytes(h, r, Some(&bh));
        let sig = falcon_sign_canonical(&kp.secret_key, &prevote_msg).unwrap();

        let precommit_msg = precommit_sign_bytes(h, r, Some(&bh));
        assert!(falcon_verify_canonical(&kp.public_key, &precommit_msg, &sig).is_err());
    }

    #[test]
    fn test_wallet_spend_sig_cannot_verify_as_proposal() {
        let kp = gen_key();

        let spend_msg = wallet_spend_auth_sign_bytes(&[0xDD; 32], 0, b"chain", 2);
        let sig = falcon_sign_canonical(&kp.secret_key, &spend_msg).unwrap();

        let proposal_msg = proposal_sign_bytes(0, 0, &[0xDD; 32]);
        assert!(falcon_verify_canonical(&kp.public_key, &proposal_msg, &sig).is_err());
    }

    // ── Sign/verify roundtrips ──

    #[test]
    fn test_proposal_sign_verify() {
        let kp = gen_key();
        let msg = proposal_sign_bytes(10, 0, &[0xAA; 32]);
        let sig = falcon_sign_canonical(&kp.secret_key, &msg).unwrap();
        assert!(falcon_verify_canonical(&kp.public_key, &msg, &sig).is_ok());
    }

    #[test]
    fn test_prevote_sign_verify() {
        let kp = gen_key();
        let msg = prevote_sign_bytes(5, 1, Some(&[0xBB; 32]));
        let sig = falcon_sign_canonical(&kp.secret_key, &msg).unwrap();
        assert!(falcon_verify_canonical(&kp.public_key, &msg, &sig).is_ok());
    }

    #[test]
    fn test_precommit_sign_verify() {
        let kp = gen_key();
        let msg = precommit_sign_bytes(5, 1, Some(&[0xCC; 32]));
        let sig = falcon_sign_canonical(&kp.secret_key, &msg).unwrap();
        assert!(falcon_verify_canonical(&kp.public_key, &msg, &sig).is_ok());
    }

    #[test]
    fn test_block_header_sign_verify() {
        let kp = gen_key();
        let msg = block_header_sign_bytes(2, 0, 0, &[0; 32], 1000, &[0; 32], &[0; 32], &[0; 32], &[0xAA; 32]);
        let sig = falcon_sign_canonical(&kp.secret_key, &msg).unwrap();
        assert!(falcon_verify_canonical(&kp.public_key, &msg, &sig).is_ok());
    }

    #[test]
    fn test_wallet_spend_auth_sign_verify() {
        let kp = gen_key();
        let msg = wallet_spend_auth_sign_bytes(&[0xDD; 32], 0, b"misaka-testnet", 2);
        let sig = falcon_sign_canonical(&kp.secret_key, &msg).unwrap();
        assert!(falcon_verify_canonical(&kp.public_key, &msg, &sig).is_ok());
    }

    #[test]
    fn test_wrong_pk_fails() {
        let kp1 = gen_key();
        let kp2 = gen_key();
        let msg = proposal_sign_bytes(10, 0, &[0xAA; 32]);
        let sig = falcon_sign_canonical(&kp1.secret_key, &msg).unwrap();
        assert!(falcon_verify_canonical(&kp2.public_key, &msg, &sig).is_err());
    }

    #[test]
    fn test_modified_payload_fails() {
        let kp = gen_key();
        let msg1 = proposal_sign_bytes(10, 0, &[0xAA; 32]);
        let sig = falcon_sign_canonical(&kp.secret_key, &msg1).unwrap();
        let msg2 = proposal_sign_bytes(10, 0, &[0xBB; 32]);
        assert!(falcon_verify_canonical(&kp.public_key, &msg2, &sig).is_err());
    }

    #[test]
    fn test_modified_signature_fails() {
        let kp = gen_key();
        let msg = proposal_sign_bytes(10, 0, &[0xAA; 32]);
        let mut sig = falcon_sign_canonical(&kp.secret_key, &msg).unwrap();
        if let Some(byte) = sig.last_mut() { *byte ^= 0xFF; }
        assert!(falcon_verify_canonical(&kp.public_key, &msg, &sig).is_err());
    }

    // ── Role-checked signing ──

    #[test]
    fn test_sign_proposal_with_validator_key() {
        let kp = gen_key();
        let rsk = RoleTaggedSecretKey::from_keypair(&kp, KeyRole::ValidatorConsensus);
        let sig = sign_proposal(&rsk, 10, 0, &[0xAA; 32]).unwrap();
        assert!(verify_proposal(&kp.public_key, 10, 0, &[0xAA; 32], &sig).is_ok());
    }

    #[test]
    fn test_sign_proposal_with_wallet_key_rejected() {
        let kp = gen_key();
        let rsk = RoleTaggedSecretKey::from_keypair(&kp, KeyRole::WalletSpend);
        let result = sign_proposal(&rsk, 10, 0, &[0xAA; 32]);
        assert!(matches!(result, Err(SigningError::WrongKeyRole { .. })));
    }

    #[test]
    fn test_sign_wallet_spend_with_validator_key_rejected() {
        let kp = gen_key();
        let rsk = RoleTaggedSecretKey::from_keypair(&kp, KeyRole::ValidatorConsensus);
        let result = sign_wallet_spend_auth(&rsk, &[0xDD; 32], 0, b"chain", 2);
        assert!(matches!(result, Err(SigningError::WrongKeyRole { .. })));
    }

    #[test]
    fn test_sign_wallet_spend_roundtrip() {
        let kp = gen_key();
        let rsk = RoleTaggedSecretKey::from_keypair(&kp, KeyRole::WalletSpend);
        let sig = sign_wallet_spend_auth(&rsk, &[0xDD; 32], 0, b"chain", 2).unwrap();
        assert!(verify_wallet_spend_auth(&kp.public_key, &[0xDD; 32], 0, b"chain", 2, &sig).is_ok());
    }

    #[test]
    fn test_sign_block_header_with_validator_key() {
        let kp = gen_key();
        let rsk = RoleTaggedSecretKey::from_keypair(&kp, KeyRole::ValidatorConsensus);
        let sig = sign_block_header(
            &rsk, 2, 0, 0, &[0; 32], 1000, &[0; 32], &[0; 32], &[0; 32], &[0xAA; 32],
        ).unwrap();
        let msg = block_header_sign_bytes(2, 0, 0, &[0; 32], 1000, &[0; 32], &[0; 32], &[0; 32], &[0xAA; 32]);
        assert!(falcon_verify_canonical(&kp.public_key, &msg, &sig).is_ok());
    }

    #[test]
    fn test_sign_block_header_with_wallet_key_rejected() {
        let kp = gen_key();
        let rsk = RoleTaggedSecretKey::from_keypair(&kp, KeyRole::WalletSpend);
        let result = sign_block_header(
            &rsk, 2, 0, 0, &[0; 32], 1000, &[0; 32], &[0; 32], &[0; 32], &[0xAA; 32],
        );
        assert!(matches!(result, Err(SigningError::WrongKeyRole { .. })));
    }
}
