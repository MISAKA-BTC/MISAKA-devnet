// ============================================================
// MISAKA Node — Genesis Initialization
// ============================================================
//
// Creates deterministic initial chain state from a genesis config.
//
// Usage:
//   let config = GenesisConfig { chain_id: "misaka-devnet-1".into(), ... };
//   let result = initialize_from_genesis(&config, &mut chain_state)?;
//
// Semantics:
//   - Genesis applies at height 0 to an empty chain state
//   - Each allocation creates a deterministic enote in the UTXO set
//   - Allocations are sorted canonically before processing
//   - Genesis hash is deterministic: same config → same hash
//   - Restarting does not reapply genesis (non-empty state skipped)
//
// Enote derivation:
//   For each allocation, a genesis enote is created with:
//     enote_id = H(GENESIS || chain_id || index || address, 32)
//     one_time_address = address bytes
//     amount_commitment = H(COMMIT || amount, 32) (transparent for genesis)
//
// ============================================================

use misaka_tx::{
    EnoteId, AmountCommitment, NoteCommitment, StoredEnote, ASSET_NATIVE, ENOTE_VERSION,
    TxStateStore,
};
use misaka_store::ChainState;
use misaka_crypto::hash::{Domain, domain_hash_multi};
use serde::{Serialize, Deserialize};

// ════════════════════════════════════════════
// Types
// ════════════════════════════════════════════

/// A single genesis allocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisAllocation {
    /// Recipient address (32-byte one-time address or wallet fingerprint).
    pub address: [u8; 32],
    /// Amount to allocate.
    pub amount: u64,
    /// Asset ID (defaults to native asset if None).
    pub asset_id: Option<[u8; 32]>,
    /// Optional memo (not consensus-critical, for operator reference).
    pub memo: Option<String>,
}

/// Genesis configuration for chain initialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Chain identifier (e.g., "misaka-devnet-1").
    pub chain_id: String,
    /// Genesis timestamp (Unix seconds).
    pub genesis_time: u64,
    /// Initial allocations.
    pub allocations: Vec<GenesisAllocation>,
    /// Initial height (should be 0).
    pub initial_height: u64,
}

/// Result of genesis initialization.
#[derive(Debug, Clone)]
pub struct GenesisResult {
    /// Deterministic genesis hash.
    pub genesis_hash: [u8; 32],
    /// Number of allocations applied.
    pub allocations_applied: usize,
    /// Total amount allocated.
    pub total_supply: u128,
    /// Whether genesis was actually applied (false if skipped).
    pub applied: bool,
}

/// Public genesis metadata (safe to expose via RPC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisInfo {
    pub chain_id: String,
    pub genesis_time: u64,
    pub genesis_hash: String,
    pub allocation_count: usize,
    pub total_supply: u128,
}

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    #[error("Genesis config invalid: {0}")]
    ConfigInvalid(String),
    #[error("Genesis already applied: chain state is non-empty")]
    AlreadyApplied,
    #[error("Genesis application failed: {0}")]
    ApplicationFailed(String),
    #[error("Genesis allocation overflow: total supply exceeds u128")]
    AllocationOverflow,
    #[error("Duplicate genesis allocation for address {0}")]
    DuplicateAllocation(String),
    #[error("Zero amount allocation at index {0}")]
    ZeroAmount(usize),
    #[error("Empty chain_id")]
    EmptyChainId,
    #[error("Empty allocations list")]
    EmptyAllocations,
}

// ════════════════════════════════════════════
// Validation
// ════════════════════════════════════════════

/// Validate a genesis config before application.
pub fn validate_genesis_config(config: &GenesisConfig) -> Result<(), GenesisError> {
    if config.chain_id.is_empty() {
        return Err(GenesisError::EmptyChainId);
    }
    if config.allocations.is_empty() {
        return Err(GenesisError::EmptyAllocations);
    }

    // Check for zero amounts
    for (i, alloc) in config.allocations.iter().enumerate() {
        if alloc.amount == 0 {
            return Err(GenesisError::ZeroAmount(i));
        }
    }

    // Check for duplicate addresses
    let mut seen = std::collections::HashSet::new();
    for alloc in &config.allocations {
        if !seen.insert(alloc.address) {
            return Err(GenesisError::DuplicateAllocation(
                hex::encode(alloc.address),
            ));
        }
    }

    // Check total supply overflow
    let total: u128 = config.allocations.iter()
        .map(|a| a.amount as u128)
        .try_fold(0u128, |acc, x| acc.checked_add(x))
        .ok_or(GenesisError::AllocationOverflow)?;

    if total == 0 {
        return Err(GenesisError::ConfigInvalid("total supply is zero".into()));
    }

    Ok(())
}

// ════════════════════════════════════════════
// Genesis hash
// ════════════════════════════════════════════

/// Compute deterministic genesis hash from config.
///
/// Hash = H(BLOCK || "GENESIS" || chain_id || genesis_time ||
///          for each allocation: address || amount)
///
/// Allocations are sorted by address for canonical ordering.
pub fn compute_genesis_hash(config: &GenesisConfig) -> [u8; 32] {
    let mut inputs: Vec<&[u8]> = Vec::new();

    let genesis_tag = b"MISAKA_GENESIS_V1";
    let time_bytes = config.genesis_time.to_le_bytes();
    inputs.push(genesis_tag);
    inputs.push(config.chain_id.as_bytes());
    inputs.push(&time_bytes);

    // Sort allocations by address for deterministic ordering
    let mut sorted_allocs = config.allocations.clone();
    sorted_allocs.sort_by_key(|a| a.address);

    // We need to collect byte representations
    let alloc_bytes: Vec<Vec<u8>> = sorted_allocs.iter().map(|a| {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&a.address);
        bytes.extend_from_slice(&a.amount.to_le_bytes());
        bytes
    }).collect();

    let alloc_refs: Vec<&[u8]> = alloc_bytes.iter().map(|b| b.as_slice()).collect();

    let mut all_inputs = inputs;
    all_inputs.extend(alloc_refs.iter());

    domain_hash_multi(Domain::Block, &all_inputs, 32).try_into().unwrap()
}

// ════════════════════════════════════════════
// Genesis enote derivation
// ════════════════════════════════════════════

/// Derive a deterministic enote ID for a genesis allocation.
fn derive_genesis_enote_id(chain_id: &str, index: usize, address: &[u8; 32]) -> EnoteId {
    let idx_bytes = (index as u64).to_le_bytes();
    let hash = domain_hash_multi(
        Domain::Block,
        &[b"MISAKA_GENESIS_ENOTE", chain_id.as_bytes(), &idx_bytes, address],
        32,
    );
    EnoteId(hash.try_into().unwrap())
}

/// Create a StoredEnote from a genesis allocation.
fn create_genesis_enote(
    chain_id: &str,
    index: usize,
    alloc: &GenesisAllocation,
) -> StoredEnote {
    let enote_id = derive_genesis_enote_id(chain_id, index, &alloc.address);
    let asset_id = alloc.asset_id.unwrap_or(ASSET_NATIVE);

    // Transparent amount commitment for genesis (amount is public)
    let ac_hash = domain_hash_multi(
        Domain::Commitment,
        &[b"GENESIS_AMOUNT", &alloc.amount.to_le_bytes()],
        32,
    );

    // Note commitment (deterministic from genesis parameters)
    let nc_hash = domain_hash_multi(
        Domain::Block,
        &[b"GENESIS_NOTE", &enote_id.0, &alloc.address],
        32,
    );

    StoredEnote {
        enote_id,
        one_time_address: alloc.address,
        amount_commitment: AmountCommitment(ac_hash.try_into().unwrap()),
        note_commitment: NoteCommitment(nc_hash.try_into().unwrap()),
        view_tag: 0,
        asset_id,
        enote_version: ENOTE_VERSION,
        created_at: 0,
    }
}

// ════════════════════════════════════════════
// Genesis application
// ════════════════════════════════════════════

/// Initialize chain state from genesis config.
///
/// Behavior:
///   - If chain state is non-empty (tip_hash != 0 || has enotes),
///     returns GenesisResult { applied: false } — idempotent on restart.
///   - If chain state is empty, validates config, creates genesis enotes,
///     inserts them, sets tip to genesis hash at height 0.
///
/// Deterministic: same config always produces same state.
pub fn initialize_from_genesis(
    config: &GenesisConfig,
    state: &mut ChainState,
) -> Result<GenesisResult, GenesisError> {
    // Check if already initialized
    if *state.tip_hash() != [0u8; 32] || state.enote_count() > 0 || state.link_tag_count() > 0 {
        return Ok(GenesisResult {
            genesis_hash: compute_genesis_hash(config),
            allocations_applied: 0,
            total_supply: 0,
            applied: false,
        });
    }

    // Validate
    validate_genesis_config(config)?;

    let genesis_hash = compute_genesis_hash(config);

    // Sort allocations by address for deterministic order
    let mut sorted_allocs = config.allocations.clone();
    sorted_allocs.sort_by_key(|a| a.address);

    let mut total_supply: u128 = 0;

    // Create and insert genesis enotes
    for (i, alloc) in sorted_allocs.iter().enumerate() {
        let enote = create_genesis_enote(&config.chain_id, i, alloc);
        state.insert_enote(&enote)
            .map_err(|e| GenesisError::ApplicationFailed(format!("enote {}: {}", i, e)))?;
        total_supply += alloc.amount as u128;
    }

    // Set genesis tip
    state.set_tip(genesis_hash, config.initial_height);

    Ok(GenesisResult {
        genesis_hash,
        allocations_applied: sorted_allocs.len(),
        total_supply,
        applied: true,
    })
}

/// Initialize from genesis only if chain state is empty.
///
/// Convenience wrapper that returns Ok even if already initialized.
pub fn initialize_from_genesis_if_needed(
    config: &GenesisConfig,
    state: &mut ChainState,
) -> Result<GenesisResult, GenesisError> {
    initialize_from_genesis(config, state)
}

/// Build GenesisInfo metadata from a config (safe to expose via RPC).
pub fn genesis_info(config: &GenesisConfig) -> GenesisInfo {
    let total: u128 = config.allocations.iter().map(|a| a.amount as u128).sum();
    GenesisInfo {
        chain_id: config.chain_id.clone(),
        genesis_time: config.genesis_time,
        genesis_hash: hex::encode(compute_genesis_hash(config)),
        allocation_count: config.allocations.len(),
        total_supply: total,
    }
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_store::ChainState;

    fn test_config() -> GenesisConfig {
        GenesisConfig {
            chain_id: "misaka-test-1".into(),
            genesis_time: 1700000000,
            allocations: vec![
                GenesisAllocation {
                    address: [0x01; 32],
                    amount: 1_000_000,
                    asset_id: None,
                    memo: Some("faucet".into()),
                },
                GenesisAllocation {
                    address: [0x02; 32],
                    amount: 500_000,
                    asset_id: None,
                    memo: Some("validator-1".into()),
                },
                GenesisAllocation {
                    address: [0x03; 32],
                    amount: 500_000,
                    asset_id: None,
                    memo: Some("dev".into()),
                },
            ],
            initial_height: 0,
        }
    }

    // ── Config validation ──

    #[test]
    fn test_valid_config() {
        assert!(validate_genesis_config(&test_config()).is_ok());
    }

    #[test]
    fn test_empty_chain_id_rejected() {
        let mut cfg = test_config();
        cfg.chain_id = String::new();
        assert!(matches!(validate_genesis_config(&cfg), Err(GenesisError::EmptyChainId)));
    }

    #[test]
    fn test_empty_allocations_rejected() {
        let mut cfg = test_config();
        cfg.allocations = vec![];
        assert!(matches!(validate_genesis_config(&cfg), Err(GenesisError::EmptyAllocations)));
    }

    #[test]
    fn test_zero_amount_rejected() {
        let mut cfg = test_config();
        cfg.allocations[0].amount = 0;
        assert!(matches!(validate_genesis_config(&cfg), Err(GenesisError::ZeroAmount(0))));
    }

    #[test]
    fn test_duplicate_address_rejected() {
        let mut cfg = test_config();
        cfg.allocations[1].address = cfg.allocations[0].address;
        assert!(matches!(validate_genesis_config(&cfg), Err(GenesisError::DuplicateAllocation(_))));
    }

    // ── Genesis hash ──

    #[test]
    fn test_genesis_hash_deterministic() {
        let cfg = test_config();
        let h1 = compute_genesis_hash(&cfg);
        let h2 = compute_genesis_hash(&cfg);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_config_different_hash() {
        let cfg1 = test_config();
        let mut cfg2 = test_config();
        cfg2.chain_id = "misaka-test-2".into();
        assert_ne!(compute_genesis_hash(&cfg1), compute_genesis_hash(&cfg2));
    }

    #[test]
    fn test_genesis_hash_order_independent() {
        // Allocations are sorted internally, so swapping order produces same hash
        let cfg1 = test_config();
        let mut cfg2 = test_config();
        cfg2.allocations.reverse();
        assert_eq!(compute_genesis_hash(&cfg1), compute_genesis_hash(&cfg2));
    }

    // ── Genesis initialization ──

    #[test]
    fn test_genesis_applies_to_empty_state() {
        let cfg = test_config();
        let mut state = ChainState::genesis();

        let result = initialize_from_genesis(&cfg, &mut state).unwrap();
        assert!(result.applied);
        assert_eq!(result.allocations_applied, 3);
        assert_eq!(result.total_supply, 2_000_000);
        assert_eq!(*state.tip_hash(), result.genesis_hash);
        assert_eq!(state.tip_height(), 0);
        assert_eq!(state.enote_count(), 3);
    }

    #[test]
    fn test_genesis_does_not_reapply() {
        let cfg = test_config();
        let mut state = ChainState::genesis();

        let r1 = initialize_from_genesis(&cfg, &mut state).unwrap();
        assert!(r1.applied);

        let r2 = initialize_from_genesis(&cfg, &mut state).unwrap();
        assert!(!r2.applied);
        assert_eq!(state.enote_count(), 3); // not doubled
    }

    #[test]
    fn test_genesis_skips_non_empty_state() {
        let cfg = test_config();
        let mut state = ChainState::genesis();

        // Pre-populate state
        state.set_tip([0xFF; 32], 5);

        let result = initialize_from_genesis(&cfg, &mut state).unwrap();
        assert!(!result.applied);
    }

    // ── Genesis enote derivation ──

    #[test]
    fn test_genesis_enote_ids_deterministic() {
        let id1 = derive_genesis_enote_id("test", 0, &[0x01; 32]);
        let id2 = derive_genesis_enote_id("test", 0, &[0x01; 32]);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_genesis_enote_ids_unique() {
        let id1 = derive_genesis_enote_id("test", 0, &[0x01; 32]);
        let id2 = derive_genesis_enote_id("test", 1, &[0x01; 32]);
        let id3 = derive_genesis_enote_id("test", 0, &[0x02; 32]);
        assert_ne!(id1, id2);
        assert_ne!(id1, id3);
    }

    // ── Genesis info ──

    #[test]
    fn test_genesis_info() {
        let cfg = test_config();
        let info = genesis_info(&cfg);
        assert_eq!(info.chain_id, "misaka-test-1");
        assert_eq!(info.allocation_count, 3);
        assert_eq!(info.total_supply, 2_000_000);
    }

    // ── Integration: first block after genesis ──

    #[test]
    fn test_first_block_after_genesis() {
        let cfg = test_config();
        let mut state = ChainState::genesis();

        let result = initialize_from_genesis(&cfg, &mut state).unwrap();
        assert!(result.applied);

        // State should be at height 0 with genesis hash
        assert_eq!(state.tip_height(), 0);
        assert_eq!(*state.tip_hash(), result.genesis_hash);

        // A real block at height 1 with prev_hash = genesis_hash would work
        // (not testing full block application here, just state consistency)
    }
}
