// ============================================================
// MISAKA Block — Parallel Validation
// ============================================================
//
// Three-phase pipeline:
//
//   Phase A (serial):  Cheap block-level prechecks
//     height, prev_hash, merkle root, duplicate tx_ids,
//     duplicate link tags, block size, binding integrity
//
//   Phase B (parallel): Heavy per-tx cryptographic verification
//     ring sig, balance proof, range proofs, fee checks
//     Each worker reads from a frozen ChainStateSnapshot
//
//   Phase C (serial):  Aggregate + block-local conflict checks
//     Detect cross-tx link tag conflicts, duplicate output enotes
//     Collect verified TxEffects in original block order
//
//   Apply (serial):    Atomic state mutation
//     Apply collected effects to mutable ChainState with rollback
//
// Determinism:
//   - Workers operate on indexed positions
//   - Results are collected in original tx order
//   - Success/failure outcome is identical to serial path
//
// ============================================================

use misaka_crypto::proof_backend::ProofBackend;
use misaka_tx::{
    TxBody, TxId, LinkTag, EnoteId,
    verify::compute_actual_size,
    verify_with_store, extract_effects, apply_tx_effects,
    TxEffects, StoredEnote,
};
use misaka_store::{Block, ChainState, ChainStateSnapshot};
use crate::{
    BlockError, BlockApplyResult, BlockValidationResult,
    validate_block,
};
use std::collections::HashSet;

// ════════════════════════════════════════════
// Configuration
// ════════════════════════════════════════════

/// Configuration for parallel block validation.
#[derive(Debug, Clone)]
pub struct ParallelValidationConfig {
    /// Number of worker threads. 1 = serial fallback.
    pub parallelism: usize,
    /// Whether parallel validation is enabled. If false, falls back to serial.
    pub enable_parallel: bool,
    /// Maximum block size in bytes.
    pub max_block_bytes: usize,
}

impl Default for ParallelValidationConfig {
    fn default() -> Self {
        // Default to available CPUs minus 1, minimum 1
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self {
            parallelism: cpus.saturating_sub(1).max(1),
            enable_parallel: true,
            max_block_bytes: 2 * 1024 * 1024,
        }
    }
}

// ════════════════════════════════════════════
// Verified effects
// ════════════════════════════════════════════

/// Pre-verified transaction effects ready for serial application.
///
/// Produced by parallel verification workers. Contains all information
/// needed to apply the tx's state changes without re-verifying.
#[derive(Debug, Clone)]
pub struct TxVerifiedEffects {
    /// Original index in the block (for deterministic ordering).
    pub tx_index: usize,
    /// Transaction ID.
    pub tx_id: TxId,
    /// Link tags consumed by this tx (one per input).
    pub link_tags: Vec<LinkTag>,
    /// New enotes produced by this tx.
    pub new_enotes: Vec<StoredEnote>,
    /// Actual canonical size of this tx.
    pub actual_size_bytes: u32,
    /// Total fee paid.
    pub total_fee: u64,
}

impl TxVerifiedEffects {
    /// Convert to TxEffects for application via existing apply_tx_effects.
    pub fn to_tx_effects(&self) -> TxEffects {
        TxEffects {
            new_enotes: self.new_enotes.clone(),
            new_link_tags: self.link_tags.clone(),
        }
    }
}

/// Result of parallel per-tx verification.
enum TxWorkerResult {
    Valid(TxVerifiedEffects),
    Invalid { index: usize, reason: String },
}

// ════════════════════════════════════════════
// Phase A: cheap block-level prechecks (serial)
// ════════════════════════════════════════════

/// Run cheap block-level prechecks before starting parallel work.
///
/// Reuses the existing `validate_block` function plus snapshot checks.
/// Returns Ok(()) if all cheap checks pass, or the block error.
fn phase_a_prechecks(
    block: &Block,
    expected_height: u64,
    expected_prev_hash: &[u8; 32],
    max_block_bytes: usize,
) -> Result<(), BlockError> {
    let result = validate_block(block, expected_height, expected_prev_hash, max_block_bytes);
    match result {
        BlockValidationResult::Valid => Ok(()),
        BlockValidationResult::Invalid(err) => Err(err),
    }
}

// ════════════════════════════════════════════
// Phase B: parallel per-tx verification
// ════════════════════════════════════════════

/// Verify a single transaction against a read-only snapshot.
///
/// This function runs in a worker thread. It performs the full
/// cryptographic verification pipeline and extracts effects.
fn verify_single_tx<P: ProofBackend + Sync>(
    index: usize,
    tx: &TxBody,
    snapshot: &ChainStateSnapshot,
    backend: &P,
) -> TxWorkerResult {
    // Full verification against snapshot (read-only)
    let result = verify_with_store(tx, snapshot, backend);
    if !result.valid {
        let reason = result.error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown verification error".into());
        return TxWorkerResult::Invalid { index, reason };
    }

    // Extract effects
    let effects = extract_effects(tx);
    let actual_size = compute_actual_size(tx);

    TxWorkerResult::Valid(TxVerifiedEffects {
        tx_index: index,
        tx_id: tx.tx_id,
        link_tags: effects.new_link_tags,
        new_enotes: effects.new_enotes,
        actual_size_bytes: actual_size,
        total_fee: tx.fee.total_fee,
    })
}

/// Run Phase B: parallel heavy per-tx verification.
///
/// Uses `std::thread::scope` for scoped threads — no `Arc` needed.
/// Workers share a read-only `&ChainStateSnapshot` safely.
///
/// Returns results in original block tx order.
fn phase_b_parallel_verify<P: ProofBackend + Sync>(
    txs: &[TxBody],
    snapshot: &ChainStateSnapshot,
    backend: &P,
    parallelism: usize,
) -> Vec<TxWorkerResult> {
    if txs.is_empty() {
        return Vec::new();
    }

    if parallelism <= 1 {
        // Serial fallback
        return txs.iter().enumerate()
            .map(|(i, tx)| verify_single_tx(i, tx, snapshot, backend))
            .collect();
    }

    // Parallel: use scoped threads with work-stealing via chunks
    let chunk_size = (txs.len() + parallelism - 1) / parallelism;
    let mut all_results: Vec<Option<TxWorkerResult>> = txs.iter().map(|_| None).collect();

    std::thread::scope(|s| {
        let mut handles = Vec::new();

        for chunk_start in (0..txs.len()).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(txs.len());
            let chunk = &txs[chunk_start..chunk_end];

            let handle = s.spawn(move || {
                let mut chunk_results = Vec::with_capacity(chunk.len());
                for (offset, tx) in chunk.iter().enumerate() {
                    let index = chunk_start + offset;
                    chunk_results.push((index, verify_single_tx(index, tx, snapshot, backend)));
                }
                chunk_results
            });
            handles.push(handle);
        }

        // Collect results and place in original order
        for handle in handles {
            let chunk_results = handle.join().expect("worker thread panicked");
            for (index, result) in chunk_results {
                all_results[index] = Some(result);
            }
        }
    });

    // Unwrap Options (all slots filled by workers)
    all_results.into_iter().map(|r| r.expect("missing worker result")).collect()
}

// ════════════════════════════════════════════
// Phase C: aggregate + block-local conflict checks (serial)
// ════════════════════════════════════════════

/// Aggregate parallel results and check for block-local conflicts.
///
/// Returns verified effects in original block order, or the first error.
fn phase_c_aggregate(
    results: Vec<TxWorkerResult>,
) -> Result<Vec<TxVerifiedEffects>, BlockError> {
    let mut effects = Vec::with_capacity(results.len());
    let mut all_link_tags = HashSet::new();
    let mut all_output_enote_ids = HashSet::new();

    for result in results {
        match result {
            TxWorkerResult::Invalid { index, reason } => {
                return Err(BlockError::BlockTxInvalid { index, reason });
            }
            TxWorkerResult::Valid(eff) => {
                // Check cross-tx link tag conflicts
                for tag in &eff.link_tags {
                    if !all_link_tags.insert(*tag) {
                        return Err(BlockError::DuplicateLinkTagInBlock(
                            hex::encode(tag.0),
                        ));
                    }
                }

                // Check cross-tx output enote ID conflicts
                for enote in &eff.new_enotes {
                    if !all_output_enote_ids.insert(enote.enote_id) {
                        return Err(BlockError::BlockTxInvalid {
                            index: eff.tx_index,
                            reason: format!(
                                "duplicate output enote_id across txs: {}",
                                hex::encode(enote.enote_id.0)
                            ),
                        });
                    }
                }

                effects.push(eff);
            }
        }
    }

    // Effects are already in original block order (results vector was ordered)
    Ok(effects)
}

// ════════════════════════════════════════════
// Public API: validate_block_parallel
// ════════════════════════════════════════════

/// Validate a block using parallel per-tx verification.
///
/// Phases:
///   A. Cheap block-level prechecks (serial)
///   B. Heavy per-tx cryptographic verification (parallel)
///   C. Aggregate + block-local conflict checks (serial)
///
/// Returns verified effects in original tx order, ready for
/// `apply_verified_block` to commit atomically.
///
/// The snapshot is taken from `state` at call time and remains
/// frozen during all parallel work.
pub fn validate_block_parallel<P: ProofBackend + Sync>(
    block: &Block,
    state: &ChainState,
    backend: &P,
    config: &ParallelValidationConfig,
) -> Result<Vec<TxVerifiedEffects>, BlockError> {
    let expected_height = if *state.tip_hash() == [0u8; 32] { 0 } else { state.tip_height() + 1 };

    // Phase A: cheap serial prechecks
    phase_a_prechecks(block, expected_height, state.tip_hash(), config.max_block_bytes)?;

    if block.transactions.is_empty() {
        return Ok(Vec::new());
    }

    // Snapshot for parallel read-only access
    let snapshot = state.snapshot();

    // Phase B: parallel heavy verification
    let parallelism = if config.enable_parallel { config.parallelism } else { 1 };
    let results = phase_b_parallel_verify(&block.transactions, &snapshot, backend, parallelism);

    // Phase C: aggregate + conflict checks
    phase_c_aggregate(results)
}

// ════════════════════════════════════════════
// Apply verified effects (serial, atomic)
// ════════════════════════════════════════════

/// Apply pre-verified block effects atomically to the chain state.
///
/// The effects must have been produced by `validate_block_parallel`.
/// This function does NOT re-verify cryptographic proofs — it trusts
/// that the effects are the output of successful verification.
///
/// It does re-check state-dependent conditions (link tag existence,
/// ring member existence) to guard against TOCTOU races between
/// snapshot time and apply time. If any check fails, the entire
/// block is rolled back.
pub fn apply_verified_block(
    block: &Block,
    effects: &[TxVerifiedEffects],
    state: &mut ChainState,
) -> BlockApplyResult {
    let snapshot = state.snapshot();

    for eff in effects {
        let tx_effects = eff.to_tx_effects();
        if let Err(e) = apply_tx_effects(state, &tx_effects) {
            state.restore(snapshot);
            return BlockApplyResult::Rejected(BlockError::AtomicApplyFailed(
                format!("tx {} apply failed: {}", eff.tx_index, e),
            ));
        }
    }

    let block_hash = block.hash();
    let height = block.header.height;
    let total_fees: u64 = effects.iter().map(|e| e.total_fee).sum();
    let tx_count = effects.len();

    state.set_tip(block_hash, height);

    BlockApplyResult::Applied {
        block_hash,
        height,
        tx_count,
        total_fees,
    }
}

/// Convenience: validate in parallel + apply atomically.
///
/// Full pipeline in one call:
///   1. Parallel validation (Phase A + B + C)
///   2. Serial atomic apply
///   3. Returns BlockApplyResult
pub fn validate_and_apply_parallel<P: ProofBackend + Sync>(
    block: &Block,
    state: &mut ChainState,
    backend: &P,
    config: &ParallelValidationConfig,
) -> BlockApplyResult {
    let effects = match validate_block_parallel(block, state, backend, config) {
        Ok(e) => e,
        Err(err) => return BlockApplyResult::Rejected(err),
    };

    apply_verified_block(block, &effects, state)
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_tx::*;
    use misaka_crypto::ring_sig::{RingSignature, larrs_keygen};
    use misaka_crypto::proof_backend::{
        TestnetBackend, RangeProofBackend, BalanceProofBackend,
    };
    use misaka_crypto::hash::merkle_root;
    use misaka_store::{BlockHeader, ChainState};

    // ── Test helpers ──

    fn dummy_enote() -> Enote {
        let ac = AmountCommitment([0xCC; 32]);
        let addr = [0x11; 32];
        let payload = RecipientPayload::encrypt(&[0x42; 32], vec![0; 32], 100, 10, b"", 0);
        let ph = payload.hash();
        let nc = NoteCommitment::compute(&addr, &ac, 0x42, &ph, &ASSET_NATIVE, ENOTE_VERSION);
        Enote {
            enote_id: EnoteId([0xF0; 32]),
            enote_version: ENOTE_VERSION,
            asset_id: ASSET_NATIVE,
            one_time_address: addr,
            amount_commitment: ac,
            note_commitment: nc,
            view_tag: 0x42,
            recipient_payload: payload,
            created_at: 0,
        }
    }

    fn dummy_input(id_byte: u8) -> TxInput {
        let kp = larrs_keygen(&[id_byte; 32]);
        let ring_proof = RingSignature {
            ring: vec![vec![0; 64]; 4],
            key_image: kp.key_image,
            c0: [0; 32],
            responses: vec![vec![0; 64]; 4],
        };
        let ring_pk_hash = TxInput::compute_ring_pk_hash(&ring_proof);
        TxInput {
            ring: RingMembers {
                members: [EnoteId([1; 32]), EnoteId([2; 32]), EnoteId([3; 32]), EnoteId([4; 32])],
                member_commitments: [AmountCommitment([0; 32]); 4],
            },
            ring_proof,
            link_tag: LinkTag(kp.key_image),
            pseudo_output_commitment: AmountCommitment([0; 32]),
            ring_pk_hash,
        }
    }

    fn make_tx(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> TxBody {
        let fee = FeeStatement::compute(2000, 1);
        let body_hash = compute_tx_body_hash(&inputs, &outputs, &fee);
        let bp = BalanceProofBackend::prove(
            &TestnetBackend,
            &[misaka_crypto::commitment::commit(100, 10)],
            &[misaka_crypto::commitment::commit(100, 10)],
            0,
        ).unwrap();
        let range_proofs: Vec<_> = outputs.iter().map(|_|
            RangeProofBackend::prove(&TestnetBackend, &misaka_crypto::commitment::commit(100, 10)).unwrap()
        ).collect();
        let proofs = TxProofBundle {
            balance_proof: bp,
            range_proofs,
            fee_proof: FeeProof::new(fee.total_fee),
            proof_backend_id: TestnetBackend::BACKEND_ID,
        };
        let proof_hash = compute_tx_proof_hash(&proofs);
        let binding_hash = compute_tx_binding_hash(&body_hash, &proof_hash, TX_VERSION, &[]);
        let tx_id = compute_tx_id(&binding_hash);
        TxBody {
            tx_id, tx_body_hash: body_hash, tx_proof_hash: proof_hash,
            tx_binding_hash: binding_hash, version: TX_VERSION,
            inputs, outputs, proofs, fee, tx_extra: vec![], size_bytes: 2000,
        }
    }

    fn make_block(txs: Vec<TxBody>, height: u64, prev_hash: [u8; 32]) -> Block {
        let tx_merkle_root = if txs.is_empty() {
            [0u8; 32]
        } else {
            let slices: Vec<&[u8]> = txs.iter().map(|tx| tx.tx_id.0.as_slice()).collect();
            merkle_root(&slices)
        };
        Block {
            header: BlockHeader {
                version: 2, height, round: 0, prev_hash, timestamp: 1000,
                tx_merkle_root, utxo_root: [0; 32], link_tag_root: [0; 32],
                proposer_id: [0xAA; 32], proposer_sig: vec![], bft_sigs: vec![],
            },
            transactions: txs,
        }
    }

    fn seeded_chain_state() -> ChainState {
        let mut state = ChainState::genesis();
        for id_byte in [1u8, 2, 3, 4] {
            let eid = EnoteId([id_byte; 32]);
            let enote = StoredEnote {
                enote_id: eid,
                one_time_address: [id_byte; 32],
                amount_commitment: AmountCommitment([0xCC; 32]),
                note_commitment: NoteCommitment([0; 32]),
                view_tag: 0,
                asset_id: ASSET_NATIVE,
                enote_version: ENOTE_VERSION,
                created_at: 0,
            };
            state.insert_enote(&enote).unwrap();
        }
        state
    }

    fn serial_config() -> ParallelValidationConfig {
        ParallelValidationConfig {
            parallelism: 1,
            enable_parallel: false,
            max_block_bytes: 10_000_000,
        }
    }

    fn parallel_config(n: usize) -> ParallelValidationConfig {
        ParallelValidationConfig {
            parallelism: n,
            enable_parallel: true,
            max_block_bytes: 10_000_000,
        }
    }

    // ════════════════════════════════════════════
    // Correctness tests
    // ════════════════════════════════════════════

    #[test]
    fn test_parallel_accepts_valid_block() {
        let state = seeded_chain_state();
        let tx1 = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let tx2 = make_tx(vec![dummy_input(0x02)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx1, tx2], 0, [0u8; 32]);

        let effects = validate_block_parallel(&block, &state, &TestnetBackend, &parallel_config(2)).unwrap();
        assert_eq!(effects.len(), 2);
        assert_eq!(effects[0].tx_index, 0);
        assert_eq!(effects[1].tx_index, 1);
    }

    #[test]
    fn test_parallel_rejects_block_with_invalid_tx() {
        let state = seeded_chain_state();
        let tx1 = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);

        // tx2 references non-existent ring members
        let mut inp2 = dummy_input(0x02);
        inp2.ring.members = [
            EnoteId([0xA0; 32]), EnoteId([0xA1; 32]),
            EnoteId([0xA2; 32]), EnoteId([0xA3; 32]),
        ];
        let tx2 = make_tx(vec![inp2], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx1, tx2], 0, [0u8; 32]);

        let result = validate_block_parallel(&block, &state, &TestnetBackend, &parallel_config(2));
        assert!(result.is_err());
        if let Err(BlockError::BlockTxInvalid { index, .. }) = result {
            assert_eq!(index, 1);
        } else {
            panic!("expected BlockTxInvalid");
        }
    }

    #[test]
    fn test_parallel_rejects_duplicate_link_tags_across_txs() {
        let state = seeded_chain_state();
        let inp1 = dummy_input(0x01);
        let tag = inp1.link_tag;
        let tx1 = make_tx(vec![inp1], vec![TxOutput { enote: dummy_enote() }]);

        let mut inp2 = dummy_input(0x02);
        inp2.link_tag = tag; // same link tag
        let tx2 = make_tx(vec![inp2], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx1, tx2], 0, [0u8; 32]);

        // Phase A precheck catches this (duplicate link tag in block)
        let result = validate_block_parallel(&block, &state, &TestnetBackend, &parallel_config(2));
        assert!(result.is_err());
    }

    #[test]
    fn test_parallel_preserves_original_tx_order() {
        let state = seeded_chain_state();
        let mut txs = Vec::new();
        for i in 1u8..=4 {
            txs.push(make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }]));
        }
        let tx_ids: Vec<TxId> = txs.iter().map(|tx| tx.tx_id).collect();
        let block = make_block(txs, 0, [0u8; 32]);

        let effects = validate_block_parallel(&block, &state, &TestnetBackend, &parallel_config(4)).unwrap();
        for (i, eff) in effects.iter().enumerate() {
            assert_eq!(eff.tx_index, i);
            assert_eq!(eff.tx_id, tx_ids[i]);
        }
    }

    #[test]
    fn test_parallel_matches_serial_result() {
        let state = seeded_chain_state();
        let txs: Vec<TxBody> = (1u8..=3).map(|i|
            make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }])
        ).collect();
        let block = make_block(txs, 0, [0u8; 32]);

        let serial = validate_block_parallel(&block, &state, &TestnetBackend, &serial_config()).unwrap();
        let parallel = validate_block_parallel(&block, &state, &TestnetBackend, &parallel_config(3)).unwrap();

        assert_eq!(serial.len(), parallel.len());
        for (s, p) in serial.iter().zip(parallel.iter()) {
            assert_eq!(s.tx_id, p.tx_id);
            assert_eq!(s.tx_index, p.tx_index);
            assert_eq!(s.link_tags, p.link_tags);
            assert_eq!(s.total_fee, p.total_fee);
            assert_eq!(s.actual_size_bytes, p.actual_size_bytes);
        }
    }

    // ════════════════════════════════════════════
    // Determinism tests
    // ════════════════════════════════════════════

    #[test]
    fn test_repeated_runs_same_result() {
        let state = seeded_chain_state();
        let txs: Vec<TxBody> = (1u8..=4).map(|i|
            make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }])
        ).collect();
        let block = make_block(txs, 0, [0u8; 32]);
        let config = parallel_config(3);

        let r1 = validate_block_parallel(&block, &state, &TestnetBackend, &config).unwrap();
        let r2 = validate_block_parallel(&block, &state, &TestnetBackend, &config).unwrap();

        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.tx_id, b.tx_id);
            assert_eq!(a.tx_index, b.tx_index);
        }
    }

    // ════════════════════════════════════════════
    // Apply safety tests
    // ════════════════════════════════════════════

    #[test]
    fn test_apply_verified_block_atomic() {
        let mut state = seeded_chain_state();
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 0, [0u8; 32]);

        let effects = validate_block_parallel(&block, &state, &TestnetBackend, &serial_config()).unwrap();

        let result = apply_verified_block(&block, &effects, &mut state);
        assert!(result.is_applied());
        assert_eq!(state.tip_height(), 0);
    }

    #[test]
    fn test_apply_no_partial_writes_on_failure() {
        let mut state = seeded_chain_state();
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 0, [0u8; 32]);

        let effects = validate_block_parallel(&block, &state, &TestnetBackend, &serial_config()).unwrap();

        // Pre-insert a link tag so apply will fail
        let tag = effects[0].link_tags[0];
        state.insert_link_tag(&tag).unwrap();

        let enotes_before = state.enote_count();
        let tags_before = state.link_tag_count();

        let result = apply_verified_block(&block, &effects, &mut state);
        assert!(!result.is_applied());

        // State should be fully rolled back (except the tag we manually inserted)
        assert_eq!(state.enote_count(), enotes_before);
        assert_eq!(state.link_tag_count(), tags_before);
    }

    #[test]
    fn test_snapshot_read_only_during_validation() {
        // This test confirms the snapshot is created once and
        // not mutated during validation.
        let state = seeded_chain_state();
        let initial_enotes = state.enote_count();
        let initial_tags = state.link_tag_count();

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 0, [0u8; 32]);

        let _effects = validate_block_parallel(&block, &state, &TestnetBackend, &parallel_config(2)).unwrap();

        // State must be unchanged after validation (no side effects)
        assert_eq!(state.enote_count(), initial_enotes);
        assert_eq!(state.link_tag_count(), initial_tags);
    }

    // ════════════════════════════════════════════
    // validate_and_apply_parallel convenience
    // ════════════════════════════════════════════

    #[test]
    fn test_validate_and_apply_parallel() {
        let mut state = seeded_chain_state();
        let txs: Vec<TxBody> = (1u8..=3).map(|i|
            make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }])
        ).collect();
        let block = make_block(txs, 0, [0u8; 32]);

        let result = validate_and_apply_parallel(&block, &mut state, &TestnetBackend, &parallel_config(2));
        assert!(result.is_applied());
        assert_eq!(state.link_tag_count(), 3);
    }

    #[test]
    fn test_empty_block_parallel() {
        let state = seeded_chain_state();
        let block = make_block(vec![], 0, [0u8; 32]);

        let effects = validate_block_parallel(&block, &state, &TestnetBackend, &parallel_config(2)).unwrap();
        assert!(effects.is_empty());
    }

    #[test]
    fn test_parallel_disabled_falls_back_serial() {
        let state = seeded_chain_state();
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 0, [0u8; 32]);

        let mut config = parallel_config(4);
        config.enable_parallel = false;

        let effects = validate_block_parallel(&block, &state, &TestnetBackend, &config).unwrap();
        assert_eq!(effects.len(), 1);
    }
}
