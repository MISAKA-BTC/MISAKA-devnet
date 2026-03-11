// ============================================================
// MISAKA Network — Block Pipeline
// ============================================================
//
// Connects: mempool → block builder → validation → atomic apply → cleanup
//
// Pipeline:
//
//   Proposer side:
//     1. BlockBuilder::build() selects txs from mempool by priority
//     2. Constructs Block with deterministic tx ordering + merkle root
//     3. Returns unsigned block for consensus layer to sign
//
//   Receiver side:
//     1. validate_block() checks header, duplicates, sizes, tx proofs
//     2. apply_block_atomically() applies with full rollback on failure
//     3. on_block_committed() cleans mempool + advances chain head
//
// Determinism:
//   - TX ordering follows mempool priority (fee/byte → arrival → proof size → tx_id)
//   - Merkle root computed from ordered tx_id list
//   - No randomness anywhere in the pipeline
//
// ============================================================

use misaka_crypto::hash::merkle_root;
use misaka_crypto::proof_backend::ProofBackend;
use misaka_tx::{
    TxBody, TxId, LinkTag,
    TxStateStore,
    verify::compute_actual_size,
    verify_with_store, extract_effects, apply_tx_effects,
};
use misaka_store::{
    Block, BlockHeader, ChainState,
};
use misaka_mempool::{Mempool, MempoolStoreView};
use std::collections::HashSet;

pub mod parallel;

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    #[error("Block too large: {size} bytes (max {max})")]
    BlockTooLarge { size: usize, max: usize },
    #[error("Block tx invalid at index {index}: {reason}")]
    BlockTxInvalid { index: usize, reason: String },
    #[error("Duplicate tx_id in block: {0}")]
    DuplicateTxIdInBlock(String),
    #[error("Duplicate link tag in block: {0}")]
    DuplicateLinkTagInBlock(String),
    #[error("Ring member missing for tx {tx_index} input {input_index}: {member_hex}")]
    RingMemberMissing { tx_index: usize, input_index: usize, member_hex: String },
    #[error("Store apply failure: {0}")]
    StoreApplyFailure(String),
    #[error("Atomic apply failed (rolled back): {0}")]
    AtomicApplyFailed(String),
    #[error("Header integrity: {0}")]
    HeaderIntegrity(String),
    #[error("Height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },
    #[error("Prev hash mismatch")]
    PrevHashMismatch,
    #[error("Merkle root mismatch")]
    MerkleRootMismatch,
    #[error("Empty block (no transactions)")]
    EmptyBlock,
    #[error("Mempool error: {0}")]
    MempoolError(String),
}

// ════════════════════════════════════════════
// Block validation result
// ════════════════════════════════════════════

#[derive(Debug)]
pub enum BlockValidationResult {
    Valid,
    Invalid(BlockError),
}

impl BlockValidationResult {
    pub fn is_valid(&self) -> bool { matches!(self, Self::Valid) }
}

// ════════════════════════════════════════════
// Block apply result
// ════════════════════════════════════════════

#[derive(Debug)]
pub enum BlockApplyResult {
    /// Block applied successfully.
    Applied {
        block_hash: [u8; 32],
        height: u64,
        tx_count: usize,
        total_fees: u64,
    },
    /// Block rejected; state has been rolled back.
    Rejected(BlockError),
}

impl BlockApplyResult {
    pub fn is_applied(&self) -> bool { matches!(self, Self::Applied { .. }) }
}

// ════════════════════════════════════════════
// Block builder (proposer side)
// ════════════════════════════════════════════

/// Configuration for block building.
#[derive(Debug, Clone)]
pub struct BlockBuilderConfig {
    pub max_block_bytes: usize,
    pub version: u32,
}

impl Default for BlockBuilderConfig {
    fn default() -> Self {
        Self {
            max_block_bytes: 2 * 1024 * 1024, // 2 MB
            version: 2,
        }
    }
}

/// Build a candidate block from the mempool.
///
/// This is the proposer-side block construction. It:
///   1. Asks mempool for prioritized candidates (deterministic ordering)
///   2. Constructs a Block with proper merkle root
///   3. Returns an unsigned block (signature added by consensus layer)
///
/// The returned block has empty proposer_sig and bft_sigs — the
/// consensus layer is responsible for signing.
///
/// Determinism: tx ordering is fully determined by mempool priority
/// (fee_per_byte → arrival_seq → proof_bytes → tx_id). No randomness.
pub fn build_block<S: MempoolStoreView>(
    mempool: &mut Mempool,
    store: &S,
    config: &BlockBuilderConfig,
    height: u64,
    round: u32,
    prev_hash: [u8; 32],
    timestamp: u64,
    proposer_id: [u8; 32],
) -> Result<Block, BlockError> {
    // Get prioritized tx list from mempool
    let txs = mempool.build_block_candidate(store, config.max_block_bytes)
        .map_err(|e| BlockError::MempoolError(e.to_string()))?;

    // Compute tx merkle root
    let tx_merkle_root = if txs.is_empty() {
        [0u8; 32] // empty block merkle root
    } else {
        let tx_id_slices: Vec<&[u8]> = txs.iter()
            .map(|tx| tx.tx_id.0.as_slice())
            .collect();
        merkle_root(&tx_id_slices)
    };

    // Placeholder roots (would be computed from full state in production)
    // For now: utxo_root and link_tag_root are zeroed — the consensus
    // layer or store can fill these in after block construction.
    let utxo_root = [0u8; 32];
    let link_tag_root = [0u8; 32];

    let header = BlockHeader {
        version: config.version,
        height,
        round,
        prev_hash,
        timestamp,
        tx_merkle_root,
        utxo_root,
        link_tag_root,
        proposer_id,
        proposer_sig: Vec::new(), // consensus layer signs
        bft_sigs: Vec::new(),     // consensus layer collects
    };

    Ok(Block {
        header,
        transactions: txs,
    })
}

// ════════════════════════════════════════════
// Block validation (receiver side)
// ════════════════════════════════════════════

/// Validate a block before applying it.
///
/// Checks:
///   1. Header: height, prev_hash, merkle root consistency
///   2. No duplicate tx_ids in block
///   3. No duplicate link tags across all txs in block
///   4. Block total size within limit
///   5. Each tx: structural validity (binding, size, proof sizes)
///
/// NOTE: This does NOT verify proposer signature or BFT signatures.
/// That is the consensus layer's responsibility (via misaka-verify).
/// This function validates the block's content integrity.
///
/// NOTE: Full proof verification (ring sigs, balance, range) is done
/// during apply_block_atomically, not here. This function only checks
/// structural integrity so we can reject obviously invalid blocks early.
pub fn validate_block(
    block: &Block,
    expected_height: u64,
    expected_prev_hash: &[u8; 32],
    max_block_bytes: usize,
) -> BlockValidationResult {
    let h = &block.header;

    // 1. Height
    if h.height != expected_height {
        return BlockValidationResult::Invalid(BlockError::HeightMismatch {
            expected: expected_height,
            got: h.height,
        });
    }

    // 2. Prev hash (skip for genesis)
    if h.height > 0 && h.prev_hash != *expected_prev_hash {
        return BlockValidationResult::Invalid(BlockError::PrevHashMismatch);
    }

    // 3. Merkle root
    let computed_merkle = if block.transactions.is_empty() {
        [0u8; 32]
    } else {
        let tx_id_slices: Vec<&[u8]> = block.transactions.iter()
            .map(|tx| tx.tx_id.0.as_slice())
            .collect();
        merkle_root(&tx_id_slices)
    };
    if h.tx_merkle_root != computed_merkle {
        return BlockValidationResult::Invalid(BlockError::MerkleRootMismatch);
    }

    // 4. No duplicate tx_ids
    {
        let mut seen_ids = HashSet::with_capacity(block.transactions.len());
        for tx in &block.transactions {
            if !seen_ids.insert(tx.tx_id) {
                return BlockValidationResult::Invalid(BlockError::DuplicateTxIdInBlock(
                    hex::encode(tx.tx_id.0),
                ));
            }
        }
    }

    // 5. No duplicate link tags across all txs
    {
        let mut seen_tags = HashSet::new();
        for tx in &block.transactions {
            for inp in &tx.inputs {
                if !seen_tags.insert(inp.link_tag) {
                    return BlockValidationResult::Invalid(BlockError::DuplicateLinkTagInBlock(
                        hex::encode(inp.link_tag.0),
                    ));
                }
            }
        }
    }

    // 6. Block total size
    let total_size: usize = block.transactions.iter()
        .map(|tx| compute_actual_size(tx) as usize)
        .sum();
    if total_size > max_block_bytes {
        return BlockValidationResult::Invalid(BlockError::BlockTooLarge {
            size: total_size,
            max: max_block_bytes,
        });
    }

    // 7. Each tx: binding integrity check (cheap)
    for (i, tx) in block.transactions.iter().enumerate() {
        if !tx.verify_binding() {
            return BlockValidationResult::Invalid(BlockError::BlockTxInvalid {
                index: i,
                reason: "binding hash mismatch".into(),
            });
        }
    }

    BlockValidationResult::Valid
}

// ════════════════════════════════════════════
// Atomic block application
// ════════════════════════════════════════════

/// Apply a block atomically with full cryptographic verification.
///
/// For each transaction:
///   1. Full verification via verify_with_store (ring sigs, balance/range proofs, etc.)
///   2. Extract effects (new enotes, new link tags)
///   3. Apply effects to store
///
/// Atomicity: if ANY tx fails, the entire block is rolled back.
/// No partial state updates are visible.
///
/// On success, the chain tip is advanced to the new block.
pub fn apply_block_atomically<P: ProofBackend>(
    block: &Block,
    state: &mut ChainState,
    backend: &P,
) -> BlockApplyResult {
    apply_block_with_verifier(block, state, |tx, st| {
        let result = verify_with_store(tx, st, backend);
        if result.valid {
            Ok(())
        } else {
            Err(result.error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown verification error".into()))
        }
    })
}

/// Apply a block atomically with lightweight verification only.
///
/// Checks per-tx:
///   - Binding integrity
///   - Structural validity (inputs, outputs, version, size)
///   - No duplicate link tags within tx
///   - Link tags not already in store
///   - Ring members still exist in store
///
/// Does NOT verify: ring signatures, balance proofs, range proofs.
///
/// Use this when cryptographic proofs were already verified at an
/// earlier stage (e.g., mempool admission) and only state-dependent
/// checks need to be re-run.
///
/// Atomicity: same snapshot/rollback semantics as full verification.
pub fn apply_block_atomically_trusted(
    block: &Block,
    state: &mut ChainState,
) -> BlockApplyResult {
    apply_block_with_verifier(block, state, |tx, st| {
        // Binding integrity
        if !tx.verify_binding() {
            return Err("binding hash mismatch".into());
        }
        // Structural validity
        if tx.inputs.is_empty() { return Err("empty inputs".into()); }
        if tx.outputs.is_empty() { return Err("empty outputs".into()); }

        // Intra-tx duplicate link tags
        let mut seen = HashSet::new();
        for inp in &tx.inputs {
            if !seen.insert(inp.link_tag) {
                return Err(format!("duplicate link tag in tx: {}", hex::encode(inp.link_tag.0)));
            }
        }

        // Link tags not in store
        for inp in &tx.inputs {
            match st.has_link_tag(&inp.link_tag) {
                Ok(true) => return Err(format!("link tag already in store: {}", hex::encode(inp.link_tag.0))),
                Ok(false) => {}
                Err(e) => return Err(format!("store error: {}", e)),
            }
        }

        // Ring members exist
        for (i, inp) in tx.inputs.iter().enumerate() {
            for member_id in &inp.ring.members {
                match st.enote_exists(member_id) {
                    Ok(true) => {}
                    Ok(false) => return Err(format!(
                        "ring member not found: input {} member {}",
                        i, hex::encode(member_id.0)
                    )),
                    Err(e) => return Err(format!("store error: {}", e)),
                }
            }
        }

        Ok(())
    })
}

/// Core atomic apply: snapshot → verify each tx → apply effects → advance tip.
///
/// The `verify_tx` closure receives the transaction and current state,
/// returning Ok(()) if valid or Err(reason) if invalid.
fn apply_block_with_verifier<V>(
    block: &Block,
    state: &mut ChainState,
    verify_tx: V,
) -> BlockApplyResult
where
    V: Fn(&TxBody, &ChainState) -> Result<(), String>,
{
    // Snapshot for rollback
    let snapshot = state.snapshot();

    // Verify and apply each tx sequentially
    for (i, tx) in block.transactions.iter().enumerate() {
        // Verify
        if let Err(reason) = verify_tx(tx, state) {
            state.restore(snapshot);
            return BlockApplyResult::Rejected(BlockError::BlockTxInvalid {
                index: i,
                reason,
            });
        }

        // Extract and apply effects
        let effects = extract_effects(tx);
        if let Err(e) = apply_tx_effects(state, &effects) {
            // Rollback
            state.restore(snapshot);
            return BlockApplyResult::Rejected(BlockError::AtomicApplyFailed(
                format!("tx {} apply failed: {}", i, e),
            ));
        }
    }

    // All txs applied successfully — advance tip
    let block_hash = block.hash();
    let height = block.header.height;
    let total_fees = block.total_fees();
    let tx_count = block.transactions.len();

    state.set_tip(block_hash, height);

    BlockApplyResult::Applied {
        block_hash,
        height,
        tx_count,
        total_fees,
    }
}

// ════════════════════════════════════════════
// Post-commit hooks
// ════════════════════════════════════════════

/// Post-commit cleanup: update mempool after a block has been applied.
///
/// This must be called after apply_block_atomically succeeds.
/// It removes:
///   - All included transactions from the mempool
///   - Any remaining transactions that conflict on link tags
///   - (Via on_block_committed's conflict detection)
///
/// All mempool indexes are kept consistent.
pub fn on_block_committed(
    block: &Block,
    mempool: &mut Mempool,
) {
    let included_tx_ids: Vec<TxId> = block.transactions.iter()
        .map(|tx| tx.tx_id)
        .collect();

    let confirmed_link_tags: Vec<LinkTag> = block.transactions.iter()
        .flat_map(|tx| tx.inputs.iter().map(|inp| inp.link_tag))
        .collect();

    mempool.on_block_committed(&included_tx_ids, &confirmed_link_tags);
}

// ════════════════════════════════════════════
// Consensus integration: full pipeline
// ════════════════════════════════════════════

/// Propose a block (proposer side, full pipeline).
///
/// This is the convenience function for the consensus layer:
///   1. Build candidate block from mempool
///   2. Return unsigned block for signing
///
/// The consensus layer should then:
///   3. Sign the block (Falcon signature)
///   4. Broadcast to validators
///   5. Collect BFT votes
///   6. Call commit_block() after quorum
pub fn propose_block<S: MempoolStoreView>(
    mempool: &mut Mempool,
    store: &S,
    config: &BlockBuilderConfig,
    height: u64,
    round: u32,
    prev_hash: [u8; 32],
    timestamp: u64,
    proposer_id: [u8; 32],
) -> Result<Block, BlockError> {
    build_block(mempool, store, config, height, round, prev_hash, timestamp, proposer_id)
}

/// Commit a block (full pipeline for receiver/validator).
///
/// Pipeline:
///   1. Validate block structure
///   2. Apply atomically (with full tx verification + rollback)
///   3. Clean mempool
///
/// Returns the apply result. If rejected, state is unchanged.
pub fn commit_block<P: ProofBackend>(
    block: &Block,
    state: &mut ChainState,
    backend: &P,
    mempool: &mut Mempool,
    expected_height: u64,
    expected_prev_hash: &[u8; 32],
    max_block_bytes: usize,
) -> BlockApplyResult {
    // Step 1: Validate structure
    let validation = validate_block(block, expected_height, expected_prev_hash, max_block_bytes);
    if let BlockValidationResult::Invalid(err) = validation {
        return BlockApplyResult::Rejected(err);
    }

    // Step 2: Apply atomically
    let result = apply_block_atomically(block, state, backend);

    // Step 3: If applied, clean mempool
    if result.is_applied() {
        on_block_committed(block, mempool);
    }

    result
}

/// Commit a block with lightweight verification (trusted mode).
///
/// Same as commit_block but uses apply_block_atomically_trusted
/// (no cryptographic proof verification). Use when proofs were
/// already verified at mempool admission time.
pub fn commit_block_trusted(
    block: &Block,
    state: &mut ChainState,
    mempool: &mut Mempool,
    expected_height: u64,
    expected_prev_hash: &[u8; 32],
    max_block_bytes: usize,
) -> BlockApplyResult {
    let validation = validate_block(block, expected_height, expected_prev_hash, max_block_bytes);
    if let BlockValidationResult::Invalid(err) = validation {
        return BlockApplyResult::Rejected(err);
    }

    let result = apply_block_atomically_trusted(block, state);

    if result.is_applied() {
        on_block_committed(block, mempool);
    }

    result
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
    use misaka_store::ChainState;
    use misaka_mempool::{Mempool, AdmitResult};
    

    // ── Test store view (for mempool operations) ──

    struct TestStoreView {
        enotes: HashSet<EnoteId>,
        link_tags: HashSet<LinkTag>,
    }

    impl TestStoreView {
        fn new() -> Self {
            Self { enotes: HashSet::new(), link_tags: HashSet::new() }
        }
        fn with_ring_members(ids: &[[u8; 32]]) -> Self {
            let mut s = Self::new();
            for id in ids { s.enotes.insert(EnoteId(*id)); }
            s
        }
    }

    impl MempoolStoreView for TestStoreView {
        fn has_link_tag(&self, tag: &LinkTag) -> Result<bool, String> {
            Ok(self.link_tags.contains(tag))
        }
        fn ring_member_exists(&self, member_id: &EnoteId) -> Result<bool, String> {
            Ok(self.enotes.contains(member_id))
        }
    }

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

    fn standard_store_view() -> TestStoreView {
        TestStoreView::with_ring_members(&[[1; 32], [2; 32], [3; 32], [4; 32]])
    }

    fn pass_proofs(_tx: &TxBody) -> Result<(), String> { Ok(()) }

    /// Create a ChainState pre-seeded with ring member enotes.
    fn seeded_chain_state() -> ChainState {
        let mut state = ChainState::genesis();
        // Insert ring member enotes that our test txs reference
        for id_byte in [1u8, 2, 3, 4] {
            let eid = EnoteId([id_byte; 32]);
            let enote = misaka_tx::StoredEnote {
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

    /// Build a valid block from a list of transactions.
    fn make_block(txs: Vec<TxBody>, height: u64, prev_hash: [u8; 32]) -> Block {
        let tx_merkle_root = if txs.is_empty() {
            [0u8; 32]
        } else {
            let slices: Vec<&[u8]> = txs.iter().map(|tx| tx.tx_id.0.as_slice()).collect();
            merkle_root(&slices)
        };

        Block {
            header: BlockHeader {
                version: 2,
                height,
                round: 0,
                prev_hash,
                timestamp: 1000,
                tx_merkle_root,
                utxo_root: [0u8; 32],
                link_tag_root: [0u8; 32],
                proposer_id: [0xAA; 32],
                proposer_sig: vec![],
                bft_sigs: vec![],
            },
            transactions: txs,
        }
    }

    // ════════════════════════════════════════════
    // Block builder tests
    // ════════════════════════════════════════════

    #[test]
    fn test_build_block_from_mempool() {
        let mut mempool = Mempool::with_defaults();
        let store_view = standard_store_view();

        // Admit 3 txs
        for i in 1u8..=3 {
            let tx = make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }]);
            assert!(matches!(
                mempool.admit_tx(tx, &store_view, pass_proofs),
                AdmitResult::Accepted { .. }
            ));
        }

        let config = BlockBuilderConfig::default();
        let block = build_block(
            &mut mempool, &store_view, &config,
            1, 0, [0u8; 32], 1000, [0xAA; 32],
        ).unwrap();

        assert_eq!(block.transactions.len(), 3);
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.proposer_id, [0xAA; 32]);

        // Verify merkle root matches
        let computed = block.compute_tx_merkle();
        assert_eq!(block.header.tx_merkle_root, computed);
    }

    #[test]
    fn test_build_block_respects_size_limit() {
        let mut mempool = Mempool::with_defaults();
        let store_view = standard_store_view();

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let tx_size = compute_actual_size(&tx) as usize;
        assert!(matches!(
            mempool.admit_tx(tx, &store_view, pass_proofs),
            AdmitResult::Accepted { .. }
        ));

        // Build with max_block_bytes smaller than any tx
        let config = BlockBuilderConfig {
            max_block_bytes: tx_size - 1,
            ..Default::default()
        };
        let block = build_block(
            &mut mempool, &store_view, &config,
            1, 0, [0u8; 32], 1000, [0xAA; 32],
        ).unwrap();

        assert!(block.transactions.is_empty());
    }

    #[test]
    fn test_build_block_deterministic_ordering() {
        // Build twice with same mempool state → same tx order
        let store_view = standard_store_view();
        let config = BlockBuilderConfig::default();

        let mut mempool1 = Mempool::with_defaults();
        let mut mempool2 = Mempool::with_defaults();

        for i in 1u8..=5 {
            let tx = make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }]);
            assert!(matches!(
                mempool1.admit_tx(tx.clone(), &store_view, pass_proofs),
                AdmitResult::Accepted { .. }
            ));
            assert!(matches!(
                mempool2.admit_tx(tx, &store_view, pass_proofs),
                AdmitResult::Accepted { .. }
            ));
        }

        let block1 = build_block(&mut mempool1, &store_view, &config, 1, 0, [0; 32], 1000, [0xAA; 32]).unwrap();
        let block2 = build_block(&mut mempool2, &store_view, &config, 1, 0, [0; 32], 1000, [0xAA; 32]).unwrap();

        assert_eq!(block1.transactions.len(), block2.transactions.len());
        for (a, b) in block1.transactions.iter().zip(block2.transactions.iter()) {
            assert_eq!(a.tx_id, b.tx_id, "tx ordering must be deterministic");
        }
        assert_eq!(block1.header.tx_merkle_root, block2.header.tx_merkle_root);
    }

    #[test]
    fn test_build_block_skips_link_tag_conflict() {
        // The mempool already handles link tag conflicts at admission time
        // (first-seen wins, rejects later conflicts). This test confirms
        // that the builder produces a conflict-free block.
        let mut mempool = Mempool::with_defaults();
        let store_view = standard_store_view();

        let inp1 = dummy_input(0x01);
        let tag1 = inp1.link_tag;
        let tx1 = make_tx(vec![inp1], vec![TxOutput { enote: dummy_enote() }]);

        // Try to add a conflicting tx (will be rejected at admission)
        let mut inp2 = dummy_input(0x02);
        inp2.link_tag = tag1; // force conflict
        let tx2 = make_tx(vec![inp2], vec![TxOutput { enote: dummy_enote() }]);

        assert!(matches!(
            mempool.admit_tx(tx1, &store_view, pass_proofs),
            AdmitResult::Accepted { .. }
        ));
        // This should be rejected
        assert!(matches!(
            mempool.admit_tx(tx2, &store_view, pass_proofs),
            AdmitResult::Rejected(_)
        ));

        let config = BlockBuilderConfig::default();
        let block = build_block(&mut mempool, &store_view, &config, 1, 0, [0; 32], 1000, [0xAA; 32]).unwrap();
        assert_eq!(block.transactions.len(), 1);
    }

    // ════════════════════════════════════════════
    // Block validation tests
    // ════════════════════════════════════════════

    #[test]
    fn test_validate_valid_block() {
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 1, [0u8; 32]);

        let result = validate_block(&block, 1, &[0u8; 32], 10_000_000);
        assert!(result.is_valid());
    }

    #[test]
    fn test_validate_height_mismatch() {
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 5, [0u8; 32]);

        let result = validate_block(&block, 1, &[0u8; 32], 10_000_000);
        assert!(!result.is_valid());
        assert!(matches!(result, BlockValidationResult::Invalid(BlockError::HeightMismatch { .. })));
    }

    #[test]
    fn test_validate_prev_hash_mismatch() {
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 2, [0xAA; 32]);

        let result = validate_block(&block, 2, &[0xBB; 32], 10_000_000);
        assert!(!result.is_valid());
        assert!(matches!(result, BlockValidationResult::Invalid(BlockError::PrevHashMismatch)));
    }

    #[test]
    fn test_validate_merkle_root_mismatch() {
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let mut block = make_block(vec![tx], 1, [0u8; 32]);
        block.header.tx_merkle_root = [0xFF; 32]; // tamper

        let result = validate_block(&block, 1, &[0u8; 32], 10_000_000);
        assert!(!result.is_valid());
        assert!(matches!(result, BlockValidationResult::Invalid(BlockError::MerkleRootMismatch)));
    }

    #[test]
    fn test_validate_duplicate_tx_id() {
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        // Same tx twice
        let block = make_block(vec![tx.clone(), tx], 1, [0u8; 32]);

        let result = validate_block(&block, 1, &[0u8; 32], 10_000_000);
        assert!(!result.is_valid());
        assert!(matches!(result, BlockValidationResult::Invalid(BlockError::DuplicateTxIdInBlock(_))));
    }

    #[test]
    fn test_validate_duplicate_link_tag_across_txs() {
        let inp1 = dummy_input(0x01);
        let tag = inp1.link_tag;
        let tx1 = make_tx(vec![inp1], vec![TxOutput { enote: dummy_enote() }]);

        let mut inp2 = dummy_input(0x02);
        inp2.link_tag = tag; // same link tag
        let tx2 = make_tx(vec![inp2], vec![TxOutput { enote: dummy_enote() }]);

        let block = make_block(vec![tx1, tx2], 1, [0u8; 32]);

        let result = validate_block(&block, 1, &[0u8; 32], 10_000_000);
        assert!(!result.is_valid());
        assert!(matches!(result, BlockValidationResult::Invalid(BlockError::DuplicateLinkTagInBlock(_))));
    }

    #[test]
    fn test_validate_block_too_large() {
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 1, [0u8; 32]);

        let result = validate_block(&block, 1, &[0u8; 32], 1); // 1 byte limit
        assert!(!result.is_valid());
        assert!(matches!(result, BlockValidationResult::Invalid(BlockError::BlockTooLarge { .. })));
    }

    // ════════════════════════════════════════════
    // Atomic apply tests
    // ════════════════════════════════════════════

    #[test]
    fn test_apply_valid_block() {
        let mut state = seeded_chain_state();
        let inp = dummy_input(0x01);
        let tag = inp.link_tag;
        let tx = make_tx(vec![inp], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 0, [0u8; 32]);

        let result = apply_block_atomically_trusted(&block, &mut state);
        assert!(result.is_applied());

        if let BlockApplyResult::Applied { height, tx_count, .. } = result {
            assert_eq!(height, 0);
            assert_eq!(tx_count, 1);
        }

        // Link tag should now be in state
        assert!(state.has_link_tag(&tag).unwrap());
        // Output enote should be persisted
        let out_eid = EnoteId([0xF0; 32]); // from dummy_enote
        assert!(state.enote_exists(&out_eid).unwrap());
    }

    #[test]
    fn test_apply_rollback_on_failing_tx() {
        let mut state = seeded_chain_state();

        let inp1 = dummy_input(0x01);
        let tag1 = inp1.link_tag;
        let tx1 = make_tx(vec![inp1], vec![TxOutput { enote: dummy_enote() }]);

        // tx2 has a link tag that already exists (we'll pre-insert it)
        let inp2 = dummy_input(0x02);
        let tag2 = inp2.link_tag;
        // Pre-insert tag2 to make tx2 fail during apply
        state.insert_link_tag(&tag2).unwrap();

        let tx2 = make_tx(vec![inp2], vec![TxOutput { enote: dummy_enote() }]);

        let block = make_block(vec![tx1, tx2], 0, [0u8; 32]);

        let enote_count_before = state.enote_count();
        let link_tag_count_before = state.link_tag_count();

        let result = apply_block_atomically_trusted(&block, &mut state);
        assert!(!result.is_applied());

        // State must be fully rolled back
        assert_eq!(state.enote_count(), enote_count_before);
        assert_eq!(state.link_tag_count(), link_tag_count_before);
        // tag1 should NOT be in state (rolled back)
        assert!(!state.has_link_tag(&tag1).unwrap());
    }

    #[test]
    fn test_apply_no_partial_writes() {
        let mut state = seeded_chain_state();

        // First tx valid, second tx has ring members that don't exist
        let inp1 = dummy_input(0x01);
        let tx1 = make_tx(vec![inp1], vec![TxOutput { enote: dummy_enote() }]);

        let mut inp2 = dummy_input(0x02);
        // Set ring members to non-existent enotes
        inp2.ring.members = [
            EnoteId([0xA0; 32]), EnoteId([0xA1; 32]),
            EnoteId([0xA2; 32]), EnoteId([0xA3; 32]),
        ];
        let tx2 = make_tx(vec![inp2], vec![TxOutput { enote: dummy_enote() }]);

        let block = make_block(vec![tx1, tx2], 0, [0u8; 32]);

        let snap_enotes = state.enote_count();
        let snap_tags = state.link_tag_count();
        let snap_hash = *state.tip_hash();
        let snap_height = state.tip_height();

        let result = apply_block_atomically_trusted(&block, &mut state);
        assert!(!result.is_applied());

        // Full rollback
        assert_eq!(state.enote_count(), snap_enotes);
        assert_eq!(state.link_tag_count(), snap_tags);
        assert_eq!(*state.tip_hash(), snap_hash);
        assert_eq!(state.tip_height(), snap_height);
    }

    // ════════════════════════════════════════════
    // Cleanup tests
    // ════════════════════════════════════════════

    #[test]
    fn test_mempool_removes_included_tx() {
        let mut mempool = Mempool::with_defaults();
        let store_view = standard_store_view();

        let inp = dummy_input(0x01);
        let tx = make_tx(vec![inp.clone()], vec![TxOutput { enote: dummy_enote() }]);
        let tx_id = tx.tx_id;

        assert!(matches!(
            mempool.admit_tx(tx.clone(), &store_view, pass_proofs),
            AdmitResult::Accepted { .. }
        ));
        assert!(mempool.contains_tx(&tx_id));

        let block = make_block(vec![tx], 1, [0u8; 32]);
        on_block_committed(&block, &mut mempool);

        assert!(!mempool.contains_tx(&tx_id));
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_mempool_removes_conflicting_tx() {
        let mut mempool = Mempool::with_defaults();
        let store_view = standard_store_view();

        // tx_a and tx_b have different link tags, both admitted
        let inp_a = dummy_input(0x01);
        let inp_b = dummy_input(0x02);
        let tag_b = inp_b.link_tag;
        let tx_a = make_tx(vec![inp_a], vec![TxOutput { enote: dummy_enote() }]);
        let tx_b = make_tx(vec![inp_b], vec![TxOutput { enote: dummy_enote() }]);
        let id_a = tx_a.tx_id;
        let id_b = tx_b.tx_id;

        assert!(matches!(mempool.admit_tx(tx_a, &store_view, pass_proofs), AdmitResult::Accepted { .. }));
        assert!(matches!(mempool.admit_tx(tx_b, &store_view, pass_proofs), AdmitResult::Accepted { .. }));

        // Simulate: a block arrives containing a DIFFERENT tx that confirms tag_b
        // (the block doesn't contain tx_b itself, but uses the same link tag)
        let mut foreign_inp = dummy_input(0x99);
        foreign_inp.link_tag = tag_b;
        let foreign_tx = make_tx(vec![foreign_inp], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![foreign_tx], 1, [0u8; 32]);

        on_block_committed(&block, &mut mempool);

        // tx_a should remain (unrelated)
        assert!(mempool.contains_tx(&id_a));
        // tx_b should be evicted (link tag conflict)
        assert!(!mempool.contains_tx(&id_b));
    }

    #[test]
    fn test_mempool_indexes_consistent_after_cleanup() {
        let mut mempool = Mempool::with_defaults();
        let store_view = standard_store_view();

        for i in 1u8..=5 {
            let tx = make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }]);
            assert!(matches!(
                mempool.admit_tx(tx, &store_view, pass_proofs),
                AdmitResult::Accepted { .. }
            ));
        }

        // Build and commit a block with some txs
        let config = BlockBuilderConfig { max_block_bytes: 5000, ..Default::default() };
        let block = build_block(
            &mut mempool, &store_view, &config,
            1, 0, [0; 32], 1000, [0xAA; 32],
        ).unwrap();

        on_block_committed(&block, &mut mempool);

        // Remaining mempool should be consistent
        // (verify_consistency is pub(crate) in mempool, so we check via public API)
        // Some txs were included, some may remain
        assert!(mempool.len() <= 5);

        // Re-admitting should not panic (consistency check)
        for i in 1u8..=5 {
            let tx = make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }]);
            let _result = mempool.admit_tx(tx, &store_view, pass_proofs);
            // Either already in pool (DuplicateTxId / LinkTagConflict) or accepted
            // The point is: no panic, no inconsistency
        }
    }

    // ════════════════════════════════════════════
    // Full integration test
    // ════════════════════════════════════════════

    #[test]
    fn test_full_pipeline_mempool_to_cleanup() {
        // This is the end-to-end integration test:
        //   mempool → build block → validate → atomic apply → cleanup

        let mut state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();
        let store_view = standard_store_view();
        let config = BlockBuilderConfig::default();

        // 1. Admit transactions into mempool
        let mut admitted_ids = Vec::new();
        for i in 1u8..=4 {
            let tx = make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }]);
            admitted_ids.push(tx.tx_id);
            assert!(matches!(
                mempool.admit_tx(tx, &store_view, pass_proofs),
                AdmitResult::Accepted { .. }
            ));
        }
        assert_eq!(mempool.len(), 4);

        // 2. Build block (proposer side)
        let block = build_block(
            &mut mempool, &store_view, &config,
            0, 0, [0u8; 32], 1000, [0xAA; 32],
        ).unwrap();
        assert_eq!(block.transactions.len(), 4);

        // 3. Validate block (receiver side)
        let validation = validate_block(&block, 0, &[0u8; 32], config.max_block_bytes);
        assert!(validation.is_valid());

        // 4. Apply block atomically
        let enotes_before = state.enote_count();
        let tags_before = state.link_tag_count();

        let result = apply_block_atomically_trusted(&block, &mut state);
        assert!(result.is_applied());

        if let BlockApplyResult::Applied { height, tx_count, total_fees, .. } = &result {
            assert_eq!(*height, 0);
            assert_eq!(*tx_count, 4);
            assert!(total_fees > &0);
        }

        // State should have advanced
        assert!(state.enote_count() > enotes_before);
        assert_eq!(state.link_tag_count(), tags_before + 4);

        // All link tags from included txs should be in state
        for tx in &block.transactions {
            for inp in &tx.inputs {
                assert!(state.has_link_tag(&inp.link_tag).unwrap());
            }
        }

        // 5. Mempool cleanup
        on_block_committed(&block, &mut mempool);
        assert_eq!(mempool.len(), 0);

        // All admitted tx_ids should be gone from mempool
        for id in &admitted_ids {
            assert!(!mempool.contains_tx(id));
        }
    }

    #[test]
    fn test_commit_block_full_pipeline() {
        // Test the convenience commit_block() function
        let mut state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();
        let store_view = standard_store_view();

        for i in 1u8..=3 {
            let tx = make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }]);
            assert!(matches!(
                mempool.admit_tx(tx, &store_view, pass_proofs),
                AdmitResult::Accepted { .. }
            ));
        }

        let config = BlockBuilderConfig::default();
        let block = build_block(
            &mut mempool, &store_view, &config,
            0, 0, [0u8; 32], 1000, [0xAA; 32],
        ).unwrap();

        let result = commit_block_trusted(
            &block,
            &mut state,
            &mut mempool,
            0,
            &[0u8; 32],
            config.max_block_bytes,
        );

        assert!(result.is_applied());
        assert_eq!(mempool.len(), 0);
        assert_eq!(state.link_tag_count(), 3 + 0); // 3 new tags, 0 pre-existing
        // (ring member enotes don't have link tags)
    }

    #[test]
    fn test_commit_block_rejected_validation() {
        // Block with wrong height → rejected at validation, no state change
        let mut state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 99, [0u8; 32]); // wrong height

        let snap_height = state.tip_height();
        let snap_hash = *state.tip_hash();

        let result = commit_block_trusted(
            &block, &mut state, &mut mempool,
            0, &[0u8; 32], 10_000_000,
        );

        assert!(!result.is_applied());
        assert_eq!(state.tip_height(), snap_height);
        assert_eq!(*state.tip_hash(), snap_hash);
    }

    #[test]
    fn test_sequential_blocks() {
        // Apply two blocks in sequence
        let mut state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();
        let store_view = standard_store_view();
        let config = BlockBuilderConfig::default();

        // Block 0: txs 1,2
        for i in 1u8..=2 {
            let tx = make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }]);
            assert!(matches!(
                mempool.admit_tx(tx, &store_view, pass_proofs),
                AdmitResult::Accepted { .. }
            ));
        }
        let block0 = build_block(
            &mut mempool, &store_view, &config,
            0, 0, [0u8; 32], 1000, [0xAA; 32],
        ).unwrap();
        assert_eq!(block0.transactions.len(), 2);

        let result0 = commit_block_trusted(
            &block0, &mut state, &mut mempool,
            0, &[0u8; 32], config.max_block_bytes,
        );
        assert!(result0.is_applied());
        let block0_hash = block0.hash();

        // Block 1: txs 3,4
        for i in 3u8..=4 {
            let tx = make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }]);
            assert!(matches!(
                mempool.admit_tx(tx, &store_view, pass_proofs),
                AdmitResult::Accepted { .. }
            ));
        }
        let block1 = build_block(
            &mut mempool, &store_view, &config,
            1, 0, block0_hash, 2000, [0xAA; 32],
        ).unwrap();
        assert_eq!(block1.transactions.len(), 2);

        let result1 = commit_block_trusted(
            &block1, &mut state, &mut mempool,
            1, &block0_hash, config.max_block_bytes,
        );
        assert!(result1.is_applied());

        assert_eq!(state.tip_height(), 1);
        assert_eq!(state.link_tag_count(), 4);
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_empty_block() {
        let mut state = seeded_chain_state();
        let block = make_block(vec![], 0, [0u8; 32]);

        let validation = validate_block(&block, 0, &[0u8; 32], 10_000_000);
        assert!(validation.is_valid());

        let result = apply_block_atomically_trusted(&block, &mut state);
        assert!(result.is_applied());

        if let BlockApplyResult::Applied { tx_count, total_fees, .. } = result {
            assert_eq!(tx_count, 0);
            assert_eq!(total_fees, 0);
        }
    }
}
