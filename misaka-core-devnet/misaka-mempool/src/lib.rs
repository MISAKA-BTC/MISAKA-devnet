// ============================================================
// MISAKA Network — Transaction Mempool
// ============================================================
//
// Testnet-hardening mempool with:
//   - Pre-validation before admission (cheap checks first)
//   - Duplicate tx_id rejection
//   - Duplicate tx_binding_hash rejection
//   - Link tag conflict rejection (first-seen wins, no RBF)
//   - Fee-per-byte priority ordering
//   - Congestion-based dynamic minimum fee
//   - Deterministic block candidate selection
//   - Revalidation against store before block inclusion
//
// Admission order (reject before expensive proof verification):
//   1. Binding / structure checks
//   2. Canonical size recomputation
//   3. Proof size checks
//   4. Fee checks (with congestion factor)
//   5. Duplicate link tag inside tx
//   6. Ring member existence from store
//   7. Global link tag existence from store
//   8. Duplicate tx_id check in mempool
//   9. Duplicate binding hash check in mempool
//  10. Link tag conflict check in mempool
//  11. Cryptographic proof verification
//  12. Insert into mempool
//
// ============================================================

use misaka_tx::{
    TxBody, TxId, TxBindingHash, LinkTag, EnoteId,
    FeeStatement, MAX_TX_SIZE,
    verify::compute_actual_size,
};
use std::collections::{HashMap, HashSet, BinaryHeap};
use std::cmp::Ordering;
use std::time::SystemTime;

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("Duplicate tx_id in mempool: {0}")]
    DuplicateTxId(String),
    #[error("Duplicate tx_binding_hash in mempool: {0}")]
    DuplicateBindingHash(String),
    #[error("Duplicate link tag inside transaction: {0}")]
    DuplicateLinkTagInTransaction(String),
    #[error("Link tag conflict with tx already in mempool: tag={tag}, existing_tx={existing_tx}")]
    LinkTagConflictInMempool { tag: String, existing_tx: String },
    #[error("Link tag already in persistent store: {0}")]
    LinkTagAlreadyInStore(String),
    #[error("Ring member not found in store: input {input_index} member {member_hex}")]
    RingMemberNotFound { input_index: usize, member_hex: String },
    #[error("Fee too low: got {got}, minimum {min} (congestion factor {congestion})")]
    FeeTooLow { got: u64, min: u64, congestion: u8 },
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),
    #[error("TX too large for mempool: {size} bytes (max {max})")]
    TxTooLargeForMempool { size: u32, max: u32 },
    #[error("Block assembly conflict: {0}")]
    BlockAssemblyConflict(String),
    #[error("Mempool index inconsistency: {0}")]
    MempoolIndexInconsistency(String),
    #[error("TX structural/binding error: {0}")]
    TxValidation(#[from] misaka_tx::TxError),
    #[error("Store error: {0}")]
    StoreError(String),
}

/// Result of admission attempt.
#[derive(Debug)]
pub enum AdmitResult {
    /// TX accepted into mempool.
    Accepted { tx_id: TxId, fee_per_byte: u64 },
    /// TX rejected with reason.
    Rejected(MempoolError),
}

// ════════════════════════════════════════════
// Store view trait (read-only for mempool)
// ════════════════════════════════════════════

/// Read-only view of persistent store for mempool operations.
///
/// This is deliberately separate from TxStateStore — the mempool
/// never mutates the persistent store.
pub trait MempoolStoreView {
    /// Check if a link tag exists in the committed chain state.
    fn has_link_tag(&self, tag: &LinkTag) -> Result<bool, String>;
    /// Check if a ring member (enote) exists in the committed enote set.
    fn ring_member_exists(&self, member_id: &EnoteId) -> Result<bool, String>;
    /// Check if a tx_id already exists on chain (optional optimization).
    fn tx_exists(&self, tx_id: &TxId) -> Result<bool, String> {
        let _ = tx_id;
        Ok(false)
    }
}

/// Adapter: wraps any `TxStateStore` as a read-only `MempoolStoreView`.
///
/// Usage:
/// ```ignore
/// let view = StoreViewAdapter(&chain_state);
/// mempool.admit_tx(tx, &view, verify_fn);
/// ```
pub struct StoreViewAdapter<'a, S: misaka_tx::TxStateStore>(pub &'a S);

impl<'a, S: misaka_tx::TxStateStore> MempoolStoreView for StoreViewAdapter<'a, S> {
    fn has_link_tag(&self, tag: &LinkTag) -> Result<bool, String> {
        self.0.has_link_tag(tag).map_err(|e| e.to_string())
    }

    fn ring_member_exists(&self, member_id: &EnoteId) -> Result<bool, String> {
        self.0.enote_exists(member_id).map_err(|e| e.to_string())
    }
}

// ════════════════════════════════════════════
// Mempool entry
// ════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub tx: TxBody,
    pub tx_id: TxId,
    pub tx_binding_hash: TxBindingHash,
    pub actual_size_bytes: u32,
    pub proof_bytes: usize,
    pub total_fee: u64,
    pub fee_per_byte: u64,
    pub arrival_seq: u64,
    pub arrival_time: Option<u64>,
}

impl MempoolEntry {
    fn from_tx(tx: TxBody, arrival_seq: u64) -> Self {
        let tx_id = tx.tx_id;
        let tx_binding_hash = tx.tx_binding_hash;
        let actual_size_bytes = compute_actual_size(&tx);
        let proof_bytes = compute_proof_bytes(&tx);
        let total_fee = tx.fee.total_fee;
        // fee_per_byte: integer division, rounding down
        let fee_per_byte = if actual_size_bytes > 0 {
            total_fee / (actual_size_bytes as u64)
        } else {
            0
        };
        let arrival_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());

        Self {
            tx,
            tx_id,
            tx_binding_hash,
            actual_size_bytes,
            proof_bytes,
            total_fee,
            fee_per_byte,
            arrival_seq,
            arrival_time,
        }
    }
}

/// Compute total proof bytes from a tx.
fn compute_proof_bytes(tx: &TxBody) -> usize {
    let mut total = tx.proofs.balance_proof.proof.len();
    for rp in &tx.proofs.range_proofs {
        total += rp.proof.len();
    }
    total
}

// ════════════════════════════════════════════
// Priority key (deterministic ordering)
// ════════════════════════════════════════════

/// Priority key for mempool ordering.
///
/// Ordering rules:
///   1. Higher fee_per_byte first
///   2. Older arrival_seq first (lower = older)
///   3. Smaller proof_bytes first
///   4. Smaller tx_id (lexicographic) first
#[derive(Debug, Clone, Eq, PartialEq)]
struct PriorityKey {
    fee_per_byte: u64,
    arrival_seq: u64,
    proof_bytes: usize,
    tx_id: TxId,
}

impl Ord for PriorityKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // 1. Higher fee_per_byte first
        self.fee_per_byte.cmp(&other.fee_per_byte)
            // 2. Older arrival_seq first (lower is better → reverse)
            .then_with(|| other.arrival_seq.cmp(&self.arrival_seq))
            // 3. Smaller proof_bytes first (lower is better → reverse)
            .then_with(|| other.proof_bytes.cmp(&self.proof_bytes))
            // 4. Smaller tx_id first (lower is better → reverse)
            .then_with(|| other.tx_id.cmp(&self.tx_id))
    }
}

impl PartialOrd for PriorityKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PriorityKey {
    fn from_entry(entry: &MempoolEntry) -> Self {
        Self {
            fee_per_byte: entry.fee_per_byte,
            arrival_seq: entry.arrival_seq,
            proof_bytes: entry.proof_bytes,
            tx_id: entry.tx_id,
        }
    }
}

// ════════════════════════════════════════════
// Congestion-based minimum fee
// ════════════════════════════════════════════

/// Mempool configuration.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions in mempool.
    pub max_tx_count: usize,
    /// Maximum total bytes in mempool.
    pub max_total_bytes: usize,
    /// Maximum size of a single block for assembly (bytes).
    pub max_block_bytes: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_tx_count: 10_000,
            max_total_bytes: 50 * 1024 * 1024, // 50 MB
            max_block_bytes: 2 * 1024 * 1024,   // 2 MB
        }
    }
}

/// Compute congestion factor based on mempool fill level.
///
/// Fill ratio thresholds:
///   <50%  → 1
///   50-69% → 2
///   70-84% → 3
///   85-94% → 4
///   >=95%  → 5
fn congestion_factor(current_bytes: usize, max_bytes: usize) -> u8 {
    if max_bytes == 0 {
        return 5;
    }
    // Use basis points to avoid floating point
    let fill_bps = ((current_bytes as u128) * 10_000 / (max_bytes as u128)) as u64;
    if fill_bps < 5_000 { 1 }
    else if fill_bps < 7_000 { 2 }
    else if fill_bps < 8_500 { 3 }
    else if fill_bps < 9_500 { 4 }
    else { 5 }
}

/// Compute the locally required minimum fee for a given tx size.
fn compute_minimum_fee(actual_size: u32, congestion: u8) -> u64 {
    FeeStatement::compute(actual_size, congestion).total_fee
}

// ════════════════════════════════════════════
// Block build statistics
// ════════════════════════════════════════════

/// Statistics from block candidate building.
///
/// Useful for throughput monitoring and packing efficiency analysis.
#[derive(Debug, Clone, Default)]
pub struct BlockBuildStats {
    /// Number of mempool entries considered.
    pub candidates_considered: usize,
    /// Number of txs included in the block.
    pub included_txs: usize,
    /// Number of txs skipped due to exceeding remaining block space.
    pub skipped_oversize: usize,
    /// Number of txs skipped due to block-local link tag conflict.
    pub skipped_conflict: usize,
    /// Number of txs skipped/removed due to stale store state.
    pub skipped_stale: usize,
    /// Total bytes of included txs.
    pub block_bytes: usize,
    /// Maximum block bytes allowed.
    pub max_block_bytes: usize,
}

impl BlockBuildStats {
    /// Block utilization as a percentage (0.0 - 100.0).
    pub fn utilization_pct(&self) -> f64 {
        if self.max_block_bytes == 0 { return 0.0; }
        (self.block_bytes as f64 / self.max_block_bytes as f64) * 100.0
    }
}

// ════════════════════════════════════════════
// Mempool
// ════════════════════════════════════════════

pub struct Mempool {
    config: MempoolConfig,

    // Primary storage
    by_txid: HashMap<TxId, MempoolEntry>,

    // Secondary indexes
    by_binding_hash: HashMap<TxBindingHash, TxId>,
    by_link_tag: HashMap<LinkTag, TxId>,

    // Priority queue (lazy deletion — entries may reference removed txs)
    priority_heap: BinaryHeap<PriorityKey>,

    // Monotonic sequence counter
    next_seq: u64,

    // Tracking
    total_bytes: usize,

    // Set of tx_ids that have been removed (for lazy heap deletion)
    removed_set: HashSet<TxId>,
}

impl Mempool {
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            by_txid: HashMap::new(),
            by_binding_hash: HashMap::new(),
            by_link_tag: HashMap::new(),
            priority_heap: BinaryHeap::new(),
            next_seq: 0,
            total_bytes: 0,
            removed_set: HashSet::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(MempoolConfig::default())
    }

    // ── Queries ──

    pub fn len(&self) -> usize { self.by_txid.len() }
    pub fn is_empty(&self) -> bool { self.by_txid.is_empty() }
    pub fn total_bytes(&self) -> usize { self.total_bytes }
    pub fn contains_tx(&self, tx_id: &TxId) -> bool { self.by_txid.contains_key(tx_id) }

    pub fn get_entry(&self, tx_id: &TxId) -> Option<&MempoolEntry> {
        self.by_txid.get(tx_id)
    }

    /// Current congestion factor.
    pub fn congestion_factor(&self) -> u8 {
        congestion_factor(self.total_bytes, self.config.max_total_bytes)
    }

    // ── Admission ──

    /// Admit a transaction into the mempool.
    ///
    /// Runs all validation checks in the specified order,
    /// rejecting early before expensive proof verification.
    ///
    /// The `verify_proofs` callback is invoked only after all cheap checks pass.
    /// It should run the full cryptographic proof verification pipeline
    /// (ring signatures, balance proof, range proofs).
    /// Returns Ok(()) if proofs are valid, or Err(message) if invalid.
    pub fn admit_tx<S, V>(
        &mut self,
        tx: TxBody,
        store: &S,
        verify_proofs: V,
    ) -> AdmitResult
    where
        S: MempoolStoreView,
        V: FnOnce(&TxBody) -> Result<(), String>,
    {
        // Step 1: Binding / structure checks
        if !tx.verify_binding() {
            return AdmitResult::Rejected(MempoolError::TxValidation(
                misaka_tx::TxError::BindingMismatch,
            ));
        }
        if let Err(e) = check_structure(&tx) {
            return AdmitResult::Rejected(MempoolError::TxValidation(e));
        }

        // Step 2: Canonical size recomputation
        let actual_size = compute_actual_size(&tx);
        if actual_size > MAX_TX_SIZE {
            return AdmitResult::Rejected(MempoolError::TxTooLargeForMempool {
                size: actual_size,
                max: MAX_TX_SIZE,
            });
        }

        // Step 3: Proof size checks
        if let Err(e) = check_proof_sizes(&tx) {
            return AdmitResult::Rejected(MempoolError::TxValidation(e));
        }

        // Step 4: Fee checks with congestion
        let congestion = self.congestion_factor();
        let min_fee = compute_minimum_fee(actual_size, congestion);
        if tx.fee.total_fee < min_fee {
            return AdmitResult::Rejected(MempoolError::FeeTooLow {
                got: tx.fee.total_fee,
                min: min_fee,
                congestion,
            });
        }
        if !tx.fee.verify() {
            return AdmitResult::Rejected(MempoolError::TxValidation(
                misaka_tx::TxError::InvalidFeeProof,
            ));
        }
        if !tx.proofs.fee_proof.verify() {
            return AdmitResult::Rejected(MempoolError::TxValidation(
                misaka_tx::TxError::InvalidFeeProof,
            ));
        }

        // Step 5: Duplicate link tag inside tx
        {
            let mut seen = HashSet::new();
            for inp in &tx.inputs {
                if !seen.insert(inp.link_tag) {
                    return AdmitResult::Rejected(MempoolError::DuplicateLinkTagInTransaction(
                        hex::encode(inp.link_tag.0),
                    ));
                }
            }
        }

        // Step 6: Ring member existence from store
        for (i, inp) in tx.inputs.iter().enumerate() {
            for member_id in &inp.ring.members {
                match store.ring_member_exists(member_id) {
                    Ok(true) => {}
                    Ok(false) => {
                        return AdmitResult::Rejected(MempoolError::RingMemberNotFound {
                            input_index: i,
                            member_hex: hex::encode(member_id.0),
                        });
                    }
                    Err(e) => {
                        return AdmitResult::Rejected(MempoolError::StoreError(e));
                    }
                }
            }
        }

        // Step 7: Global link tag existence from store
        for inp in &tx.inputs {
            match store.has_link_tag(&inp.link_tag) {
                Ok(false) => {}
                Ok(true) => {
                    return AdmitResult::Rejected(MempoolError::LinkTagAlreadyInStore(
                        hex::encode(inp.link_tag.0),
                    ));
                }
                Err(e) => {
                    return AdmitResult::Rejected(MempoolError::StoreError(e));
                }
            }
        }

        // Step 8: Duplicate tx_id check in mempool
        let tx_id = tx.tx_id;
        if self.by_txid.contains_key(&tx_id) {
            return AdmitResult::Rejected(MempoolError::DuplicateTxId(
                hex::encode(tx_id.0),
            ));
        }

        // Step 9: Duplicate binding hash check in mempool
        let binding_hash = tx.tx_binding_hash;
        if self.by_binding_hash.contains_key(&binding_hash) {
            return AdmitResult::Rejected(MempoolError::DuplicateBindingHash(
                hex::encode(binding_hash.0),
            ));
        }

        // Step 10: Link tag conflict check in mempool
        for inp in &tx.inputs {
            if let Some(existing_id) = self.by_link_tag.get(&inp.link_tag) {
                return AdmitResult::Rejected(MempoolError::LinkTagConflictInMempool {
                    tag: hex::encode(inp.link_tag.0),
                    existing_tx: hex::encode(existing_id.0),
                });
            }
        }

        // Step 11: Cryptographic proof verification (expensive — last)
        if let Err(msg) = verify_proofs(&tx) {
            return AdmitResult::Rejected(MempoolError::ProofVerificationFailed(msg));
        }

        // All checks passed — insert
        let seq = self.next_seq;
        self.next_seq += 1;

        let entry = MempoolEntry::from_tx(tx, seq);
        let fee_per_byte = entry.fee_per_byte;

        // Insert indexes
        self.by_binding_hash.insert(binding_hash, tx_id);
        for inp in &entry.tx.inputs {
            self.by_link_tag.insert(inp.link_tag, tx_id);
        }

        let pkey = PriorityKey::from_entry(&entry);
        self.total_bytes += entry.actual_size_bytes as usize;
        self.by_txid.insert(tx_id, entry);
        self.priority_heap.push(pkey);

        AdmitResult::Accepted { tx_id, fee_per_byte }
    }

    // ── Removal ──

    /// Remove a transaction by tx_id, cleaning all indexes.
    pub fn remove_tx(&mut self, tx_id: &TxId) -> Option<MempoolEntry> {
        let entry = self.by_txid.remove(tx_id)?;

        // Clean binding hash index
        self.by_binding_hash.remove(&entry.tx_binding_hash);

        // Clean link tag index
        for inp in &entry.tx.inputs {
            self.by_link_tag.remove(&inp.link_tag);
        }

        // Track for lazy heap deletion
        self.removed_set.insert(*tx_id);

        self.total_bytes = self.total_bytes.saturating_sub(entry.actual_size_bytes as usize);

        Some(entry)
    }

    /// Handle a committed block: remove included txs and evict
    /// any remaining txs that conflict on link tags.
    pub fn on_block_committed(
        &mut self,
        included_tx_ids: &[TxId],
        confirmed_link_tags: &[LinkTag],
    ) {
        // Remove included transactions
        for tx_id in included_tx_ids {
            self.remove_tx(tx_id);
        }

        // Find and remove any remaining txs that conflict with confirmed link tags
        let mut to_remove = Vec::new();
        for tag in confirmed_link_tags {
            if let Some(conflicting_tx_id) = self.by_link_tag.get(tag) {
                to_remove.push(*conflicting_tx_id);
            }
        }
        for tx_id in to_remove {
            self.remove_tx(&tx_id);
        }

        // Compact the removed_set / heap periodically
        self.maybe_compact_heap();
    }

    /// Remove all transactions that fail revalidation against the store.
    pub fn evict_invalid<S: MempoolStoreView>(&mut self, store: &S) {
        let tx_ids: Vec<TxId> = self.by_txid.keys().copied().collect();
        let mut to_remove = Vec::new();

        for tx_id in &tx_ids {
            if let Some(entry) = self.by_txid.get(tx_id) {
                if !self.revalidate_entry(entry, store) {
                    to_remove.push(*tx_id);
                }
            }
        }

        for tx_id in to_remove {
            self.remove_tx(&tx_id);
        }
    }

    // ── Block candidate selection ──

    /// Build a block candidate by selecting transactions in priority order.
    ///
    /// Revalidates each candidate against the store before inclusion.
    /// Deterministic ordering guaranteed by PriorityKey.
    pub fn build_block_candidate<S: MempoolStoreView>(
        &mut self,
        store: &S,
        max_block_bytes: usize,
    ) -> Result<Vec<TxBody>, MempoolError> {
        // Drain the heap into a sorted vec for deterministic iteration.
        // We rebuild the heap after selection.
        let mut candidates: Vec<PriorityKey> = Vec::with_capacity(self.priority_heap.len());
        while let Some(pkey) = self.priority_heap.pop() {
            // Skip lazily-deleted entries
            if self.removed_set.contains(&pkey.tx_id) {
                continue;
            }
            // Skip entries no longer in mempool
            if !self.by_txid.contains_key(&pkey.tx_id) {
                continue;
            }
            candidates.push(pkey);
        }
        // candidates is now sorted highest-priority first (heap pop order)

        let mut block_txs: Vec<TxBody> = Vec::new();
        let mut block_bytes: usize = 0;
        let mut block_seen_tags: HashSet<LinkTag> = HashSet::new();
        let mut used_keys: Vec<PriorityKey> = Vec::new();
        let mut skipped_keys: Vec<PriorityKey> = Vec::new();
        let mut invalidated_tx_ids: Vec<TxId> = Vec::new();

        for pkey in candidates {
            let entry = match self.by_txid.get(&pkey.tx_id) {
                Some(e) => e,
                None => continue,
            };

            let tx_size = entry.actual_size_bytes as usize;

            // Skip if would overflow block
            if block_bytes + tx_size > max_block_bytes {
                skipped_keys.push(pkey);
                continue;
            }

            // Check link tag conflicts within this candidate block
            let mut tag_conflict = false;
            for inp in &entry.tx.inputs {
                if block_seen_tags.contains(&inp.link_tag) {
                    tag_conflict = true;
                    break;
                }
            }
            if tag_conflict {
                skipped_keys.push(pkey);
                continue;
            }

            // Revalidate against store
            if !self.revalidate_entry(entry, store) {
                invalidated_tx_ids.push(pkey.tx_id);
                continue;
            }

            // Include in block
            for inp in &entry.tx.inputs {
                block_seen_tags.insert(inp.link_tag);
            }
            block_bytes += tx_size;
            block_txs.push(entry.tx.clone());
            used_keys.push(pkey);
        }

        // Rebuild heap with remaining (non-used, non-invalidated) entries
        let used_set: HashSet<TxId> = used_keys.iter().map(|k| k.tx_id).collect();
        for pkey in skipped_keys {
            if !used_set.contains(&pkey.tx_id) {
                self.priority_heap.push(pkey);
            }
        }
        // Re-push used keys too (they're still in mempool until commit)
        for pkey in used_keys {
            self.priority_heap.push(pkey);
        }

        // Remove invalidated entries
        for tx_id in invalidated_tx_ids {
            self.remove_tx(&tx_id);
        }

        // Clear the removed set since we just rebuilt clean
        self.removed_set.clear();

        Ok(block_txs)
    }

    /// Build a block candidate with detailed packing statistics.
    ///
    /// Same logic as build_block_candidate but additionally returns
    /// statistics about the packing process for observability.
    pub fn build_block_candidate_with_stats<S: MempoolStoreView>(
        &mut self,
        store: &S,
        max_block_bytes: usize,
    ) -> Result<(Vec<TxBody>, BlockBuildStats), MempoolError> {
        // Drain the heap
        let mut candidates: Vec<PriorityKey> = Vec::with_capacity(self.priority_heap.len());
        while let Some(pkey) = self.priority_heap.pop() {
            if self.removed_set.contains(&pkey.tx_id) { continue; }
            if !self.by_txid.contains_key(&pkey.tx_id) { continue; }
            candidates.push(pkey);
        }

        let mut block_txs: Vec<TxBody> = Vec::new();
        let mut block_bytes: usize = 0;
        let mut block_seen_tags: HashSet<LinkTag> = HashSet::new();
        let mut used_keys: Vec<PriorityKey> = Vec::new();
        let mut skipped_keys: Vec<PriorityKey> = Vec::new();
        let mut invalidated_tx_ids: Vec<TxId> = Vec::new();

        let mut stats = BlockBuildStats::default();
        stats.candidates_considered = candidates.len();

        for pkey in candidates {
            let entry = match self.by_txid.get(&pkey.tx_id) {
                Some(e) => e,
                None => continue,
            };

            let tx_size = entry.actual_size_bytes as usize;

            if block_bytes + tx_size > max_block_bytes {
                stats.skipped_oversize += 1;
                skipped_keys.push(pkey);
                continue;
            }

            let mut tag_conflict = false;
            for inp in &entry.tx.inputs {
                if block_seen_tags.contains(&inp.link_tag) {
                    tag_conflict = true;
                    break;
                }
            }
            if tag_conflict {
                stats.skipped_conflict += 1;
                skipped_keys.push(pkey);
                continue;
            }

            if !self.revalidate_entry(entry, store) {
                stats.skipped_stale += 1;
                invalidated_tx_ids.push(pkey.tx_id);
                continue;
            }

            for inp in &entry.tx.inputs {
                block_seen_tags.insert(inp.link_tag);
            }
            block_bytes += tx_size;
            block_txs.push(entry.tx.clone());
            used_keys.push(pkey);
        }

        stats.included_txs = block_txs.len();
        stats.block_bytes = block_bytes;
        stats.max_block_bytes = max_block_bytes;

        // Rebuild heap
        let used_set: HashSet<TxId> = used_keys.iter().map(|k| k.tx_id).collect();
        for pkey in skipped_keys {
            if !used_set.contains(&pkey.tx_id) {
                self.priority_heap.push(pkey);
            }
        }
        for pkey in used_keys {
            self.priority_heap.push(pkey);
        }
        for tx_id in invalidated_tx_ids {
            self.remove_tx(&tx_id);
        }
        self.removed_set.clear();

        Ok((block_txs, stats))
    }

    // ── Internal helpers ──

    /// Revalidate a mempool entry against current store state.
    fn revalidate_entry<S: MempoolStoreView>(
        &self,
        entry: &MempoolEntry,
        store: &S,
    ) -> bool {
        // Check link tags still not in store
        for inp in &entry.tx.inputs {
            match store.has_link_tag(&inp.link_tag) {
                Ok(false) => {}
                _ => return false,
            }
        }

        // Check ring members still exist
        for inp in &entry.tx.inputs {
            for member_id in &inp.ring.members {
                match store.ring_member_exists(member_id) {
                    Ok(true) => {}
                    _ => return false,
                }
            }
        }

        true
    }

    /// Compact the heap if the removed set is large.
    fn maybe_compact_heap(&mut self) {
        // Compact if removed_set > 25% of heap size
        if self.removed_set.len() > self.priority_heap.len() / 4 + 10 {
            let old_heap = std::mem::take(&mut self.priority_heap);
            for pkey in old_heap.into_vec() {
                if !self.removed_set.contains(&pkey.tx_id) && self.by_txid.contains_key(&pkey.tx_id) {
                    self.priority_heap.push(pkey);
                }
            }
            self.removed_set.clear();
        }
    }

    /// Verify index consistency (for testing/debugging).
    #[cfg(test)]
    fn verify_consistency(&self) -> Result<(), String> {
        // Every tx in by_txid should have its binding hash indexed
        for (tx_id, entry) in &self.by_txid {
            let bh = &entry.tx_binding_hash;
            match self.by_binding_hash.get(bh) {
                Some(indexed_id) if indexed_id == tx_id => {}
                Some(other) => {
                    return Err(format!(
                        "binding hash {} points to {} but expected {}",
                        hex::encode(bh.0),
                        hex::encode(other.0),
                        hex::encode(tx_id.0),
                    ));
                }
                None => {
                    return Err(format!(
                        "binding hash {} not indexed for tx {}",
                        hex::encode(bh.0),
                        hex::encode(tx_id.0),
                    ));
                }
            }

            // Every link tag should point back to this tx
            for inp in &entry.tx.inputs {
                match self.by_link_tag.get(&inp.link_tag) {
                    Some(indexed_id) if indexed_id == tx_id => {}
                    Some(other) => {
                        return Err(format!(
                            "link tag {} points to {} but expected {}",
                            hex::encode(inp.link_tag.0),
                            hex::encode(other.0),
                            hex::encode(tx_id.0),
                        ));
                    }
                    None => {
                        return Err(format!(
                            "link tag {} not indexed for tx {}",
                            hex::encode(inp.link_tag.0),
                            hex::encode(tx_id.0),
                        ));
                    }
                }
            }
        }

        // Every binding_hash index entry should point to a valid tx
        for (bh, tx_id) in &self.by_binding_hash {
            if !self.by_txid.contains_key(tx_id) {
                return Err(format!(
                    "binding hash {} points to missing tx {}",
                    hex::encode(bh.0),
                    hex::encode(tx_id.0),
                ));
            }
        }

        // Every link_tag index entry should point to a valid tx
        for (tag, tx_id) in &self.by_link_tag {
            if !self.by_txid.contains_key(tx_id) {
                return Err(format!(
                    "link tag {} points to missing tx {}",
                    hex::encode(tag.0),
                    hex::encode(tx_id.0),
                ));
            }
        }

        Ok(())
    }
}

// ════════════════════════════════════════════
// Stateless checks (inlined for admission)
// ════════════════════════════════════════════

fn check_structure(tx: &TxBody) -> Result<(), misaka_tx::TxError> {
    use misaka_tx::{TX_VERSION, MAX_INPUTS, MAX_OUTPUTS};
    if tx.version != TX_VERSION { return Err(misaka_tx::TxError::UnsupportedVersion(tx.version)); }
    if tx.inputs.is_empty() { return Err(misaka_tx::TxError::EmptyInputs); }
    if tx.outputs.is_empty() { return Err(misaka_tx::TxError::EmptyOutputs); }
    if tx.inputs.len() > MAX_INPUTS { return Err(misaka_tx::TxError::TooManyInputs(tx.inputs.len())); }
    if tx.outputs.len() > MAX_OUTPUTS { return Err(misaka_tx::TxError::TooManyOutputs(tx.outputs.len())); }
    if tx.tx_extra.len() > 256 { return Err(misaka_tx::TxError::TxExtraTooLarge(tx.tx_extra.len())); }
    Ok(())
}

fn check_proof_sizes(tx: &TxBody) -> Result<(), misaka_tx::TxError> {
    use misaka_tx::{MAX_BALANCE_PROOF_SIZE, MAX_RANGE_PROOF_SIZE, MAX_TX_PROOF_SIZE};
    let bp_size = tx.proofs.balance_proof.proof.len();
    if bp_size > MAX_BALANCE_PROOF_SIZE {
        return Err(misaka_tx::TxError::BalanceProofTooLarge { size: bp_size });
    }
    let mut total = bp_size;
    for (i, rp) in tx.proofs.range_proofs.iter().enumerate() {
        let s = rp.proof.len();
        if s > MAX_RANGE_PROOF_SIZE {
            return Err(misaka_tx::TxError::RangeProofTooLarge { index: i, size: s });
        }
        total += s;
    }
    if total > MAX_TX_PROOF_SIZE {
        return Err(misaka_tx::TxError::TotalProofBytesTooLarge { size: total });
    }
    Ok(())
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

    // ── Test store ──

    struct TestStore {
        enotes: HashSet<EnoteId>,
        link_tags: HashSet<LinkTag>,
    }

    impl TestStore {
        fn new() -> Self {
            Self { enotes: HashSet::new(), link_tags: HashSet::new() }
        }
        fn with_ring_members(ids: &[[u8; 32]]) -> Self {
            let mut s = Self::new();
            for id in ids { s.enotes.insert(EnoteId(*id)); }
            s
        }
    }

    impl MempoolStoreView for TestStore {
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
        make_tx_with_fee(inputs, outputs, fee)
    }

    fn make_tx_with_fee(inputs: Vec<TxInput>, outputs: Vec<TxOutput>, fee: FeeStatement) -> TxBody {
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

    fn standard_store() -> TestStore {
        TestStore::with_ring_members(&[[1; 32], [2; 32], [3; 32], [4; 32]])
    }

    fn pass_proofs(_tx: &TxBody) -> Result<(), String> { Ok(()) }
    fn fail_proofs(_tx: &TxBody) -> Result<(), String> { Err("proof failed".into()) }

    // ════════════════════════════════════════════
    // Admission tests
    // ════════════════════════════════════════════

    #[test]
    fn test_admit_valid_tx() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let tx_id = tx.tx_id;

        match pool.admit_tx(tx, &store, pass_proofs) {
            AdmitResult::Accepted { tx_id: id, .. } => assert_eq!(id, tx_id),
            AdmitResult::Rejected(e) => panic!("unexpected rejection: {e}"),
        }

        assert!(pool.contains_tx(&tx_id));
        assert_eq!(pool.len(), 1);
        pool.verify_consistency().unwrap();
    }

    #[test]
    fn test_reject_duplicate_tx_id() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);

        // First admission succeeds
        assert!(matches!(pool.admit_tx(tx.clone(), &store, pass_proofs), AdmitResult::Accepted { .. }));

        // Second admission with same tx fails
        match pool.admit_tx(tx, &store, pass_proofs) {
            AdmitResult::Rejected(MempoolError::DuplicateTxId(_)) => {}
            other => panic!("expected DuplicateTxId, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_duplicate_binding_hash() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);

        assert!(matches!(pool.admit_tx(tx.clone(), &store, pass_proofs), AdmitResult::Accepted { .. }));

        // Fabricate a tx with same binding hash but different tx_id
        // (in practice impossible due to hash chain, but test the index)
        let tx2 = tx.clone();
        // We can't easily make a different tx_id with same binding_hash due to
        // the hash chain, so we test via the actual duplicate path
        match pool.admit_tx(tx2, &store, pass_proofs) {
            AdmitResult::Rejected(MempoolError::DuplicateTxId(_)) => {}
            AdmitResult::Rejected(MempoolError::DuplicateBindingHash(_)) => {}
            other => panic!("expected duplicate rejection, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_duplicate_link_tag_in_tx() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        let mut inp1 = dummy_input(0x01);
        let inp2 = dummy_input(0x01);
        inp1.link_tag = inp2.link_tag; // force duplicate

        let tx = make_tx(vec![inp1, inp2], vec![TxOutput { enote: dummy_enote() }]);

        match pool.admit_tx(tx, &store, pass_proofs) {
            AdmitResult::Rejected(MempoolError::DuplicateLinkTagInTransaction(_)) => {}
            other => panic!("expected DuplicateLinkTagInTransaction, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_link_tag_in_store() {
        let mut pool = Mempool::with_defaults();
        let inp = dummy_input(0x01);
        let mut store = standard_store();
        store.link_tags.insert(inp.link_tag);

        let tx = make_tx(vec![inp], vec![TxOutput { enote: dummy_enote() }]);

        match pool.admit_tx(tx, &store, pass_proofs) {
            AdmitResult::Rejected(MempoolError::LinkTagAlreadyInStore(_)) => {}
            other => panic!("expected LinkTagAlreadyInStore, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_link_tag_conflict_in_mempool() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        let inp1 = dummy_input(0x01);
        let link_tag = inp1.link_tag;

        let tx1 = make_tx(vec![inp1], vec![TxOutput { enote: dummy_enote() }]);
        assert!(matches!(pool.admit_tx(tx1, &store, pass_proofs), AdmitResult::Accepted { .. }));

        // Second tx with same link tag (different key material but forced same tag)
        let mut inp2 = dummy_input(0x02);
        inp2.link_tag = link_tag;
        let tx2 = make_tx(vec![inp2], vec![TxOutput { enote: dummy_enote() }]);

        match pool.admit_tx(tx2, &store, pass_proofs) {
            AdmitResult::Rejected(MempoolError::LinkTagConflictInMempool { .. }) => {}
            other => panic!("expected LinkTagConflictInMempool, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_ring_member_not_found() {
        let mut pool = Mempool::with_defaults();
        let store = TestStore::new(); // empty — no enotes

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);

        match pool.admit_tx(tx, &store, pass_proofs) {
            AdmitResult::Rejected(MempoolError::RingMemberNotFound { .. }) => {}
            other => panic!("expected RingMemberNotFound, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_fee_too_low() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        // Create tx with very low fee
        let fee = FeeStatement {
            base_fee: 1,
            size_fee: 0,
            total_fee: 1,
            congestion_factor: 1,
            commitment: AmountCommitment(misaka_crypto::commitment::commit_fee(1).hash),
        };
        let tx = make_tx_with_fee(
            vec![dummy_input(0x01)],
            vec![TxOutput { enote: dummy_enote() }],
            fee,
        );

        match pool.admit_tx(tx, &store, pass_proofs) {
            AdmitResult::Rejected(MempoolError::FeeTooLow { .. }) => {}
            other => panic!("expected FeeTooLow, got {other:?}"),
        }
    }

    #[test]
    fn test_reject_proof_verification_failed() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);

        match pool.admit_tx(tx, &store, fail_proofs) {
            AdmitResult::Rejected(MempoolError::ProofVerificationFailed(_)) => {}
            other => panic!("expected ProofVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_admit_indexes_correctly() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();
        let inp = dummy_input(0x01);
        let link_tag = inp.link_tag;
        let tx = make_tx(vec![inp], vec![TxOutput { enote: dummy_enote() }]);
        let tx_id = tx.tx_id;
        let binding_hash = tx.tx_binding_hash;

        assert!(matches!(pool.admit_tx(tx, &store, pass_proofs), AdmitResult::Accepted { .. }));

        // Check all indexes
        assert!(pool.by_txid.contains_key(&tx_id));
        assert_eq!(pool.by_binding_hash.get(&binding_hash), Some(&tx_id));
        assert_eq!(pool.by_link_tag.get(&link_tag), Some(&tx_id));
        pool.verify_consistency().unwrap();
    }

    // ════════════════════════════════════════════
    // Priority tests
    // ════════════════════════════════════════════

    #[test]
    fn test_higher_fee_per_byte_ranks_first() {
        // Two txs with different fees — higher fee should come first in block
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        let tx_low = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let fee_high = FeeStatement::compute(2000, 5); // much higher congestion factor
        let tx_high = make_tx_with_fee(
            vec![dummy_input(0x02)],
            vec![TxOutput { enote: dummy_enote() }],
            fee_high,
        );

        let low_id = tx_low.tx_id;
        let high_id = tx_high.tx_id;

        // Admit low-fee first
        assert!(matches!(pool.admit_tx(tx_low, &store, pass_proofs), AdmitResult::Accepted { .. }));
        assert!(matches!(pool.admit_tx(tx_high, &store, pass_proofs), AdmitResult::Accepted { .. }));

        let block = pool.build_block_candidate(&store, 10_000_000).unwrap();
        assert_eq!(block.len(), 2);
        assert_eq!(block[0].tx_id, high_id, "higher fee tx should come first");
        assert_eq!(block[1].tx_id, low_id, "lower fee tx should come second");
    }

    #[test]
    fn test_tie_older_arrival_first() {
        // Same fee → older (lower arrival_seq) should come first
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        let tx1 = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let tx2 = make_tx(vec![dummy_input(0x02)], vec![TxOutput { enote: dummy_enote() }]);

        let id1 = tx1.tx_id;
        let id2 = tx2.tx_id;

        // Same fee (both use compute(2000,1))
        assert!(matches!(pool.admit_tx(tx1, &store, pass_proofs), AdmitResult::Accepted { .. }));
        assert!(matches!(pool.admit_tx(tx2, &store, pass_proofs), AdmitResult::Accepted { .. }));

        let block = pool.build_block_candidate(&store, 10_000_000).unwrap();
        assert_eq!(block.len(), 2);
        // Same fee → arrival order (tx1 arrived first)
        assert_eq!(block[0].tx_id, id1, "older tx should come first on fee tie");
        assert_eq!(block[1].tx_id, id2);
    }

    #[test]
    fn test_tie_smaller_proof_bytes_first() {
        // Same fee, same arrival? Hard to test directly since arrival_seq
        // is auto-assigned. Instead verify PriorityKey ordering directly.
        let k1 = PriorityKey {
            fee_per_byte: 100,
            arrival_seq: 5,
            proof_bytes: 1000,
            tx_id: TxId([0x01; 32]),
        };
        let k2 = PriorityKey {
            fee_per_byte: 100,
            arrival_seq: 5,
            proof_bytes: 2000,
            tx_id: TxId([0x01; 32]),
        };
        // k1 has smaller proof_bytes → should rank higher
        assert!(k1 > k2);
    }

    #[test]
    fn test_tie_smaller_txid_first() {
        let k1 = PriorityKey {
            fee_per_byte: 100,
            arrival_seq: 5,
            proof_bytes: 1000,
            tx_id: TxId([0x01; 32]),
        };
        let k2 = PriorityKey {
            fee_per_byte: 100,
            arrival_seq: 5,
            proof_bytes: 1000,
            tx_id: TxId([0xFF; 32]),
        };
        // k1 has smaller tx_id → should rank higher
        assert!(k1 > k2);
    }

    // ════════════════════════════════════════════
    // Block building tests
    // ════════════════════════════════════════════

    #[test]
    fn test_block_excludes_link_tag_conflicts() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        // Two txs sharing a link tag — first-seen wins (tx1)
        let inp1 = dummy_input(0x01);
        let link_tag = inp1.link_tag;
        let tx1 = make_tx(vec![inp1], vec![TxOutput { enote: dummy_enote() }]);

        let mut inp2 = dummy_input(0x02);
        inp2.link_tag = link_tag;
        let tx2 = make_tx(vec![inp2], vec![TxOutput { enote: dummy_enote() }]);

        let id1 = tx1.tx_id;

        // tx1 in pool, tx2 rejected at admission due to conflict
        assert!(matches!(pool.admit_tx(tx1, &store, pass_proofs), AdmitResult::Accepted { .. }));
        match pool.admit_tx(tx2, &store, pass_proofs) {
            AdmitResult::Rejected(MempoolError::LinkTagConflictInMempool { .. }) => {}
            other => panic!("expected LinkTagConflictInMempool, got {other:?}"),
        }

        let block = pool.build_block_candidate(&store, 10_000_000).unwrap();
        assert_eq!(block.len(), 1);
        assert_eq!(block[0].tx_id, id1);
    }

    #[test]
    fn test_block_skips_oversized_tx() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let actual_size = compute_actual_size(&tx) as usize;

        assert!(matches!(pool.admit_tx(tx, &store, pass_proofs), AdmitResult::Accepted { .. }));

        // Block size smaller than tx → should return empty
        let block = pool.build_block_candidate(&store, actual_size - 1).unwrap();
        assert!(block.is_empty());
    }

    #[test]
    fn test_block_revalidates_against_store() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        let inp = dummy_input(0x01);
        let link_tag = inp.link_tag;
        let tx = make_tx(vec![inp], vec![TxOutput { enote: dummy_enote() }]);

        assert!(matches!(pool.admit_tx(tx, &store, pass_proofs), AdmitResult::Accepted { .. }));

        // Now link tag appears in store (simulating a block commit)
        let mut store2 = standard_store();
        store2.link_tags.insert(link_tag);

        let block = pool.build_block_candidate(&store2, 10_000_000).unwrap();
        assert!(block.is_empty(), "tx should be excluded during revalidation");
    }

    #[test]
    fn test_included_txs_removed_after_commit() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        let inp = dummy_input(0x01);
        let tx = make_tx(vec![inp.clone()], vec![TxOutput { enote: dummy_enote() }]);
        let tx_id = tx.tx_id;

        assert!(matches!(pool.admit_tx(tx, &store, pass_proofs), AdmitResult::Accepted { .. }));
        assert!(pool.contains_tx(&tx_id));

        pool.on_block_committed(&[tx_id], &[inp.link_tag]);

        assert!(!pool.contains_tx(&tx_id));
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_conflicting_txs_removed_after_commit() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        // tx1 and tx3 have different link tags, both admitted
        let inp1 = dummy_input(0x01);
        let inp3 = dummy_input(0x03);
        let tag1 = inp1.link_tag;
        let tag3 = inp3.link_tag;

        let tx1 = make_tx(vec![inp1], vec![TxOutput { enote: dummy_enote() }]);
        let tx3 = make_tx(vec![inp3], vec![TxOutput { enote: dummy_enote() }]);
        let id1 = tx1.tx_id;
        let id3 = tx3.tx_id;

        assert!(matches!(pool.admit_tx(tx1, &store, pass_proofs), AdmitResult::Accepted { .. }));
        assert!(matches!(pool.admit_tx(tx3, &store, pass_proofs), AdmitResult::Accepted { .. }));

        // Block confirms tag3 (not our tx3's tx_id, but the tag itself)
        // This should remove tx3 from mempool as a conflict
        pool.on_block_committed(&[], &[tag3]);

        assert!(pool.contains_tx(&id1), "tx1 should remain");
        assert!(!pool.contains_tx(&id3), "tx3 should be evicted");
    }

    // ════════════════════════════════════════════
    // Cleanup tests
    // ════════════════════════════════════════════

    #[test]
    fn test_remove_clears_all_indexes() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        let inp = dummy_input(0x01);
        let link_tag = inp.link_tag;
        let tx = make_tx(vec![inp], vec![TxOutput { enote: dummy_enote() }]);
        let tx_id = tx.tx_id;
        let binding_hash = tx.tx_binding_hash;

        assert!(matches!(pool.admit_tx(tx, &store, pass_proofs), AdmitResult::Accepted { .. }));

        let entry = pool.remove_tx(&tx_id).expect("should be present");
        assert_eq!(entry.tx_id, tx_id);

        assert!(!pool.by_txid.contains_key(&tx_id));
        assert!(!pool.by_binding_hash.contains_key(&binding_hash));
        assert!(!pool.by_link_tag.contains_key(&link_tag));
        assert_eq!(pool.total_bytes, 0);
    }

    #[test]
    fn test_heap_consistency_after_lazy_deletion() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        // Add several txs
        for i in 1u8..=5 {
            let tx = make_tx(vec![dummy_input(i)], vec![TxOutput { enote: dummy_enote() }]);
            assert!(matches!(pool.admit_tx(tx, &store, pass_proofs), AdmitResult::Accepted { .. }));
        }

        // Remove some
        let tx_to_remove = make_tx(vec![dummy_input(0x03)], vec![TxOutput { enote: dummy_enote() }]);
        pool.remove_tx(&tx_to_remove.tx_id);

        // Build block should still work correctly, skipping removed entries
        let block = pool.build_block_candidate(&store, 10_000_000).unwrap();
        assert_eq!(block.len(), 4);

        // All remaining txs should still be in pool
        pool.verify_consistency().unwrap();
    }

    // ════════════════════════════════════════════
    // Congestion factor tests
    // ════════════════════════════════════════════

    #[test]
    fn test_congestion_factor_thresholds() {
        let max = 1_000_000;
        assert_eq!(congestion_factor(0, max), 1);
        assert_eq!(congestion_factor(400_000, max), 1);
        assert_eq!(congestion_factor(500_000, max), 2);
        assert_eq!(congestion_factor(690_000, max), 2);
        assert_eq!(congestion_factor(700_000, max), 3);
        assert_eq!(congestion_factor(840_000, max), 3);
        assert_eq!(congestion_factor(850_000, max), 4);
        assert_eq!(congestion_factor(940_000, max), 4);
        assert_eq!(congestion_factor(950_000, max), 5);
        assert_eq!(congestion_factor(1_000_000, max), 5);
    }

    #[test]
    fn test_congestion_factor_zero_max() {
        assert_eq!(congestion_factor(0, 0), 5);
    }

    // ════════════════════════════════════════════
    // Multi-block workflow test
    // ════════════════════════════════════════════

    #[test]
    fn test_full_block_build_commit_cycle() {
        let mut pool = Mempool::with_defaults();
        let store = standard_store();

        // Admit 3 txs
        let mut tx_ids = Vec::new();
        let mut all_tags = Vec::new();
        for i in 1u8..=3 {
            let inp = dummy_input(i);
            all_tags.push(inp.link_tag);
            let tx = make_tx(vec![inp], vec![TxOutput { enote: dummy_enote() }]);
            tx_ids.push(tx.tx_id);
            assert!(matches!(pool.admit_tx(tx, &store, pass_proofs), AdmitResult::Accepted { .. }));
        }

        assert_eq!(pool.len(), 3);

        // Build block
        let block = pool.build_block_candidate(&store, 10_000_000).unwrap();
        assert_eq!(block.len(), 3);

        // Commit block
        let committed_ids: Vec<TxId> = block.iter().map(|tx| tx.tx_id).collect();
        let committed_tags: Vec<LinkTag> = block.iter()
            .flat_map(|tx| tx.inputs.iter().map(|i| i.link_tag))
            .collect();
        pool.on_block_committed(&committed_ids, &committed_tags);

        assert_eq!(pool.len(), 0);
        pool.verify_consistency().unwrap();
    }
}
