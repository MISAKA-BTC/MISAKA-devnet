// ============================================================
// MISAKA Network — Block / State Storage (Phase 2)
// ============================================================
//
// ChainState implements TxStateStore from misaka-tx.
// All TX verification and state application flows through the trait.
//
// ============================================================

use misaka_crypto::hash::{Domain, domain_hash_multi, merkle_root};
use misaka_tx::{
    TxBody, EnoteId, LinkTag,
    TxStateStore, StoredEnote,
    verify_with_store, extract_effects, apply_tx_effects,
};
use misaka_crypto::proof_backend::ProofBackend;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, BTreeMap};
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },
    #[error("Prev hash mismatch")]
    PrevHashMismatch,
    #[error("Operation not supported for {0:?} node")]
    NotSupported(NodeRole),
    #[error("TX verification failed: {0}")]
    TxVerifyFailed(String),
    #[error("TX apply failed: {0}")]
    TxApplyFailed(String),
}

// ── Node roles ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole { Light, Validator, Archive }

#[derive(Debug, Clone)]
pub struct PrunePolicy {
    pub role: NodeRole,
    pub retention_blocks: u64,
}

impl PrunePolicy {
    pub fn for_role(role: NodeRole) -> Self {
        match role {
            NodeRole::Light     => Self { role, retention_blocks: 0 },
            NodeRole::Validator => Self { role, retention_blocks: 1000 },
            NodeRole::Archive   => Self { role, retention_blocks: u64::MAX },
        }
    }
    fn should_store_body(&self, h: u64, tip: u64) -> bool {
        match self.role {
            NodeRole::Light => false,
            NodeRole::Archive => true,
            NodeRole::Validator => tip.saturating_sub(h) < self.retention_blocks,
        }
    }
    fn keeps_full_state(&self) -> bool {
        matches!(self.role, NodeRole::Validator | NodeRole::Archive)
    }
}

// ── Block types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub round: u32,
    pub prev_hash: [u8; 32],
    pub timestamp: u64,
    pub tx_merkle_root: [u8; 32],
    pub utxo_root: [u8; 32],
    pub link_tag_root: [u8; 32],
    pub proposer_id: [u8; 32],
    pub proposer_sig: Vec<u8>,
    pub bft_sigs: Vec<BftSig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BftSig {
    pub vote_type: u8,
    pub height: u64,
    pub round: u32,
    pub block_hash: [u8; 32],
    pub validator_id: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<TxBody>,
}

impl Block {
    pub fn hash(&self) -> [u8; 32] {
        domain_hash_multi(
            Domain::Block,
            &[
                &self.header.version.to_le_bytes(),
                &self.header.height.to_le_bytes(),
                &self.header.round.to_le_bytes(),
                &self.header.prev_hash,
                &self.header.timestamp.to_le_bytes(),
                &self.header.tx_merkle_root,
                &self.header.utxo_root,
                &self.header.link_tag_root,
                &self.header.proposer_id,
            ],
            32,
        ).try_into().unwrap()
    }

    pub fn compute_tx_merkle(&self) -> [u8; 32] {
        let hashes: Vec<&[u8]> = self.transactions.iter()
            .map(|tx| tx.tx_id.0.as_slice()).collect();
        merkle_root(&hashes)
    }

    pub fn total_fees(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.fee.total_fee).sum()
    }
}

// ════════════════════════════════════════════
// ChainState (implements TxStateStore)
// ════════════════════════════════════════════

/// Error type for ChainState store operations.
#[derive(Debug)]
pub struct ChainStateError(pub String);

impl fmt::Display for ChainStateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ChainStateError: {}", self.0)
    }
}

/// Privacy-aware chain state.
///
/// Enotes grow monotonically (ring sig hides which was spent).
/// Link tag set is the sole double-spend prevention mechanism.
pub struct ChainState {
    enotes: HashMap<EnoteId, StoredEnote>,
    link_tags: HashSet<LinkTag>,
    tip_hash: [u8; 32],
    tip_height: u64,
}

/// Snapshot of ChainState for atomic rollback.
///
/// Also implements TxStateStore (read-only) for parallel verification:
/// workers can read link tags and enotes without mutating state.
/// Mutable operations (insert_link_tag, insert_enote) panic — they
/// must never be called on a snapshot.
pub struct ChainStateSnapshot {
    enotes: HashMap<EnoteId, StoredEnote>,
    link_tags: HashSet<LinkTag>,
    tip_hash: [u8; 32],
    tip_height: u64,
}

impl ChainStateSnapshot {
    pub fn tip_hash(&self) -> &[u8; 32] { &self.tip_hash }
    pub fn tip_height(&self) -> u64 { self.tip_height }
}

/// Read-only TxStateStore for parallel verification against a frozen snapshot.
impl TxStateStore for ChainStateSnapshot {
    type Error = ChainStateError;

    fn has_link_tag(&self, tag: &LinkTag) -> Result<bool, Self::Error> {
        Ok(self.link_tags.contains(tag))
    }

    fn insert_link_tag(&mut self, _tag: &LinkTag) -> Result<(), Self::Error> {
        Err(ChainStateError("insert_link_tag called on read-only snapshot".into()))
    }

    fn enote_exists(&self, id: &EnoteId) -> Result<bool, Self::Error> {
        Ok(self.enotes.contains_key(id))
    }

    fn load_enote(&self, id: &EnoteId) -> Result<Option<StoredEnote>, Self::Error> {
        Ok(self.enotes.get(id).cloned())
    }

    fn insert_enote(&mut self, _enote: &StoredEnote) -> Result<(), Self::Error> {
        Err(ChainStateError("insert_enote called on read-only snapshot".into()))
    }
}

impl ChainState {
    pub fn genesis() -> Self {
        Self {
            enotes: HashMap::new(),
            link_tags: HashSet::new(),
            tip_hash: [0u8; 32],
            tip_height: 0,
        }
    }

    pub fn tip_hash(&self) -> &[u8; 32] { &self.tip_hash }
    pub fn tip_height(&self) -> u64 { self.tip_height }
    pub fn enote_count(&self) -> usize { self.enotes.len() }
    pub fn link_tag_count(&self) -> usize { self.link_tags.len() }

    /// Create a snapshot of the current state for rollback.
    ///
    /// Used by atomic block application: snapshot before applying,
    /// restore if any tx fails.
    pub fn snapshot(&self) -> ChainStateSnapshot {
        ChainStateSnapshot {
            enotes: self.enotes.clone(),
            link_tags: self.link_tags.clone(),
            tip_hash: self.tip_hash,
            tip_height: self.tip_height,
        }
    }

    /// Restore state from a snapshot, discarding all changes since snapshot.
    pub fn restore(&mut self, snap: ChainStateSnapshot) {
        self.enotes = snap.enotes;
        self.link_tags = snap.link_tags;
        self.tip_hash = snap.tip_hash;
        self.tip_height = snap.tip_height;
    }

    /// Update tip hash and height after block commit.
    ///
    /// Separated from apply logic so the block crate can
    /// control when the tip advances.
    pub fn set_tip(&mut self, hash: [u8; 32], height: u64) {
        self.tip_hash = hash;
        self.tip_height = height;
    }

    /// Apply a committed block using store-backed verification.
    ///
    /// For each TX: verify → extract effects → apply atomically.
    pub fn apply_block<P: ProofBackend>(
        &mut self,
        block: &Block,
        backend: &P,
    ) -> Result<(), StoreError>
    {
        let h = &block.header;
        let expected = if self.tip_height == 0 && self.tip_hash == [0u8; 32] {
            h.height
        } else {
            self.tip_height + 1
        };
        if h.height != expected {
            return Err(StoreError::HeightMismatch { expected, got: h.height });
        }
        if h.height > 0 && h.prev_hash != self.tip_hash {
            return Err(StoreError::PrevHashMismatch);
        }

        for tx in &block.transactions {
            // Verify against store state
            let result = verify_with_store(tx, self, backend);
            if !result.valid {
                let msg = result.error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown".into());
                return Err(StoreError::TxVerifyFailed(msg));
            }

            // Apply effects
            let effects = extract_effects(tx);
            apply_tx_effects(self, &effects)
                .map_err(|e| StoreError::TxApplyFailed(e.to_string()))?;
        }

        self.tip_hash = block.hash();
        self.tip_height = h.height;
        Ok(())
    }

    /// Apply block without TX verification (light nodes / trusted import).
    pub fn apply_block_trusted(&mut self, block: &Block) -> Result<(), StoreError> {
        let h = &block.header;
        let expected = if self.tip_height == 0 && self.tip_hash == [0u8; 32] {
            h.height
        } else {
            self.tip_height + 1
        };
        if h.height != expected {
            return Err(StoreError::HeightMismatch { expected, got: h.height });
        }
        self.tip_hash = block.hash();
        self.tip_height = h.height;
        Ok(())
    }
}

/// TxStateStore implementation for ChainState.
impl TxStateStore for ChainState {
    type Error = ChainStateError;

    fn has_link_tag(&self, tag: &LinkTag) -> Result<bool, Self::Error> {
        Ok(self.link_tags.contains(tag))
    }

    fn insert_link_tag(&mut self, tag: &LinkTag) -> Result<(), Self::Error> {
        if !self.link_tags.insert(*tag) {
            return Err(ChainStateError(format!(
                "duplicate link tag: {}", hex::encode(tag.0)
            )));
        }
        Ok(())
    }

    fn enote_exists(&self, id: &EnoteId) -> Result<bool, Self::Error> {
        Ok(self.enotes.contains_key(id))
    }

    fn load_enote(&self, id: &EnoteId) -> Result<Option<StoredEnote>, Self::Error> {
        Ok(self.enotes.get(id).cloned())
    }

    fn insert_enote(&mut self, enote: &StoredEnote) -> Result<(), Self::Error> {
        self.enotes.insert(enote.enote_id, enote.clone());
        Ok(())
    }
}

// ── Node store ──

pub struct NodeStore {
    policy: PrunePolicy,
    headers: BTreeMap<u64, BlockHeader>,
    bodies: BTreeMap<u64, Vec<TxBody>>,
    pub state: ChainState,
}

impl NodeStore {
    pub fn new(role: NodeRole) -> Self {
        Self {
            policy: PrunePolicy::for_role(role),
            headers: BTreeMap::new(),
            bodies: BTreeMap::new(),
            state: ChainState::genesis(),
        }
    }

    pub fn role(&self) -> NodeRole { self.policy.role }
    pub fn tip_height(&self) -> u64 { self.state.tip_height }
    pub fn header_count(&self) -> usize { self.headers.len() }
    pub fn body_count(&self) -> usize { self.bodies.len() }

    pub fn commit_block<P: ProofBackend>(
        &mut self,
        block: &Block,
        backend: &P,
    ) -> Result<(), StoreError>
    {
        let height = block.header.height;
        self.headers.insert(height, block.header.clone());

        if self.policy.keeps_full_state() {
            self.state.apply_block(block, backend)?;
        } else {
            self.state.apply_block_trusted(block)?;
        }

        if self.policy.should_store_body(height, height) {
            self.bodies.insert(height, block.transactions.clone());
        }

        if self.policy.role == NodeRole::Validator {
            let cutoff = height.saturating_sub(self.policy.retention_blocks);
            let old: Vec<u64> = self.bodies.range(..cutoff).map(|(k, _)| *k).collect();
            for k in old { self.bodies.remove(&k); }
        }

        Ok(())
    }

    pub fn get_header(&self, h: u64) -> Option<&BlockHeader> { self.headers.get(&h) }
    pub fn has_body(&self, h: u64) -> bool { self.bodies.contains_key(&h) }
    pub fn get_body(&self, h: u64) -> Option<&Vec<TxBody>> { self.bodies.get(&h) }

    /// Reconstruct a full Block from stored header + body at height h.
    pub fn get_block(&self, h: u64) -> Option<Block> {
        let header = self.headers.get(&h)?.clone();
        let txs = self.bodies.get(&h)?.clone();
        Some(Block { header, transactions: txs })
    }

    pub fn stats(&self) -> StoreStats {
        StoreStats {
            role: self.policy.role,
            tip_height: self.state.tip_height,
            header_count: self.headers.len(),
            body_count: self.bodies.len(),
            enote_count: self.state.enote_count(),
            link_tag_count: self.state.link_tag_count(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StoreStats {
    pub role: NodeRole,
    pub tip_height: u64,
    pub header_count: usize,
    pub body_count: usize,
    pub enote_count: usize,
    pub link_tag_count: usize,
}
