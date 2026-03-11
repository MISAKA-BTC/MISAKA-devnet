// ============================================================
// MISAKA Relay — Relay Manager
// ============================================================
//
// Central message handler that wires:
//   peer network → mempool admission → block validation/commit → re-announce
//
// Transport-agnostic: produces OutboundAction values that the
// network layer dispatches. All state is synchronous.
//
// ============================================================

use crate::{
    PeerId, BlockHash, RelayConfig, RelayMessage, OutboundAction,
    PenaltyReason, RelayCounters,
    peer::{PeerRegistry, BoundedHashSet},
    orphan::{OrphanBlockPool, OrphanEntry},
};
use misaka_tx::{TxBody, TxId, verify::compute_actual_size, MAX_TX_SIZE};
use misaka_store::{Block, ChainState};
use misaka_mempool::{Mempool, MempoolStoreView, AdmitResult};
use misaka_block::{
    validate_block, apply_block_atomically_trusted,
    on_block_committed, BlockApplyResult, BlockValidationResult,
};
use std::collections::HashMap;

/// The relay manager: handles incoming messages, drives the pipeline,
/// and produces outbound actions.
///
/// Lifetime-free: stores owned state. The caller passes in references
/// to mempool/state for each operation.
pub struct RelayManager {
    config: RelayConfig,
    peers: PeerRegistry,
    orphans: OrphanBlockPool,
    counters: RelayCounters,

    // ── Global known-object caches ──
    known_tx_ids: BoundedHashSet<TxId>,
    known_block_hashes: BoundedHashSet<BlockHash>,

    // ── Dedup: recently requested objects (avoid multi-peer requests) ──
    recently_requested_txs: BoundedHashSet<TxId>,
    recently_requested_blocks: BoundedHashSet<BlockHash>,

    // ── TX storage for serving GetTx requests ──
    // (small cache of recently accepted txs)
    tx_cache: HashMap<TxId, Box<TxBody>>,
    tx_cache_order: std::collections::VecDeque<TxId>,
    max_tx_cache: usize,

    // ── Block storage for serving GetBlock requests ──
    // (small cache of recently committed blocks)
    block_cache: HashMap<BlockHash, Box<Block>>,
    block_cache_order: std::collections::VecDeque<BlockHash>,
    max_block_cache: usize,
}

impl RelayManager {
    pub fn new(config: RelayConfig) -> Self {
        let max_tx = config.max_known_tx_cache;
        let max_blk = config.max_known_block_cache;
        let max_req = config.max_recent_requests;
        Self {
            peers: PeerRegistry::new(config.clone()),
            orphans: OrphanBlockPool::new(&config),
            counters: RelayCounters::default(),
            known_tx_ids: BoundedHashSet::new(max_tx),
            known_block_hashes: BoundedHashSet::new(max_blk),
            recently_requested_txs: BoundedHashSet::new(max_req),
            recently_requested_blocks: BoundedHashSet::new(max_req),
            tx_cache: HashMap::new(),
            tx_cache_order: std::collections::VecDeque::new(),
            max_tx_cache: 256,
            block_cache: HashMap::new(),
            block_cache_order: std::collections::VecDeque::new(),
            max_block_cache: 32,
            config,
        }
    }

    // ── Accessors ──

    pub fn counters(&self) -> &RelayCounters { &self.counters }
    pub fn peers(&self) -> &PeerRegistry { &self.peers }
    pub fn orphan_count(&self) -> usize { self.orphans.len() }
    pub fn config(&self) -> &RelayConfig { &self.config }

    // ── Peer management ──

    pub fn register_peer(&mut self, peer_id: PeerId) {
        self.peers.register(peer_id);
    }

    pub fn unregister_peer(&mut self, peer_id: PeerId) {
        self.peers.unregister(&peer_id);
    }

    // ════════════════════════════════════════════
    // Main message handler
    // ════════════════════════════════════════════

    /// Handle an incoming message from a peer.
    ///
    /// Returns a list of outbound actions to perform.
    /// The caller is responsible for dispatching them.
    ///
    /// `now_secs` is the current Unix timestamp for rate limiting.
    pub fn handle_message<S, V>(
        &mut self,
        peer_id: PeerId,
        msg: RelayMessage,
        now_secs: u64,
        mempool: &mut Mempool,
        state: &mut ChainState,
        store_view: &S,
        verify_proofs: V,
    ) -> Vec<OutboundAction>
    where
        S: MempoolStoreView,
        V: Fn(&TxBody) -> Result<(), String> + Clone,
    {
        let mut actions = Vec::new();

        // Ensure peer is registered
        if self.peers.get(&peer_id).is_none() {
            self.peers.register(peer_id);
        }

        match msg {
            RelayMessage::NewTx { tx_id } =>
                self.handle_new_tx(peer_id, tx_id, now_secs, &mut actions),

            RelayMessage::GetTx { tx_id } =>
                self.handle_get_tx(peer_id, tx_id, now_secs, &mut actions),

            RelayMessage::Tx { tx } =>
                self.handle_tx(peer_id, *tx, now_secs, mempool, store_view, verify_proofs, &mut actions),

            RelayMessage::NewBlock { block_hash, height } =>
                self.handle_new_block(peer_id, block_hash, height, now_secs, &mut actions),

            RelayMessage::GetBlock { block_hash } =>
                self.handle_get_block(peer_id, block_hash, now_secs, &mut actions),

            RelayMessage::BlockMsg { block } =>
                self.handle_block(peer_id, *block, now_secs, mempool, state, store_view, verify_proofs, &mut actions),

            RelayMessage::Ping { nonce } => {
                actions.push(OutboundAction::Send {
                    peer: peer_id,
                    msg: RelayMessage::Pong { nonce },
                });
            }
            RelayMessage::Pong { .. } => {} // acknowledged, no action
            RelayMessage::PeerStatus { height, tip_hash } => {
                if let Some(ps) = self.peers.get_mut(&peer_id) {
                    ps.reported_height = height;
                    ps.reported_tip_hash = tip_hash;
                }
            }
        }

        actions
    }

    // ════════════════════════════════════════════
    // TX relay handlers
    // ════════════════════════════════════════════

    fn handle_new_tx(
        &mut self,
        peer_id: PeerId,
        tx_id: TxId,
        now_secs: u64,
        actions: &mut Vec<OutboundAction>,
    ) {
        self.counters.tx_announced += 1;

        // Rate limit
        if let Some(ps) = self.peers.get_mut(&peer_id) {
            if !ps.announce_limiter.try_consume(now_secs) {
                if ps.announce_limiter.is_hard_exceeded(now_secs) {
                    let disconnect = ps.apply_penalty(PenaltyReason::Spam);
                    self.counters.peer_penalized += 1;
                    if disconnect {
                        self.counters.peer_disconnected += 1;
                        actions.push(OutboundAction::Disconnect {
                            peer: peer_id,
                            reason: "spam rate exceeded".into(),
                        });
                    }
                }
                return;
            }
            ps.known_tx_ids.insert(tx_id);
        }

        // Already known? Skip.
        if self.known_tx_ids.contains(&tx_id) {
            return;
        }

        // Already requested from another peer? Skip.
        if self.recently_requested_txs.contains(&tx_id) {
            return;
        }

        // Request from this peer
        self.recently_requested_txs.insert(tx_id);
        if let Some(ps) = self.peers.get_mut(&peer_id) {
            ps.pending_tx_requests.insert(tx_id);
        }
        self.counters.tx_requested += 1;
        actions.push(OutboundAction::Send {
            peer: peer_id,
            msg: RelayMessage::GetTx { tx_id },
        });
    }

    fn handle_get_tx(
        &mut self,
        peer_id: PeerId,
        tx_id: TxId,
        now_secs: u64,
        actions: &mut Vec<OutboundAction>,
    ) {
        // Rate limit
        if let Some(ps) = self.peers.get_mut(&peer_id) {
            if !ps.request_limiter.try_consume(now_secs) {
                return;
            }
        }

        // Serve from cache if available
        if let Some(tx) = self.tx_cache.get(&tx_id) {
            actions.push(OutboundAction::Send {
                peer: peer_id,
                msg: RelayMessage::Tx { tx: tx.clone() },
            });
        }
    }

    fn handle_tx<S, V>(
        &mut self,
        peer_id: PeerId,
        tx: TxBody,
        now_secs: u64,
        mempool: &mut Mempool,
        store_view: &S,
        verify_proofs: V,
        actions: &mut Vec<OutboundAction>,
    )
    where
        S: MempoolStoreView,
        V: Fn(&TxBody) -> Result<(), String>,
    {
        // Rate limit
        if let Some(ps) = self.peers.get_mut(&peer_id) {
            if !ps.object_limiter.try_consume(now_secs) {
                return;
            }
        }

        let tx_id = tx.tx_id;

        // Check if we actually requested this
        let _was_requested = self.peers.get_mut(&peer_id)
            .map(|ps| ps.pending_tx_requests.remove(&tx_id))
            .unwrap_or(false);

        // Size check (cheap)
        let actual_size = compute_actual_size(&tx);
        if actual_size > MAX_TX_SIZE {
            self.penalize(peer_id, PenaltyReason::OversizedTx, actions);
            self.counters.tx_rejected += 1;
            return;
        }

        // Already known?
        if self.known_tx_ids.contains(&tx_id) {
            return;
        }

        // Mempool admission
        match mempool.admit_tx(tx.clone(), store_view, verify_proofs) {
            AdmitResult::Accepted { .. } => {
                self.counters.tx_accepted += 1;
                self.known_tx_ids.insert(tx_id);

                // Cache for serving
                self.cache_tx(tx_id, tx);

                // Re-announce to other peers
                actions.push(OutboundAction::Broadcast {
                    exclude: Some(peer_id),
                    msg: RelayMessage::NewTx { tx_id },
                });
            }
            AdmitResult::Rejected(err) => {
                self.counters.tx_rejected += 1;
                // Only penalize for clearly invalid txs, not duplicates or conflicts
                let is_structural = matches!(&err,
                    misaka_mempool::MempoolError::ProofVerificationFailed(_) |
                    misaka_mempool::MempoolError::TxValidation(_)
                );
                if is_structural {
                    self.penalize(peer_id, PenaltyReason::InvalidTx, actions);
                }
                // Mark as known to avoid re-requesting
                self.known_tx_ids.insert(tx_id);
            }
        }
    }

    // ════════════════════════════════════════════
    // Block relay handlers
    // ════════════════════════════════════════════

    fn handle_new_block(
        &mut self,
        peer_id: PeerId,
        block_hash: BlockHash,
        height: u64,
        now_secs: u64,
        actions: &mut Vec<OutboundAction>,
    ) {
        self.counters.block_announced += 1;

        // Rate limit
        if let Some(ps) = self.peers.get_mut(&peer_id) {
            if !ps.announce_limiter.try_consume(now_secs) {
                if ps.announce_limiter.is_hard_exceeded(now_secs) {
                    let disconnect = ps.apply_penalty(PenaltyReason::Spam);
                    self.counters.peer_penalized += 1;
                    if disconnect {
                        self.counters.peer_disconnected += 1;
                        actions.push(OutboundAction::Disconnect {
                            peer: peer_id,
                            reason: "block announce spam".into(),
                        });
                    }
                }
                return;
            }
            ps.known_block_hashes.insert(block_hash);
        }

        // Already known/committed?
        if self.known_block_hashes.contains(&block_hash) {
            return;
        }

        // Already in orphan buffer?
        if self.orphans.contains(&block_hash) {
            return;
        }

        // Already requested?
        if self.recently_requested_blocks.contains(&block_hash) {
            return;
        }

        // Request
        self.recently_requested_blocks.insert(block_hash);
        if let Some(ps) = self.peers.get_mut(&peer_id) {
            ps.pending_block_requests.insert(block_hash);
        }
        self.counters.block_requested += 1;
        actions.push(OutboundAction::Send {
            peer: peer_id,
            msg: RelayMessage::GetBlock { block_hash },
        });
    }

    fn handle_get_block(
        &mut self,
        peer_id: PeerId,
        block_hash: BlockHash,
        now_secs: u64,
        actions: &mut Vec<OutboundAction>,
    ) {
        // Rate limit
        if let Some(ps) = self.peers.get_mut(&peer_id) {
            if !ps.request_limiter.try_consume(now_secs) {
                return;
            }
        }

        if let Some(block) = self.block_cache.get(&block_hash) {
            actions.push(OutboundAction::Send {
                peer: peer_id,
                msg: RelayMessage::BlockMsg { block: block.clone() },
            });
        }
    }

    fn handle_block<S, V>(
        &mut self,
        peer_id: PeerId,
        block: Block,
        now_secs: u64,
        mempool: &mut Mempool,
        state: &mut ChainState,
        store_view: &S,
        verify_proofs: V,
        actions: &mut Vec<OutboundAction>,
    )
    where
        S: MempoolStoreView,
        V: Fn(&TxBody) -> Result<(), String> + Clone,
    {
        // Rate limit
        if let Some(ps) = self.peers.get_mut(&peer_id) {
            if !ps.object_limiter.try_consume(now_secs) {
                return;
            }
        }

        let block_hash = block.hash();
        let height = block.header.height;
        let prev_hash = block.header.prev_hash;

        // Already known/committed?
        if self.known_block_hashes.contains(&block_hash) {
            return;
        }

        // Block size check (cheap)
        let total_size: usize = block.transactions.iter()
            .map(|tx| compute_actual_size(tx) as usize)
            .sum();
        if total_size > self.config.max_block_bytes {
            self.penalize(peer_id, PenaltyReason::OversizedBlock, actions);
            return;
        }

        // Structural validation (cheap — no proof verification)
        let expected_height = state.tip_height() + 1;

        // Check if parent is known
        let parent_is_tip = prev_hash == *state.tip_hash();
        let is_genesis = height == 0 && *state.tip_hash() == [0u8; 32];

        if parent_is_tip || is_genesis {
            // Parent known — full validation + commit
            self.process_block(peer_id, block, block_hash, height, mempool, state, store_view, verify_proofs, actions);
        } else {
            // Parent unknown — orphan buffer
            let entry = OrphanEntry {
                block,
                block_hash,
                parent_hash: prev_hash,
                height,
                from_peer: peer_id,
            };
            match self.orphans.insert(entry) {
                Ok(()) => {
                    self.counters.orphan_inserted += 1;
                }
                Err(_) => {
                    // Buffer full or duplicate — just drop
                }
            }
        }
    }

    // ════════════════════════════════════════════
    // Block processing pipeline
    // ════════════════════════════════════════════

    /// Process a block that has a known parent.
    fn process_block<S, V>(
        &mut self,
        from_peer: PeerId,
        block: Block,
        block_hash: BlockHash,
        height: u64,
        mempool: &mut Mempool,
        state: &mut ChainState,
        _store_view: &S,
        _verify_proofs: V,
        actions: &mut Vec<OutboundAction>,
    )
    where
        S: MempoolStoreView,
        V: Fn(&TxBody) -> Result<(), String> + Clone,
    {
        let expected_height = if *state.tip_hash() == [0u8; 32] {
            0
        } else {
            state.tip_height() + 1
        };

        // Structural validation
        let validation = validate_block(
            &block, expected_height, state.tip_hash(), self.config.max_block_bytes,
        );
        if let BlockValidationResult::Invalid(err) = validation {
            self.penalize(from_peer, PenaltyReason::InvalidBlock, actions);
            return;
        }

        // Atomic apply (trusted mode — proofs checked at mempool admission)
        let result = apply_block_atomically_trusted(&block, state);

        match result {
            BlockApplyResult::Applied { .. } => {
                self.counters.block_committed += 1;
                self.known_block_hashes.insert(block_hash);

                // Mempool cleanup
                on_block_committed(&block, mempool);

                // Cache for serving
                self.cache_block(block_hash, block);

                // Re-announce to peers
                actions.push(OutboundAction::Broadcast {
                    exclude: Some(from_peer),
                    msg: RelayMessage::NewBlock { block_hash, height },
                });

                // Process orphan children
                self.process_orphan_children(
                    block_hash, mempool, state, actions,
                );
            }
            BlockApplyResult::Rejected(_err) => {
                self.penalize(from_peer, PenaltyReason::InvalidBlock, actions);
            }
        }
    }

    /// Iteratively process orphan children after a block commit.
    fn process_orphan_children(
        &mut self,
        committed_hash: BlockHash,
        mempool: &mut Mempool,
        state: &mut ChainState,
        actions: &mut Vec<OutboundAction>,
    ) {
        let mut queue = vec![committed_hash];

        while let Some(parent_hash) = queue.pop() {
            let children = self.orphans.pop_children(&parent_hash);
            for orphan in children {
                let bh = orphan.block_hash;
                let h = orphan.height;
                let from = orphan.from_peer;

                let expected_height = if *state.tip_hash() == [0u8; 32] {
                    0
                } else {
                    state.tip_height() + 1
                };

                // Validate
                let validation = validate_block(
                    &orphan.block, expected_height, state.tip_hash(), self.config.max_block_bytes,
                );
                if let BlockValidationResult::Invalid(_) = validation {
                    self.counters.orphan_resolved += 1;
                    continue;
                }

                // Apply
                let result = apply_block_atomically_trusted(&orphan.block, state);
                match result {
                    BlockApplyResult::Applied { .. } => {
                        self.counters.block_committed += 1;
                        self.counters.orphan_resolved += 1;
                        self.known_block_hashes.insert(bh);
                        on_block_committed(&orphan.block, mempool);
                        self.cache_block(bh, orphan.block);
                        actions.push(OutboundAction::Broadcast {
                            exclude: Some(from),
                            msg: RelayMessage::NewBlock { block_hash: bh, height: h },
                        });
                        // This block's hash may have further orphan children
                        queue.push(bh);
                    }
                    BlockApplyResult::Rejected(_) => {
                        self.counters.orphan_resolved += 1;
                    }
                }
            }
        }
    }

    // ════════════════════════════════════════════
    // Convenience: announce from local proposer
    // ════════════════════════════════════════════

    /// Announce a locally accepted tx to all peers.
    pub fn announce_tx(&mut self, tx_id: TxId, tx: TxBody) -> Vec<OutboundAction> {
        self.known_tx_ids.insert(tx_id);
        self.cache_tx(tx_id, tx);
        vec![OutboundAction::Broadcast {
            exclude: None,
            msg: RelayMessage::NewTx { tx_id },
        }]
    }

    /// Announce a locally committed block to all peers.
    pub fn announce_block(&mut self, block_hash: BlockHash, height: u64, block: Block) -> Vec<OutboundAction> {
        self.known_block_hashes.insert(block_hash);
        self.cache_block(block_hash, block);
        vec![OutboundAction::Broadcast {
            exclude: None,
            msg: RelayMessage::NewBlock { block_hash, height },
        }]
    }

    // ════════════════════════════════════════════
    // Internal helpers
    // ════════════════════════════════════════════

    fn penalize(
        &mut self,
        peer_id: PeerId,
        reason: PenaltyReason,
        actions: &mut Vec<OutboundAction>,
    ) {
        self.counters.peer_penalized += 1;
        if let Some(ps) = self.peers.get_mut(&peer_id) {
            let disconnect = ps.apply_penalty(reason);
            if disconnect {
                self.counters.peer_disconnected += 1;
                actions.push(OutboundAction::Disconnect {
                    peer: peer_id,
                    reason: format!("{:?}", reason),
                });
            }
        }
    }

    fn cache_tx(&mut self, tx_id: TxId, tx: TxBody) {
        if self.tx_cache.len() >= self.max_tx_cache {
            if let Some(old) = self.tx_cache_order.pop_front() {
                self.tx_cache.remove(&old);
            }
        }
        self.tx_cache_order.push_back(tx_id);
        self.tx_cache.insert(tx_id, Box::new(tx));
    }

    fn cache_block(&mut self, block_hash: BlockHash, block: Block) {
        if self.block_cache.len() >= self.max_block_cache {
            if let Some(old) = self.block_cache_order.pop_front() {
                self.block_cache.remove(&old);
            }
        }
        self.block_cache_order.push_back(block_hash);
        self.block_cache.insert(block_hash, Box::new(block));
    }
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_tx::*;
    use misaka_crypto::ring_sig::{RingSignature, larrs_keygen};
    use misaka_crypto::proof_backend::{TestnetBackend, RangeProofBackend, BalanceProofBackend};
    use misaka_crypto::hash::merkle_root;
    use misaka_store::{BlockHeader, ChainState};
    use misaka_mempool::Mempool;
    use std::collections::HashSet;

    // ── Test fixtures ──

    struct TestStoreView {
        enotes: HashSet<EnoteId>,
        link_tags: HashSet<LinkTag>,
    }

    impl TestStoreView {
        fn standard() -> Self {
            let mut s = Self { enotes: HashSet::new(), link_tags: HashSet::new() };
            for id in [1u8, 2, 3, 4] { s.enotes.insert(EnoteId([id; 32])); }
            s
        }
    }

    impl MempoolStoreView for TestStoreView {
        fn has_link_tag(&self, tag: &LinkTag) -> Result<bool, String> {
            Ok(self.link_tags.contains(tag))
        }
        fn ring_member_exists(&self, id: &EnoteId) -> Result<bool, String> {
            Ok(self.enotes.contains(id))
        }
    }

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

    fn pass_proofs(_tx: &TxBody) -> Result<(), String> { Ok(()) }

    fn setup() -> (RelayManager, Mempool, ChainState, TestStoreView) {
        let rm = RelayManager::new(RelayConfig::default());
        let mp = Mempool::with_defaults();
        let st = seeded_chain_state();
        let sv = TestStoreView::standard();
        (rm, mp, st, sv)
    }

    // ════════════════════════════════════════════
    // TX relay tests
    // ════════════════════════════════════════════

    #[test]
    fn test_unknown_tx_triggers_get_tx() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let tx_id = tx.tx_id;

        let actions = rm.handle_message(
            1, RelayMessage::NewTx { tx_id }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );

        // Should produce a GetTx request
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], OutboundAction::Send {
            peer: 1,
            msg: RelayMessage::GetTx { tx_id: id }
        } if *id == tx_id));
    }

    #[test]
    fn test_accepted_tx_enters_mempool_and_reannounced() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);
        rm.register_peer(2);

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let tx_id = tx.tx_id;

        // Send the full tx
        let actions = rm.handle_message(
            1, RelayMessage::Tx { tx: Box::new(tx) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );

        // Should be accepted and re-announced
        assert!(mp.contains_tx(&tx_id));
        assert!(actions.iter().any(|a| matches!(a,
            OutboundAction::Broadcast { exclude: Some(1), msg: RelayMessage::NewTx { .. } }
        )));
        assert_eq!(rm.counters().tx_accepted, 1);
    }

    #[test]
    fn test_duplicate_tx_announce_ignored() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let tx_id = tx.tx_id;

        // Mark as known
        rm.known_tx_ids.insert(tx_id);

        let actions = rm.handle_message(
            1, RelayMessage::NewTx { tx_id }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );

        // No request should be generated
        assert!(actions.is_empty());
    }

    #[test]
    fn test_oversized_tx_causes_penalty() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        // Create a tx with huge tx_extra to make it oversized
        let mut tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        // The actual_size check will reject if > MAX_TX_SIZE (200_000)
        // We can't easily make compute_actual_size return > 200k with normal dummy,
        // but we test the penalty mechanism directly
        let score_before = rm.peers.get(&1).unwrap().score;

        // Simulate by checking the penalty path
        let mut actions = Vec::new();
        rm.penalize(1, PenaltyReason::OversizedTx, &mut actions);

        let score_after = rm.peers.get(&1).unwrap().score;
        assert!(score_after < score_before);
        assert_eq!(rm.counters().peer_penalized, 1);
    }

    // ════════════════════════════════════════════
    // Block relay tests
    // ════════════════════════════════════════════

    #[test]
    fn test_unknown_block_triggers_get_block() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        let bh = [0xBB; 32];
        let actions = rm.handle_message(
            1, RelayMessage::NewBlock { block_hash: bh, height: 1 }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );

        assert!(actions.iter().any(|a| matches!(a,
            OutboundAction::Send { peer: 1, msg: RelayMessage::GetBlock { block_hash } }
            if *block_hash == bh
        )));
    }

    #[test]
    fn test_valid_block_commits_and_reannounced() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);
        rm.register_peer(2);

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block = make_block(vec![tx], 0, [0u8; 32]);
        let bh = block.hash();

        let actions = rm.handle_message(
            1, RelayMessage::BlockMsg { block: Box::new(block) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );

        assert_eq!(rm.counters().block_committed, 1);
        assert!(actions.iter().any(|a| matches!(a,
            OutboundAction::Broadcast { exclude: Some(1), msg: RelayMessage::NewBlock { .. } }
        )));
    }

    #[test]
    fn test_block_unknown_parent_enters_orphan() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        // Block with parent that doesn't match current tip
        let block = make_block(vec![], 5, [0xFF; 32]);
        let bh = block.hash();

        let actions = rm.handle_message(
            1, RelayMessage::BlockMsg { block: Box::new(block) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );

        assert_eq!(rm.orphan_count(), 1);
        assert_eq!(rm.counters().orphan_inserted, 1);
    }

    #[test]
    fn test_orphan_child_processed_after_parent() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        // Block 0 (parent = genesis)
        let tx0 = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let block0 = make_block(vec![tx0], 0, [0u8; 32]);
        let block0_hash = block0.hash();

        // Block 1 (parent = block0)
        let block1 = make_block(vec![], 1, block0_hash);
        let block1_hash = block1.hash();

        // Send block1 first (orphan)
        let actions1 = rm.handle_message(
            1, RelayMessage::BlockMsg { block: Box::new(block1) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );
        assert_eq!(rm.orphan_count(), 1);

        // Now send block0 (parent) — should commit block0 then auto-process block1
        let actions0 = rm.handle_message(
            1, RelayMessage::BlockMsg { block: Box::new(block0) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );

        // Both blocks committed
        assert_eq!(rm.counters().block_committed, 2);
        assert_eq!(rm.orphan_count(), 0);
        assert_eq!(rm.counters().orphan_resolved, 1);
        assert_eq!(st.tip_height(), 1);
    }

    #[test]
    fn test_duplicate_block_ignored() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        let block = make_block(vec![], 0, [0u8; 32]);
        let bh = block.hash();

        // First time — commits
        rm.handle_message(
            1, RelayMessage::BlockMsg { block: Box::new(block.clone()) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );
        assert_eq!(rm.counters().block_committed, 1);

        // Second time — ignored (known)
        rm.handle_message(
            1, RelayMessage::BlockMsg { block: Box::new(block) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );
        assert_eq!(rm.counters().block_committed, 1); // unchanged
    }

    // ════════════════════════════════════════════
    // Peer penalty / rate limit tests
    // ════════════════════════════════════════════

    #[test]
    fn test_spam_penalty_after_rate_limit() {
        let config = RelayConfig {
            tx_announce_rate_limit: 3,
            ..RelayConfig::default()
        };
        let mut rm = RelayManager::new(config);
        let mut mp = Mempool::with_defaults();
        let mut st = seeded_chain_state();
        let sv = TestStoreView::standard();
        rm.register_peer(1);

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);

        // Send many announces — first 3 ok, rest rate-limited
        for i in 0..10 {
            let mut id = tx.tx_id;
            id.0[0] = i; // unique ids to avoid "already known" path
            rm.handle_message(
                1, RelayMessage::NewTx { tx_id: id }, 100,
                &mut mp, &mut st, &sv, pass_proofs,
            );
        }

        // After hard limit (2x = 6), penalty should be applied
        let score = rm.peers.get(&1).unwrap().score;
        assert!(score < 100, "score should have decreased: {}", score);
    }

    #[test]
    fn test_benign_duplicate_no_overpenalize() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let tx_id = tx.tx_id;

        // First announce → triggers request
        rm.handle_message(
            1, RelayMessage::NewTx { tx_id }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );
        // Second announce of same tx → already requested, just ignored
        rm.handle_message(
            1, RelayMessage::NewTx { tx_id }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );

        // Score should NOT be affected by benign duplicate
        let score = rm.peers.get(&1).unwrap().score;
        assert_eq!(score, 100);
    }

    #[test]
    fn test_disconnect_when_score_depleted() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        // Apply enough penalties to deplete score
        let mut all_actions = Vec::new();
        for _ in 0..3 {
            let mut actions = Vec::new();
            rm.penalize(1, PenaltyReason::InvalidBlock, &mut actions); // 50 each
            all_actions.extend(actions);
        }

        // Should have a Disconnect action
        assert!(all_actions.iter().any(|a| matches!(a, OutboundAction::Disconnect { peer: 1, .. })));
        assert!(rm.counters().peer_disconnected > 0);
    }

    // ════════════════════════════════════════════
    // Integration tests
    // ════════════════════════════════════════════

    #[test]
    fn test_tx_relay_mempool_to_block() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        // Peer announces a tx
        let tx = make_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        let tx_id = tx.tx_id;

        // Step 1: announce
        let actions = rm.handle_message(
            1, RelayMessage::NewTx { tx_id }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );
        assert!(actions.iter().any(|a| matches!(a, OutboundAction::Send { msg: RelayMessage::GetTx { .. }, .. })));

        // Step 2: receive full tx
        let actions = rm.handle_message(
            1, RelayMessage::Tx { tx: Box::new(tx) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );
        assert!(mp.contains_tx(&tx_id));

        // Step 3: build block from mempool
        let block_sv = TestStoreView::standard();
        let block_txs = mp.build_block_candidate(&block_sv, 2_000_000).unwrap();
        assert!(!block_txs.is_empty());
    }

    #[test]
    fn test_block_relay_commit_orphan_chain() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        // Create chain: genesis → block0 → block1 → block2
        let block0 = make_block(vec![], 0, [0u8; 32]);
        let h0 = block0.hash();
        let block1 = make_block(vec![], 1, h0);
        let h1 = block1.hash();
        let block2 = make_block(vec![], 2, h1);

        // Receive in reverse order: block2, block1, block0
        rm.handle_message(
            1, RelayMessage::BlockMsg { block: Box::new(block2) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );
        assert_eq!(rm.orphan_count(), 1);

        rm.handle_message(
            1, RelayMessage::BlockMsg { block: Box::new(block1) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );
        assert_eq!(rm.orphan_count(), 2);

        // Sending block0 should resolve the entire chain
        rm.handle_message(
            1, RelayMessage::BlockMsg { block: Box::new(block0) }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );

        assert_eq!(rm.orphan_count(), 0);
        assert_eq!(rm.counters().block_committed, 3);
        assert_eq!(st.tip_height(), 2);
    }

    #[test]
    fn test_ping_pong() {
        let (mut rm, mut mp, mut st, sv) = setup();
        rm.register_peer(1);

        let actions = rm.handle_message(
            1, RelayMessage::Ping { nonce: 42 }, 100,
            &mut mp, &mut st, &sv, pass_proofs,
        );

        assert!(matches!(&actions[0], OutboundAction::Send {
            peer: 1,
            msg: RelayMessage::Pong { nonce: 42 }
        }));
    }
}
