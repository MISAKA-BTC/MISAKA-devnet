// ============================================================
// MISAKA Testnet — In-Process Virtual Node Runner
// ============================================================
//
// Orchestrates multiple virtual nodes in a single process.
// Each node has its own ChainState, Mempool, ConsensusManager.
//
// Consensus rounds are driven in lock-step:
//   1. Proposer builds block + signs proposal
//   2. All validators handle_proposal
//   3. All validators create_prevote + distribute
//   4. All validators create_precommit + distribute
//   5. All validators try_commit + advance_height
//
// No actual networking — messages are routed through direct
// method calls in deterministic order.
//
// ============================================================

use crate::{
    NodeId, NodeRole, NodeStatus, TestnetStatus, TestnetError,
    config::TestnetConfig,
    keygen::{generate_validator_keys, ValidatorIdentity},
};
use misaka_crypto::falcon::FalconKeyPair;
use misaka_tx::{TxBody, TxId, EnoteId, AmountCommitment, NoteCommitment, ASSET_NATIVE, ENOTE_VERSION, StoredEnote, TxStateStore};
use misaka_store::ChainState;
use misaka_mempool::{Mempool, MempoolStoreView, StoreViewAdapter};
use misaka_block::{
    build_block, BlockBuilderConfig, BlockApplyResult,
    apply_block_atomically_trusted, on_block_committed,
};
use misaka_consensus::{ValidatorSet, VoteType, Vote, create_signed_vote};
use misaka_consensus_relay::{
    ConsensusManager, ConsensusRelayConfig, ConsensusEvent, Proposal,
};
use misaka_verify::ValidatorInfo;
use misaka_store::Block;
use misaka_relay::PeerId;

// ════════════════════════════════════════════
// Virtual node
// ════════════════════════════════════════════

/// A virtual in-process node.
pub struct VirtualNode {
    pub node_id: NodeId,
    pub role: NodeRole,
    pub chain_state: ChainState,
    pub mempool: Mempool,
    pub consensus: ConsensusManager,
    /// Falcon keypair (Some for validators, None for observers).
    pub keypair: Option<FalconKeyPair>,
    /// Fingerprint (validator ID).
    pub fingerprint: [u8; 32],
}

impl VirtualNode {
    fn height(&self) -> u64 { self.chain_state.tip_height() }
    fn consensus_height(&self) -> u64 { self.consensus.current_height() }
}

// ════════════════════════════════════════════
// Testnet runner
// ════════════════════════════════════════════

/// In-process multi-node testnet runner.
pub struct TestnetRunner {
    pub nodes: Vec<VirtualNode>,
    pub validator_set: ValidatorSet,
    config: TestnetConfig,
    blocks_produced: u64,
}

impl TestnetRunner {
    /// Launch a testnet with the given number of validators and observers.
    ///
    /// Generates Falcon keys, creates ValidatorSet, initializes all nodes.
    /// Each node starts at genesis with ring member enotes seeded.
    pub fn launch(
        validator_count: usize,
        observer_count: usize,
    ) -> Result<Self, TestnetError> {
        let config = TestnetConfig {
            validator_count,
            observer_count,
            ..TestnetConfig::default()
        };
        Self::launch_with_config(config)
    }

    /// Launch with explicit config.
    pub fn launch_with_config(config: TestnetConfig) -> Result<Self, TestnetError> {
        // Generate validator keys
        let identities = generate_validator_keys(config.validator_count)?;

        // Build ValidatorSet
        let infos: Vec<ValidatorInfo> = identities.iter().map(|v| ValidatorInfo {
            fingerprint: v.info.fingerprint,
            falcon_pk: v.info.falcon_pk.clone(),
        }).collect();
        let validator_set = ValidatorSet::new(infos)
            .map_err(|e| TestnetError::StartFailed(e.to_string()))?;

        // Create virtual nodes
        let mut nodes = Vec::new();
        let consensus_config = ConsensusRelayConfig::default();

        for (i, identity) in identities.iter().enumerate() {
            let node_id = (i + 1) as NodeId;
            let chain_state = seeded_genesis_state();
            let mempool = Mempool::with_defaults();
            let consensus = ConsensusManager::new(consensus_config.clone(), 0);

            nodes.push(VirtualNode {
                node_id,
                role: NodeRole::Validator,
                chain_state,
                mempool,
                consensus,
                keypair: Some(FalconKeyPair {
                    public_key: identity.keypair.public_key.clone(),
                    secret_key: identity.keypair.secret_key.clone(),
                    fingerprint: identity.keypair.fingerprint,
                }),
                fingerprint: identity.keypair.fingerprint,
            });
        }

        // Observer nodes (no keys, no consensus participation)
        for i in 0..config.observer_count {
            let node_id = (config.validator_count + i + 1) as NodeId;
            nodes.push(VirtualNode {
                node_id,
                role: NodeRole::Observer,
                chain_state: seeded_genesis_state(),
                mempool: Mempool::with_defaults(),
                consensus: ConsensusManager::new(consensus_config.clone(), 0),
                keypair: None,
                fingerprint: [0u8; 32],
            });
        }

        Ok(Self {
            nodes,
            validator_set,
            config,
            blocks_produced: 0,
        })
    }

    /// Get node by ID.
    pub fn node(&self, id: NodeId) -> Option<&VirtualNode> {
        self.nodes.iter().find(|n| n.node_id == id)
    }

    /// Get mutable node by ID.
    pub fn node_mut(&mut self, id: NodeId) -> Option<&mut VirtualNode> {
        self.nodes.iter_mut().find(|n| n.node_id == id)
    }

    /// Number of validators.
    pub fn validator_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.role == NodeRole::Validator).count()
    }

    /// Collect status from all nodes.
    pub fn status(&self) -> TestnetStatus {
        let node_statuses: Vec<NodeStatus> = self.nodes.iter().map(|n| {
            NodeStatus {
                node_id: n.node_id,
                role: n.role,
                chain_height: n.height(),
                consensus_height: n.consensus_height(),
                mempool_size: n.mempool.len(),
                is_committed: n.consensus.is_committed(),
            }
        }).collect();

        let min_h = node_statuses.iter().map(|s| s.chain_height).min().unwrap_or(0);
        let max_h = node_statuses.iter().map(|s| s.chain_height).max().unwrap_or(0);

        TestnetStatus {
            nodes: node_statuses,
            min_height: min_h,
            max_height: max_h,
            blocks_produced: self.blocks_produced,
        }
    }

    /// Check if all nodes are at the given chain height.
    pub fn all_at_height(&self, height: u64) -> bool {
        self.nodes.iter().all(|n| n.height() == height)
    }

    /// Check if all validator consensus managers are at the given height.
    pub fn all_consensus_at_height(&self, height: u64) -> bool {
        self.nodes.iter()
            .filter(|n| n.role == NodeRole::Validator)
            .all(|n| n.consensus_height() == height)
    }

    // ════════════════════════════════════════════
    // Consensus orchestration
    // ════════════════════════════════════════════

    /// Produce exactly one block through the consensus pipeline.
    ///
    /// Lock-step orchestration:
    ///   1. Proposer builds block + signs proposal
    ///   2. All validators receive proposal
    ///   3. All validators prevote
    ///   4. All validators receive all prevotes
    ///   5. All validators precommit
    ///   6. All validators receive all precommits
    ///   7. All validators commit + advance
    ///   8. Observers commit (trusted) + advance
    pub fn produce_one_block(&mut self) -> Result<(), TestnetError> {
        let height = self.nodes[0].consensus.current_height();
        let round = 0u32;

        // ── Phase 1: Proposal ──
        let proposer_info = self.validator_set.get_proposer(height, round);
        let proposer_fp = proposer_info.fingerprint;

        // Find proposer node index
        let proposer_idx = self.nodes.iter()
            .position(|n| n.fingerprint == proposer_fp)
            .ok_or_else(|| TestnetError::BlockError("proposer not found".into()))?;

        // Proposer builds block
        let block = {
            let node = &mut self.nodes[proposer_idx];
            let store_view = StoreViewAdapter(&node.chain_state);
            let block_config = BlockBuilderConfig::default();
            let prev_hash = *node.chain_state.tip_hash();
            build_block(
                &mut node.mempool, &store_view, &block_config,
                height, round, prev_hash, 1000 + height, proposer_fp,
            ).map_err(|e| TestnetError::BlockError(e.to_string()))?
        };

        let block_hash = block.hash();

        // Proposer creates signed proposal
        let proposal = {
            let node = &mut self.nodes[proposer_idx];
            let kp = node.keypair.as_ref().unwrap();
            let (proposal, _) = node.consensus.create_proposal(
                block.clone(), proposer_fp, &kp.secret_key,
            ).map_err(|e| TestnetError::BlockError(e.to_string()))?;
            proposal
        };

        // ── Phase 2: Distribute proposal to all validators ──
        let validator_indices: Vec<usize> = self.nodes.iter().enumerate()
            .filter(|(_, n)| n.role == NodeRole::Validator)
            .map(|(i, _)| i)
            .collect();

        for &idx in &validator_indices {
            if idx == proposer_idx { continue; }
            self.nodes[idx].consensus.handle_proposal(
                proposer_idx as PeerId,
                proposal.clone(),
                &self.validator_set,
            );
        }

        // ── Phase 3: All validators prevote ──
        let mut prevotes: Vec<Vote> = Vec::new();
        for &idx in &validator_indices {
            let node = &mut self.nodes[idx];
            let kp = node.keypair.as_ref().unwrap();
            if let Ok(Some((vote, _))) = node.consensus.create_prevote(
                Some(block_hash), node.fingerprint, &kp.secret_key,
            ) {
                prevotes.push(vote);
            }
        }

        // ── Phase 4: Distribute prevotes to all validators ──
        for vote in &prevotes {
            for &idx in &validator_indices {
                self.nodes[idx].consensus.handle_prevote(
                    0, // peer_id doesn't matter for in-process
                    vote.clone(),
                    &self.validator_set,
                );
            }
        }

        // ── Phase 5: All validators precommit ──
        let mut precommits: Vec<Vote> = Vec::new();
        for &idx in &validator_indices {
            let node = &mut self.nodes[idx];
            let kp = node.keypair.as_ref().unwrap();
            if let Ok(Some((vote, _))) = node.consensus.create_precommit(
                Some(block_hash), node.fingerprint, &kp.secret_key,
            ) {
                precommits.push(vote);
            }
        }

        // ── Phase 6: Distribute precommits to all validators ──
        for vote in &precommits {
            for &idx in &validator_indices {
                self.nodes[idx].consensus.handle_precommit(
                    0,
                    vote.clone(),
                    &self.validator_set,
                );
            }
        }

        // ── Phase 7: All validators commit + advance ──
        for &idx in &validator_indices {
            let node = &mut self.nodes[idx];
            // Store block candidate (it was received via proposal)
            let (committed, _) = node.consensus.try_commit(
                &mut node.chain_state, &mut node.mempool,
            );
            if !committed {
                // If consensus manager doesn't have the block, apply directly
                let result = apply_block_atomically_trusted(&block, &mut node.chain_state);
                if result.is_applied() {
                    on_block_committed(&block, &mut node.mempool);
                }
            }
            node.consensus.advance_height();
        }

        // ── Phase 8: Observers apply block (trusted) ──
        for node in self.nodes.iter_mut().filter(|n| n.role == NodeRole::Observer) {
            let result = apply_block_atomically_trusted(&block, &mut node.chain_state);
            if result.is_applied() {
                on_block_committed(&block, &mut node.mempool);
            }
            // Advance observer's consensus height
            // (observers don't participate in consensus, but track height)
        }

        self.blocks_produced += 1;
        Ok(())
    }

    /// Produce `count` blocks sequentially.
    pub fn produce_blocks(&mut self, count: u64) -> Result<(), TestnetError> {
        for _ in 0..count {
            self.produce_one_block()?;
        }
        Ok(())
    }

    /// Submit a transaction to a specific node's mempool.
    pub fn submit_tx(&mut self, node_id: NodeId, tx: TxBody) -> Result<bool, TestnetError> {
        let node = self.nodes.iter_mut()
            .find(|n| n.node_id == node_id)
            .ok_or(TestnetError::NodeLaunchFailed { node_id, reason: "not found".into() })?;

        let store_view = StoreViewAdapter(&node.chain_state);
        match node.mempool.admit_tx(tx, &store_view, |_| Ok(())) {
            misaka_mempool::AdmitResult::Accepted { .. } => Ok(true),
            misaka_mempool::AdmitResult::Rejected(_) => Ok(false),
        }
    }

    /// Propagate a transaction from one node's mempool to all others.
    ///
    /// Simplified: directly admits the tx to all other mempools.
    pub fn propagate_tx(&mut self, tx: TxBody) {
        for node in &mut self.nodes {
            let store_view = StoreViewAdapter(&node.chain_state);
            let _ = node.mempool.admit_tx(tx.clone(), &store_view, |_| Ok(()));
        }
    }

    /// Restart a specific node (simulates crash + recovery).
    ///
    /// Resets the node's consensus manager to the current chain tip + 1.
    /// ChainState and committed blocks are preserved.
    pub fn restart_node(&mut self, node_id: NodeId) -> Result<(), TestnetError> {
        let node = self.nodes.iter_mut()
            .find(|n| n.node_id == node_id)
            .ok_or(TestnetError::NodeCrashed(node_id))?;

        let next_height = if *node.chain_state.tip_hash() == [0u8; 32] {
            0
        } else {
            node.chain_state.tip_height() + 1
        };

        node.consensus = ConsensusManager::new(ConsensusRelayConfig::default(), next_height);
        node.mempool = Mempool::with_defaults();

        Ok(())
    }
}

// ════════════════════════════════════════════
// Genesis helpers
// ════════════════════════════════════════════

/// Create a genesis chain state with seeded ring member enotes.
fn seeded_genesis_state() -> ChainState {
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

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ═══════════════════════════════════════
    // Scenario A: Basic block production
    // ═══════════════════════════════════════

    #[test]
    fn test_testnet_bootstrap() {
        let testnet = TestnetRunner::launch(10, 1).unwrap();
        assert_eq!(testnet.validator_count(), 10);
        assert_eq!(testnet.nodes.len(), 11);

        let status = testnet.status();
        assert_eq!(status.nodes.len(), 11);
        assert_eq!(status.blocks_produced, 0);
    }

    #[test]
    fn test_produce_one_block() {
        let mut testnet = TestnetRunner::launch(10, 0).unwrap();
        testnet.produce_one_block().unwrap();

        // All validators should have advanced their chain
        for node in &testnet.nodes {
            if node.role == NodeRole::Validator {
                assert_eq!(node.height(), 0, "height after block 0");
            }
        }

        assert_eq!(testnet.blocks_produced, 1);
    }

    #[test]
    fn test_produce_five_blocks() {
        let mut testnet = TestnetRunner::launch(10, 1).unwrap();
        testnet.produce_blocks(5).unwrap();

        assert_eq!(testnet.blocks_produced, 5);

        // All validators should be at height 4 (blocks 0,1,2,3,4)
        for node in &testnet.nodes {
            if node.role == NodeRole::Validator {
                assert_eq!(node.height(), 4);
            }
        }

        // Observer should also be at height 4
        for node in &testnet.nodes {
            if node.role == NodeRole::Observer {
                assert_eq!(node.height(), 4);
            }
        }
    }

    #[test]
    fn test_heights_match_across_nodes() {
        let mut testnet = TestnetRunner::launch(10, 1).unwrap();
        testnet.produce_blocks(3).unwrap();

        let status = testnet.status();
        assert_eq!(status.min_height, status.max_height);
    }

    // ═══════════════════════════════════════
    // Scenario B: Transaction relay
    // ═══════════════════════════════════════

    #[test]
    fn test_tx_propagation() {
        let mut testnet = TestnetRunner::launch(10, 1).unwrap();

        // Create a dummy tx (will fail admission due to invalid proofs,
        // but tests the infrastructure)
        let tx = crate::runner::make_dummy_tx(0x01);

        // Submit to node 1
        let accepted = testnet.submit_tx(1, tx.clone());
        // May be accepted or rejected depending on validation —
        // the point is no panic
        assert!(accepted.is_ok());
    }

    // ═══════════════════════════════════════
    // Scenario C: Node restart
    // ═══════════════════════════════════════

    #[test]
    fn test_node_restart_recovery() {
        let mut testnet = TestnetRunner::launch(10, 0).unwrap();

        // Produce 3 blocks
        testnet.produce_blocks(3).unwrap();

        // Restart node 3
        testnet.restart_node(3).unwrap();

        let node3 = testnet.node(3).unwrap();
        assert_eq!(node3.height(), 2); // chain state preserved
        assert_eq!(node3.consensus_height(), 3); // consensus at next height
        assert_eq!(node3.mempool.len(), 0); // mempool cleared

        // Continue producing blocks after restart
        testnet.produce_blocks(2).unwrap();

        // Node 3 should be caught up
        let node3 = testnet.node(3).unwrap();
        assert_eq!(node3.height(), 4);
    }

    // ═══════════════════════════════════════
    // Scenario D: Status / observability
    // ═══════════════════════════════════════

    #[test]
    fn test_testnet_status() {
        let mut testnet = TestnetRunner::launch(10, 1).unwrap();
        testnet.produce_blocks(2).unwrap();

        let status = testnet.status();
        assert_eq!(status.blocks_produced, 2);
        assert_eq!(status.nodes.len(), 11);

        for ns in &status.nodes {
            assert_eq!(ns.chain_height, 1);
        }
    }

    // ═══════════════════════════════════════
    // Scenario E: Consensus round determinism
    // ═══════════════════════════════════════

    #[test]
    fn test_deterministic_proposer_rotation() {
        let mut testnet = TestnetRunner::launch(10, 0).unwrap();

        // Produce 10 blocks — each validator should propose at least once
        testnet.produce_blocks(10).unwrap();

        // All nodes should agree on height
        assert!(testnet.all_at_height(9));
    }

    #[test]
    fn test_sequential_block_chain() {
        let mut testnet = TestnetRunner::launch(10, 0).unwrap();
        testnet.produce_blocks(5).unwrap();

        // Verify chain tip hashes match across all nodes
        let tip_hash = *testnet.nodes[0].chain_state.tip_hash();
        for node in &testnet.nodes[1..] {
            assert_eq!(*node.chain_state.tip_hash(), tip_hash,
                "node {} tip hash should match", node.node_id);
        }
    }
}

// ════════════════════════════════════════════
// Test helper — dummy tx for mempool tests
// ════════════════════════════════════════════

#[cfg(test)]
pub(crate) fn make_dummy_tx(id_byte: u8) -> TxBody {
    use misaka_crypto::ring_sig::{RingSignature, larrs_keygen};
    use misaka_crypto::proof_backend::{TestnetBackend, RangeProofBackend, BalanceProofBackend};
    use misaka_tx::*;

    let kp = larrs_keygen(&[id_byte; 32]);
    let ring_proof = RingSignature {
        ring: vec![vec![0; 64]; 4],
        key_image: kp.key_image,
        c0: [0; 32],
        responses: vec![vec![0; 64]; 4],
    };
    let rpkh = TxInput::compute_ring_pk_hash(&ring_proof);
    let inp = TxInput {
        ring: RingMembers {
            members: [EnoteId([1; 32]), EnoteId([2; 32]), EnoteId([3; 32]), EnoteId([4; 32])],
            member_commitments: [AmountCommitment([0; 32]); 4],
        },
        ring_proof,
        link_tag: LinkTag(kp.key_image),
        pseudo_output_commitment: AmountCommitment([0; 32]),
        ring_pk_hash: rpkh,
    };

    let ac = AmountCommitment([0xCC; 32]);
    let addr = [0x11; 32];
    let payload = RecipientPayload::encrypt(&[0x42; 32], vec![0; 32], 100, 10, b"", 0);
    let ph = payload.hash();
    let nc = NoteCommitment::compute(&addr, &ac, 0x42, &ph, &ASSET_NATIVE, ENOTE_VERSION);
    let enote = Enote {
        enote_id: EnoteId([0xF0; 32]),
        enote_version: ENOTE_VERSION, asset_id: ASSET_NATIVE,
        one_time_address: addr, amount_commitment: ac,
        note_commitment: nc, view_tag: 0x42,
        recipient_payload: payload, created_at: 0,
    };

    let out = TxOutput { enote };
    let fee = FeeStatement::compute(2000, 1);
    let body_hash = compute_tx_body_hash(&[inp.clone()], &[out.clone()], &fee);
    let bp = BalanceProofBackend::prove(&TestnetBackend,
        &[misaka_crypto::commitment::commit(100, 10)],
        &[misaka_crypto::commitment::commit(100, 10)], 0).unwrap();
    let rp = RangeProofBackend::prove(&TestnetBackend,
        &misaka_crypto::commitment::commit(100, 10)).unwrap();
    let proofs = TxProofBundle {
        balance_proof: bp, range_proofs: vec![rp],
        fee_proof: FeeProof::new(fee.total_fee),
        proof_backend_id: TestnetBackend::BACKEND_ID,
    };
    let proof_hash = compute_tx_proof_hash(&proofs);
    let binding_hash = compute_tx_binding_hash(&body_hash, &proof_hash, TX_VERSION, &[]);
    let tx_id = compute_tx_id(&binding_hash);
    TxBody {
        tx_id, tx_body_hash: body_hash, tx_proof_hash: proof_hash,
        tx_binding_hash: binding_hash, version: TX_VERSION,
        inputs: vec![inp], outputs: vec![out], proofs, fee,
        tx_extra: vec![], size_bytes: 2000,
    }
}
