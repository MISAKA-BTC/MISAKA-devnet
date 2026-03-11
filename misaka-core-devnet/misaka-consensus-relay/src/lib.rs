// ============================================================
// MISAKA Network — Consensus Vote Relay
// ============================================================
//
// Minimal BFT-style consensus message relay on top of existing
// relay/block infrastructure.
//
// Pipeline:
//   proposal → prevote → precommit → commit
//
// Flow:
//   1. Proposer builds block, signs proposal, broadcasts
//   2. Validators receive proposal, validate, prevote for block_hash
//   3. On ≥2/3 prevotes for same block_hash: precommit
//   4. On ≥2/3 precommits for same block_hash: commit via existing pipeline
//   5. Advance to next height
//
// Reuses existing crates:
//   misaka-consensus: Vote, VoteType, ValidatorSet, signing, quorum checks
//   misaka-relay: OutboundAction, PeerId, peer penalties
//   misaka-block: validate_block, apply_block_atomically_trusted, on_block_committed
//   misaka-store: Block, ChainState
//
// ============================================================

use misaka_crypto::falcon;
use misaka_consensus::{
    Vote, VoteType, ValidatorSet,
    create_signed_vote, verify_vote,
};
use misaka_store::{Block, ChainState};
use misaka_mempool::Mempool;
use misaka_block::{
    validate_block, apply_block_atomically_trusted,
    on_block_committed, BlockApplyResult, BlockValidationResult,
};
use misaka_relay::{PeerId, BlockHash, OutboundAction, RelayMessage};
use serde::{Serialize, Deserialize};

use std::collections::HashMap;

pub mod consensus_wal;

// ════════════════════════════════════════════
// Consensus message types
// ════════════════════════════════════════════

/// Domain prefix for proposal signatures.
// Proposal domain now centralized in misaka_crypto::signing::domains.

/// A block proposal from the round's proposer.
#[derive(Debug, Clone)]
pub struct Proposal {
    pub height: u64,
    pub round: u32,
    pub block_hash: BlockHash,
    pub block: Block,
    pub proposer_id: [u8; 32],
    pub signature: Vec<u8>,
}

/// Canonical bytes for proposal signing.
///
/// Delegates to misaka_crypto::signing::proposal_sign_bytes for
/// centralized canonical byte construction and domain separation.
fn proposal_sign_bytes(height: u64, round: u32, block_hash: &BlockHash) -> [u8; 32] {
    misaka_crypto::signing::proposal_sign_bytes(height, round, block_hash)
}

/// A consensus message (proposal or vote).
#[derive(Debug, Clone)]
pub enum ConsensusMessage {
    Proposal(Proposal),
    Prevote(Vote),
    Precommit(Vote),
}

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Invalid proposal signature from {0}")]
    InvalidProposalSignature(String),
    #[error("Invalid prevote signature from {0}")]
    InvalidPrevoteSignature(String),
    #[error("Invalid precommit signature from {0}")]
    InvalidPrecommitSignature(String),
    #[error("Unknown validator: {0}")]
    UnknownValidator(String),
    #[error("Invalid proposer for height {height} round {round}: expected {expected}, got {got}")]
    InvalidProposer { height: u64, round: u32, expected: String, got: String },
    #[error("Duplicate proposal from {0} at height {1} round {2}")]
    DuplicateProposal(String, u64, u32),
    #[error("Conflicting proposal from {0}")]
    ConflictingProposal(String),
    #[error("Duplicate vote from {0}")]
    DuplicateVote(String),
    #[error("Conflicting vote from {voter}: had {existing}, got {new}")]
    ConflictingVote { voter: String, existing: String, new: String },
    #[error("Quorum reached for unknown block: {0}")]
    QuorumForUnknownBlock(String),
    #[error("Commit already done at height {0}")]
    CommitAlreadyDone(u64),
    #[error("Height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },
    #[error("Round mismatch: expected {expected}, got {got}")]
    RoundMismatch { expected: u32, got: u32 },
    #[error("Block validation failed: {0}")]
    BlockValidationFailed(String),
    #[error("Block apply failed: {0}")]
    BlockApplyFailed(String),
    #[error("Falcon error: {0}")]
    FalconError(#[from] falcon::FalconError),
}

/// Penalty reasons specific to consensus misuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusPenalty {
    InvalidProposal,
    InvalidVote,
    InvalidVoteSignature,
    ConflictingVote,
    InvalidProposer,
}

impl ConsensusPenalty {
    pub fn score(self) -> u32 {
        match self {
            Self::InvalidProposal => 40,
            Self::InvalidVote => 20,
            Self::InvalidVoteSignature => 50,
            Self::ConflictingVote => 50,
            Self::InvalidProposer => 30,
        }
    }
}

// ════════════════════════════════════════════
// Configuration
// ════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ConsensusRelayConfig {
    /// Maximum pending proposals/votes to buffer.
    pub max_pending_messages: usize,
    /// Maximum block size (bytes).
    pub max_block_bytes: usize,
}

impl Default for ConsensusRelayConfig {
    fn default() -> Self {
        Self {
            max_pending_messages: 256,
            max_block_bytes: 2 * 1024 * 1024,
        }
    }
}

// ════════════════════════════════════════════
// Counters
// ════════════════════════════════════════════

#[derive(Debug, Default, Clone)]
pub struct ConsensusCounters {
    pub proposals_received: u64,
    pub proposals_accepted: u64,
    pub prevotes_received: u64,
    pub prevotes_accepted: u64,
    pub precommits_received: u64,
    pub precommits_accepted: u64,
    pub prevote_quorums: u64,
    pub precommit_quorums: u64,
    pub blocks_committed: u64,
    pub penalties_applied: u64,
}

// ════════════════════════════════════════════
// WAL event hooks (for future persistence)
// ════════════════════════════════════════════

/// Events emitted by the consensus manager for WAL persistence.
///
/// The node runner should persist these before acting on them.
/// Serializable for WAL binary framing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ConsensusEvent {
    ProposalReceived { height: u64, round: u32, block_hash: BlockHash },
    PrevoteRecorded { height: u64, round: u32, voter: [u8; 32], block_hash: Option<BlockHash> },
    PrecommitRecorded { height: u64, round: u32, voter: [u8; 32], block_hash: Option<BlockHash> },
    PrevoteQuorum { height: u64, round: u32, block_hash: Option<BlockHash> },
    PrecommitQuorum { height: u64, round: u32, block_hash: BlockHash },
    BlockCommitted { height: u64, block_hash: BlockHash },
    HeightAdvanced { new_height: u64 },
}

// ════════════════════════════════════════════
// Round state
// ════════════════════════════════════════════

/// Stored proposal record.
#[derive(Debug, Clone)]
struct ProposalRecord {
    block_hash: BlockHash,
    block: Block,
    proposer_id: [u8; 32],
}

/// Stored vote record.
#[derive(Debug, Clone)]
struct VoteRecord {
    block_hash: Option<BlockHash>,
    signature: Vec<u8>,
}

/// Consensus state for a single height/round.
struct RoundState {
    height: u64,
    round: u32,
    proposal: Option<ProposalRecord>,
    prevotes: HashMap<[u8; 32], VoteRecord>,
    precommits: HashMap<[u8; 32], VoteRecord>,
    prevote_quorum: Option<Option<BlockHash>>,
    precommit_quorum: Option<BlockHash>,
    committed: bool,
    /// Our local prevote for this round (prevent double-voting).
    our_prevote: bool,
    /// Our local precommit for this round (prevent double-voting).
    our_precommit: bool,
}

impl RoundState {
    fn new(height: u64, round: u32) -> Self {
        Self {
            height, round,
            proposal: None,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            prevote_quorum: None,
            precommit_quorum: None,
            committed: false,
            our_prevote: false,
            our_precommit: false,
        }
    }

    fn prevote_count_for(&self, block_hash: &Option<BlockHash>) -> usize {
        self.prevotes.values().filter(|v| v.block_hash == *block_hash).count()
    }

    fn precommit_count_for(&self, block_hash: &Option<BlockHash>) -> usize {
        self.precommits.values().filter(|v| v.block_hash == *block_hash).count()
    }
}

// ════════════════════════════════════════════
// Block candidate store
// ════════════════════════════════════════════

/// Small cache of block candidates by hash, for commit after quorum.
struct BlockCandidateStore {
    blocks: HashMap<BlockHash, Block>,
    max_size: usize,
}

impl BlockCandidateStore {
    fn new(max_size: usize) -> Self {
        Self { blocks: HashMap::new(), max_size }
    }
    fn insert(&mut self, hash: BlockHash, block: Block) {
        if self.blocks.len() >= self.max_size {
            // Evict oldest (arbitrary key)
            if let Some(k) = self.blocks.keys().next().copied() {
                self.blocks.remove(&k);
            }
        }
        self.blocks.insert(hash, block);
    }
    fn get(&self, hash: &BlockHash) -> Option<&Block> {
        self.blocks.get(hash)
    }
    fn remove(&mut self, hash: &BlockHash) {
        self.blocks.remove(hash);
    }
}

// ════════════════════════════════════════════
// Known-message dedup keys
// ════════════════════════════════════════════

/// Key for deduplicating proposals: (height, round, proposer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ProposalKey { height: u64, round: u32, proposer: [u8; 32] }

/// Key for deduplicating votes: (height, round, voter, type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct VoteKey { height: u64, round: u32, voter: [u8; 32], vote_type: u8 }

// ════════════════════════════════════════════
// Consensus manager
// ════════════════════════════════════════════

/// The consensus vote relay manager.
///
/// Handles proposal/vote messages, tracks quorum, triggers commits.
/// Transport-agnostic: produces OutboundAction + ConsensusEvent values.
///
/// WAL integration: if a WAL handle is provided, events are persisted
/// before state mutations for crash recovery safety.
pub struct ConsensusManager {
    config: ConsensusRelayConfig,
    counters: ConsensusCounters,

    /// Current consensus height.
    current_height: u64,
    /// Current round within the height.
    current_round: u32,
    /// Round state for current height/round.
    round_state: RoundState,

    /// Block candidates received via proposals.
    candidates: BlockCandidateStore,

    /// Dedup caches.
    known_proposals: HashMap<ProposalKey, BlockHash>,
    known_votes: HashMap<VoteKey, Option<BlockHash>>,

    /// Optional WAL for crash recovery.
    wal: Option<misaka_wal::event_wal::EventWal>,
}

impl ConsensusManager {
    pub fn new(config: ConsensusRelayConfig, start_height: u64) -> Self {
        Self {
            counters: ConsensusCounters::default(),
            current_height: start_height,
            current_round: 0,
            round_state: RoundState::new(start_height, 0),
            candidates: BlockCandidateStore::new(config.max_pending_messages),
            known_proposals: HashMap::new(),
            known_votes: HashMap::new(),
            wal: None,
            config,
        }
    }

    /// Create with WAL persistence enabled.
    pub fn new_with_wal(
        config: ConsensusRelayConfig,
        start_height: u64,
        wal: misaka_wal::event_wal::EventWal,
    ) -> Self {
        let mut cm = Self::new(config, start_height);
        cm.wal = Some(wal);
        cm
    }

    /// Persist an event to the WAL before state mutation.
    ///
    /// Returns true if the event was successfully persisted (or WAL is disabled).
    /// Returns false if WAL is enabled but the write failed.
    ///
    /// SAFETY: Callers MUST NOT mutate consensus state if this returns false.
    /// The write-ahead invariant requires durable persistence before any
    /// in-memory state change.
    fn wal_append(&mut self, event: &ConsensusEvent) -> bool {
        match self.wal {
            Some(ref mut wal) => wal.append_event(event).is_ok(),
            None => true,
        }
    }

    /// Truncate WAL and write HeightAdvanced as first entry for new height.
    ///
    /// Returns true on success (or WAL disabled). Returns false on failure.
    fn wal_start_height(&mut self, new_height: u64) -> bool {
        let event = ConsensusEvent::HeightAdvanced { new_height };
        match self.wal {
            Some(ref mut wal) => wal.truncate_and_write(&event).is_ok(),
            None => true,
        }
    }

    pub fn counters(&self) -> &ConsensusCounters { &self.counters }
    pub fn current_height(&self) -> u64 { self.current_height }
    pub fn current_round(&self) -> u32 { self.current_round }
    pub fn is_committed(&self) -> bool { self.round_state.committed }

    /// Number of prevotes recorded for current round.
    pub fn prevote_count(&self) -> usize { self.round_state.prevotes.len() }
    /// Number of precommits recorded for current round.
    pub fn precommit_count(&self) -> usize { self.round_state.precommits.len() }

    /// Whether we already cast a prevote this round (anti-equivocation guard).
    pub fn has_our_prevote(&self) -> bool { self.round_state.our_prevote }
    /// Whether we already cast a precommit this round (anti-equivocation guard).
    pub fn has_our_precommit(&self) -> bool { self.round_state.our_precommit }

    // ════════════════════════════════════════════
    // Proposal handling
    // ════════════════════════════════════════════

    /// Handle an incoming proposal.
    ///
    /// Returns outbound actions (rebroadcast) and events (for WAL).
    pub fn handle_proposal(
        &mut self,
        from_peer: PeerId,
        proposal: Proposal,
        validator_set: &ValidatorSet,
    ) -> (Vec<OutboundAction>, Vec<ConsensusEvent>) {
        let mut actions = Vec::new();
        let mut events = Vec::new();
        self.counters.proposals_received += 1;

        // Height/round check
        if proposal.height != self.current_height {
            return (actions, events);
        }
        if proposal.round != self.current_round {
            return (actions, events);
        }

        // Already committed this height
        if self.round_state.committed {
            return (actions, events);
        }

        // Verify proposer is the expected one for this height/round
        let expected_proposer = validator_set.get_proposer(proposal.height, proposal.round);
        if proposal.proposer_id != expected_proposer.fingerprint {
            return (actions, events);
        }

        // Verify proposer is in validator set
        let proposer_info = match validator_set.get_by_fingerprint(&proposal.proposer_id) {
            Some(v) => v,
            None => return (actions, events),
        };

        // Verify signature
        let sign_bytes = proposal_sign_bytes(proposal.height, proposal.round, &proposal.block_hash);
        let sig_valid = falcon::falcon_verify(&proposer_info.falcon_pk, &sign_bytes, &proposal.signature)
            .unwrap_or(false);
        if !sig_valid {
            return (actions, events);
        }

        // Dedup: check if we already have a proposal for this height/round/proposer
        let key = ProposalKey {
            height: proposal.height,
            round: proposal.round,
            proposer: proposal.proposer_id,
        };
        if let Some(existing_hash) = self.known_proposals.get(&key) {
            if *existing_hash != proposal.block_hash {
                // Conflicting proposal — this is equivocation
                return (actions, events);
            }
            // Duplicate — ignore
            return (actions, events);
        }

        // Basic block validation
        let block_hash_recomputed = proposal.block.hash();
        if block_hash_recomputed != proposal.block_hash {
            return (actions, events);
        }

        // SAFETY: persist to WAL BEFORE mutating in-memory state
        self.counters.proposals_accepted += 1;
        let evt = ConsensusEvent::ProposalReceived {
            height: proposal.height,
            round: proposal.round,
            block_hash: proposal.block_hash,
        };
        if !self.wal_append(&evt) {
            return (actions, events); // WAL write failed — abort
        }
        events.push(evt);

        // Now mutate in-memory state
        self.known_proposals.insert(key, proposal.block_hash);
        self.candidates.insert(proposal.block_hash, proposal.block.clone());

        self.round_state.proposal = Some(ProposalRecord {
            block_hash: proposal.block_hash,
            block: proposal.block.clone(),
            proposer_id: proposal.proposer_id,
        });

        // Rebroadcast proposal to other peers
        actions.push(OutboundAction::Broadcast {
            exclude: Some(from_peer),
            msg: RelayMessage::BlockMsg { block: Box::new(proposal.block) },
        });

        (actions, events)
    }

    // ════════════════════════════════════════════
    // Vote handling
    // ════════════════════════════════════════════

    /// Handle an incoming prevote.
    pub fn handle_prevote(
        &mut self,
        from_peer: PeerId,
        vote: Vote,
        validator_set: &ValidatorSet,
    ) -> (Vec<OutboundAction>, Vec<ConsensusEvent>) {
        self.handle_vote(from_peer, vote, VoteType::Prevote, validator_set)
    }

    /// Handle an incoming precommit.
    pub fn handle_precommit(
        &mut self,
        from_peer: PeerId,
        vote: Vote,
        validator_set: &ValidatorSet,
    ) -> (Vec<OutboundAction>, Vec<ConsensusEvent>) {
        self.handle_vote(from_peer, vote, VoteType::Precommit, validator_set)
    }

    fn handle_vote(
        &mut self,
        _from_peer: PeerId,
        vote: Vote,
        expected_type: VoteType,
        validator_set: &ValidatorSet,
    ) -> (Vec<OutboundAction>, Vec<ConsensusEvent>) {
        let actions = Vec::new();
        let mut events = Vec::new();

        // Type check
        if vote.vote_type != expected_type {
            return (actions, events);
        }

        match expected_type {
            VoteType::Prevote => self.counters.prevotes_received += 1,
            VoteType::Precommit => self.counters.precommits_received += 1,
        }

        // Height/round check
        if vote.height != self.current_height || vote.round != self.current_round {
            return (actions, events);
        }
        if self.round_state.committed {
            return (actions, events);
        }

        // Verify voter is in validator set
        if !validator_set.contains(&vote.voter_id) {
            return (actions, events);
        }

        // Verify signature
        if !verify_vote(&vote, validator_set) {
            return (actions, events);
        }

        // Dedup / conflict detection
        let vk = VoteKey {
            height: vote.height,
            round: vote.round,
            voter: vote.voter_id,
            vote_type: expected_type as u8,
        };
        if let Some(existing_hash) = self.known_votes.get(&vk) {
            if *existing_hash != vote.block_hash {
                // Conflicting vote — equivocation
                return (actions, events);
            }
            // Duplicate — ignore
            return (actions, events);
        }

        // SAFETY: persist to WAL BEFORE mutating in-memory state
        let record = VoteRecord {
            block_hash: vote.block_hash,
            signature: vote.signature.clone(),
        };

        match expected_type {
            VoteType::Prevote => {
                self.counters.prevotes_accepted += 1;
                let evt = ConsensusEvent::PrevoteRecorded {
                    height: vote.height, round: vote.round,
                    voter: vote.voter_id, block_hash: vote.block_hash,
                };
                if !self.wal_append(&evt) {
                    return (actions, events); // WAL write failed — abort
                }
                events.push(evt);

                // Now mutate state
                self.known_votes.insert(vk, vote.block_hash);
                self.round_state.prevotes.insert(vote.voter_id, record);

                // Check prevote quorum
                if self.round_state.prevote_quorum.is_none() {
                    self.check_prevote_quorum(validator_set, &mut events);
                }
            }
            VoteType::Precommit => {
                self.counters.precommits_accepted += 1;
                let evt = ConsensusEvent::PrecommitRecorded {
                    height: vote.height, round: vote.round,
                    voter: vote.voter_id, block_hash: vote.block_hash,
                };
                if !self.wal_append(&evt) {
                    return (actions, events); // WAL write failed — abort
                }
                events.push(evt);

                // Now mutate state
                self.known_votes.insert(vk, vote.block_hash);
                self.round_state.precommits.insert(vote.voter_id, record);

                // Check precommit quorum
                if self.round_state.precommit_quorum.is_none() {
                    self.check_precommit_quorum(validator_set, &mut events);
                }
            }
        }

        // Rebroadcast valid vote (as a NewBlock hint, actual vote not in RelayMessage yet)
        // In practice the transport would serialize the vote directly.
        // For now we don't add vote-specific RelayMessage variants to avoid
        // changing the relay crate — the caller can handle this.

        (actions, events)
    }

    fn check_prevote_quorum(
        &mut self,
        validator_set: &ValidatorSet,
        events: &mut Vec<ConsensusEvent>,
    ) {
        let quorum = validator_set.quorum();

        let mut tally: HashMap<Option<BlockHash>, usize> = HashMap::new();
        for vr in self.round_state.prevotes.values() {
            *tally.entry(vr.block_hash).or_insert(0) += 1;
        }

        for (bh, count) in &tally {
            if *count >= quorum {
                self.counters.prevote_quorums += 1;
                let evt = ConsensusEvent::PrevoteQuorum {
                    height: self.current_height,
                    round: self.current_round,
                    block_hash: *bh,
                };
                if !self.wal_append(&evt) {
                    return; // WAL write failed — do not mark quorum
                }
                events.push(evt);
                // State mutation after WAL
                self.round_state.prevote_quorum = Some(*bh);
                return;
            }
        }
    }

    fn check_precommit_quorum(
        &mut self,
        validator_set: &ValidatorSet,
        events: &mut Vec<ConsensusEvent>,
    ) {
        let quorum = validator_set.quorum();

        let mut tally: HashMap<Option<BlockHash>, usize> = HashMap::new();
        for vr in self.round_state.precommits.values() {
            *tally.entry(vr.block_hash).or_insert(0) += 1;
        }

        for (bh, count) in &tally {
            if *count >= quorum {
                if let Some(hash) = bh {
                    self.counters.precommit_quorums += 1;
                    let evt = ConsensusEvent::PrecommitQuorum {
                        height: self.current_height,
                        round: self.current_round,
                        block_hash: *hash,
                    };
                    if !self.wal_append(&evt) {
                        return; // WAL write failed — do not mark quorum
                    }
                    events.push(evt);
                    // State mutation after WAL
                    self.round_state.precommit_quorum = Some(*hash);
                }
                return;
            }
        }
    }

    // ════════════════════════════════════════════
    // Commit trigger
    // ════════════════════════════════════════════

    /// Try to commit after precommit quorum is reached.
    ///
    /// Commit safety:
    ///   1. Write BlockCommitted to WAL + fsync
    ///   2. Apply block to state store
    ///   3. Mempool cleanup
    ///
    /// If crash between 1 and 2: recovery replays BlockCommitted and re-applies.
    /// If crash before 1: block not committed, safe to retry.
    pub fn try_commit(
        &mut self,
        state: &mut ChainState,
        mempool: &mut Mempool,
    ) -> (bool, Vec<ConsensusEvent>) {
        let mut events = Vec::new();

        if self.round_state.committed {
            return (false, events);
        }

        let block_hash = match self.round_state.precommit_quorum {
            Some(bh) => bh,
            None => return (false, events),
        };

        // Get the block
        let block = match self.candidates.get(&block_hash) {
            Some(b) => b.clone(),
            None => return (false, events), // pending — block not yet available
        };

        // Validate
        let expected_height = if *state.tip_hash() == [0u8; 32] { 0 } else { state.tip_height() + 1 };
        let validation = validate_block(
            &block, expected_height, state.tip_hash(), self.config.max_block_bytes,
        );
        if let BlockValidationResult::Invalid(_) = validation {
            return (false, events);
        }

        // COMMIT SAFETY: write to WAL BEFORE applying to state.
        // If this fails, do NOT commit — the block was not durably recorded.
        let commit_event = ConsensusEvent::BlockCommitted {
            height: self.current_height,
            block_hash,
        };
        if !self.wal_append(&commit_event) {
            return (false, events); // WAL write failed — cannot safely commit
        }

        // Apply atomically
        let result = apply_block_atomically_trusted(&block, state);
        if let BlockApplyResult::Applied { .. } = result {
            on_block_committed(&block, mempool);
            self.round_state.committed = true;
            self.counters.blocks_committed += 1;
            events.push(commit_event);
        }

        (self.round_state.committed, events)
    }

    // ════════════════════════════════════════════
    // Height advancement
    // ════════════════════════════════════════════

    /// Advance to the next height after a successful commit.
    ///
    /// SAFETY: Persists HeightAdvanced to WAL BEFORE mutating state.
    /// Truncates old WAL entries for the new height.
    pub fn advance_height(&mut self) -> Vec<ConsensusEvent> {
        let mut events = Vec::new();

        if !self.round_state.committed {
            return events;
        }

        let new_height = self.current_height + 1;

        // SAFETY: WAL write BEFORE state mutation
        let evt = ConsensusEvent::HeightAdvanced { new_height };
        if !self.wal_start_height(new_height) {
            return events; // WAL write failed — do not advance
        }
        events.push(evt);

        // Now mutate in-memory state
        self.current_height = new_height;
        self.current_round = 0;
        self.round_state = RoundState::new(self.current_height, 0);
        self.known_proposals.clear();
        self.known_votes.clear();

        events
    }

    // ════════════════════════════════════════════
    // WAL recovery
    // ════════════════════════════════════════════

    /// Recover consensus state from a WAL file.
    ///
    /// Replays all persisted ConsensusEvents to reconstruct internal state.
    /// Does NOT produce side effects (no rebroadcast, no mempool cleanup,
    /// no block proposal). Recovery only reconstructs consensus state.
    ///
    /// `local_validator_id`: our own fingerprint, used to detect our own
    /// votes in the WAL and set `our_prevote`/`our_precommit` flags
    /// (prevents double-voting after crash recovery).
    ///
    /// After recovery, the node should resume normal operation.
    /// Returns None if the WAL is empty or missing.
    pub fn recover_from_wal(
        config: ConsensusRelayConfig,
        wal_path: &std::path::Path,
        local_validator_id: Option<[u8; 32]>,
    ) -> Result<Option<Self>, String> {
        let events: Vec<ConsensusEvent> = misaka_wal::event_wal::replay_events(wal_path)
            .map_err(|e| format!("WAL replay error: {}", e))?;

        if events.is_empty() {
            return Ok(None);
        }

        // Determine starting height from events
        let mut height: u64 = 0;
        let mut round: u32 = 0;
        for event in &events {
            match event {
                ConsensusEvent::HeightAdvanced { new_height } => {
                    height = *new_height;
                    round = 0;
                }
                ConsensusEvent::ProposalReceived { height: h, round: r, .. } => {
                    height = *h;
                    round = *r;
                }
                _ => {}
            }
        }

        let mut cm = Self::new(config, height);
        cm.current_round = round;
        cm.round_state = RoundState::new(height, round);

        // Replay events to reconstruct state
        for event in &events {
            match event {
                ConsensusEvent::HeightAdvanced { new_height } => {
                    cm.current_height = *new_height;
                    cm.current_round = 0;
                    cm.round_state = RoundState::new(*new_height, 0);
                    cm.known_proposals.clear();
                    cm.known_votes.clear();
                }
                ConsensusEvent::ProposalReceived { height: h, round: r, block_hash } => {
                    if *h == cm.current_height && *r == cm.current_round {
                        let key = ProposalKey {
                            height: *h, round: *r,
                            proposer: [0; 32], // proposer not stored in event; dedup key partial
                        };
                        cm.known_proposals.insert(key, *block_hash);
                        // Note: block body not in event — caller must re-fetch if needed
                    }
                }
                ConsensusEvent::PrevoteRecorded { height: h, round: r, voter, block_hash } => {
                    if *h == cm.current_height && *r == cm.current_round {
                        let vk = VoteKey {
                            height: *h, round: *r, voter: *voter,
                            vote_type: VoteType::Prevote as u8,
                        };
                        cm.known_votes.insert(vk, *block_hash);
                        cm.round_state.prevotes.insert(*voter, VoteRecord {
                            block_hash: *block_hash,
                            signature: Vec::new(),
                        });
                        // If this is our own vote, restore the anti-equivocation flag
                        if local_validator_id.as_ref() == Some(voter) {
                            cm.round_state.our_prevote = true;
                        }
                    }
                }
                ConsensusEvent::PrecommitRecorded { height: h, round: r, voter, block_hash } => {
                    if *h == cm.current_height && *r == cm.current_round {
                        let vk = VoteKey {
                            height: *h, round: *r, voter: *voter,
                            vote_type: VoteType::Precommit as u8,
                        };
                        cm.known_votes.insert(vk, *block_hash);
                        cm.round_state.precommits.insert(*voter, VoteRecord {
                            block_hash: *block_hash,
                            signature: Vec::new(),
                        });
                        // If this is our own vote, restore the anti-equivocation flag
                        if local_validator_id.as_ref() == Some(voter) {
                            cm.round_state.our_precommit = true;
                        }
                    }
                }
                ConsensusEvent::PrevoteQuorum { height: h, round: r, block_hash } => {
                    if *h == cm.current_height && *r == cm.current_round {
                        cm.round_state.prevote_quorum = Some(*block_hash);
                    }
                }
                ConsensusEvent::PrecommitQuorum { height: h, round: r, block_hash } => {
                    if *h == cm.current_height && *r == cm.current_round {
                        cm.round_state.precommit_quorum = Some(*block_hash);
                    }
                }
                ConsensusEvent::BlockCommitted { height: h, .. } => {
                    if *h == cm.current_height {
                        cm.round_state.committed = true;
                    }
                }
            }
        }

        // Re-open WAL for append (future events will be appended)
        match misaka_wal::event_wal::EventWal::open(wal_path) {
            Ok(wal) => cm.wal = Some(wal),
            Err(_) => {} // Continue without WAL on error
        }

        Ok(Some(cm))
    }

    // ════════════════════════════════════════════
    // Local validator actions
    // ════════════════════════════════════════════

    /// Create a proposal (local proposer).
    ///
    /// Persists ProposalReceived to WAL before storing in memory.
    /// Returns the signed proposal and outbound broadcast action.
    pub fn create_proposal(
        &mut self,
        block: Block,
        proposer_id: [u8; 32],
        falcon_sk: &[u8],
    ) -> Result<(Proposal, Vec<OutboundAction>), ConsensusError> {
        let block_hash = block.hash();
        let sign_bytes = proposal_sign_bytes(self.current_height, self.current_round, &block_hash);
        let signature = falcon::falcon_sign(falcon_sk, &sign_bytes)?;

        let proposal = Proposal {
            height: self.current_height,
            round: self.current_round,
            block_hash,
            block: block.clone(),
            proposer_id,
            signature,
        };

        // SAFETY: WAL write BEFORE state mutation
        let evt = ConsensusEvent::ProposalReceived {
            height: self.current_height,
            round: self.current_round,
            block_hash,
        };
        // Best-effort for proposal (not anti-equivocation critical like votes)
        self.wal_append(&evt);

        // Store locally
        self.candidates.insert(block_hash, block.clone());
        self.round_state.proposal = Some(ProposalRecord {
            block_hash,
            block,
            proposer_id,
        });

        let key = ProposalKey {
            height: self.current_height,
            round: self.current_round,
            proposer: proposer_id,
        };
        self.known_proposals.insert(key, block_hash);

        let actions = vec![OutboundAction::Broadcast {
            exclude: None,
            msg: RelayMessage::NewBlock { block_hash, height: self.current_height },
        }];

        Ok((proposal, actions))
    }

    /// Create a prevote for the current round.
    ///
    /// SAFETY: Persists PrevoteRecorded to WAL BEFORE setting our_prevote flag.
    /// This prevents double-voting: if crash after WAL write but before flag,
    /// recovery replays the vote and sets our_prevote = true.
    ///
    /// Returns None if we already prevoted this round.
    pub fn create_prevote(
        &mut self,
        block_hash: Option<BlockHash>,
        voter_id: [u8; 32],
        falcon_sk: &[u8],
    ) -> Result<Option<(Vote, Vec<OutboundAction>)>, ConsensusError> {
        if self.round_state.our_prevote {
            return Ok(None);
        }

        let vote = create_signed_vote(
            VoteType::Prevote,
            self.current_height,
            self.current_round,
            block_hash,
            voter_id,
            falcon_sk,
        )?;

        // SAFETY: WAL write BEFORE state mutation
        let evt = ConsensusEvent::PrevoteRecorded {
            height: self.current_height,
            round: self.current_round,
            voter: voter_id,
            block_hash,
        };
        if !self.wal_append(&evt) {
            // WAL write failed — do not mark as voted
            return Ok(None);
        }

        // Now mutate state
        self.round_state.our_prevote = true;

        let vk = VoteKey {
            height: self.current_height,
            round: self.current_round,
            voter: voter_id,
            vote_type: VoteType::Prevote as u8,
        };
        self.known_votes.insert(vk, block_hash);
        self.round_state.prevotes.insert(voter_id, VoteRecord {
            block_hash,
            signature: vote.signature.clone(),
        });

        let actions = vec![]; // caller broadcasts via transport
        Ok(Some((vote, actions)))
    }

    /// Create a precommit for the current round.
    ///
    /// SAFETY: Persists PrecommitRecorded to WAL BEFORE setting our_precommit flag.
    /// Returns None if we already precommitted this round.
    pub fn create_precommit(
        &mut self,
        block_hash: Option<BlockHash>,
        voter_id: [u8; 32],
        falcon_sk: &[u8],
    ) -> Result<Option<(Vote, Vec<OutboundAction>)>, ConsensusError> {
        if self.round_state.our_precommit {
            return Ok(None);
        }

        let vote = create_signed_vote(
            VoteType::Precommit,
            self.current_height,
            self.current_round,
            block_hash,
            voter_id,
            falcon_sk,
        )?;

        // SAFETY: WAL write BEFORE state mutation
        let evt = ConsensusEvent::PrecommitRecorded {
            height: self.current_height,
            round: self.current_round,
            voter: voter_id,
            block_hash,
        };
        if !self.wal_append(&evt) {
            return Ok(None); // WAL write failed — do not mark as voted
        }

        // Now mutate state
        self.round_state.our_precommit = true;

        let vk = VoteKey {
            height: self.current_height,
            round: self.current_round,
            voter: voter_id,
            vote_type: VoteType::Precommit as u8,
        };
        self.known_votes.insert(vk, block_hash);
        self.round_state.precommits.insert(voter_id, VoteRecord {
            block_hash,
            signature: vote.signature.clone(),
        });

        let actions = vec![];
        Ok(Some((vote, actions)))
    }

    /// Check if prevote quorum has been reached and return the block hash.
    pub fn prevote_quorum_hash(&self) -> Option<Option<BlockHash>> {
        self.round_state.prevote_quorum
    }

    /// Check if precommit quorum has been reached and return the block hash.
    pub fn precommit_quorum_hash(&self) -> Option<BlockHash> {
        self.round_state.precommit_quorum
    }

    /// Check if proposal is available for current round.
    pub fn has_proposal(&self) -> bool {
        self.round_state.proposal.is_some()
    }

    /// Get the proposed block hash if available.
    pub fn proposal_block_hash(&self) -> Option<BlockHash> {
        self.round_state.proposal.as_ref().map(|p| p.block_hash)
    }

    // ════════════════════════════════════════════
    // WAL recovery: replay events without side effects
    // ════════════════════════════════════════════

    /// Replay a consensus event to reconstruct internal state.
    ///
    /// Called during recovery from WAL. Does NOT:
    ///   - verify signatures
    ///   - produce outbound actions (no rebroadcast)
    ///   - trigger block commits (caller handles post-recovery commit)
    ///   - clean mempool
    ///
    /// Events must be replayed in order of original recording.
    pub fn replay_event(&mut self, event: &ConsensusEvent) {
        match event {
            ConsensusEvent::ProposalReceived { height, round, block_hash } => {
                if *height == self.current_height && *round == self.current_round {
                    // We don't have the full block in the event, so mark proposal
                    // as known. The block candidate must be restored separately
                    // if needed for commit.
                    let key = ProposalKey {
                        height: *height,
                        round: *round,
                        proposer: [0u8; 32], // proposer not in event; use placeholder
                    };
                    self.known_proposals.insert(key, *block_hash);
                }
            }
            ConsensusEvent::PrevoteRecorded { height, round, voter, block_hash } => {
                if *height == self.current_height && *round == self.current_round {
                    let vk = VoteKey {
                        height: *height,
                        round: *round,
                        voter: *voter,
                        vote_type: VoteType::Prevote as u8,
                    };
                    self.known_votes.insert(vk, *block_hash);
                    self.round_state.prevotes.insert(*voter, VoteRecord {
                        block_hash: *block_hash,
                        signature: Vec::new(), // signature not in event
                    });
                }
            }
            ConsensusEvent::PrecommitRecorded { height, round, voter, block_hash } => {
                if *height == self.current_height && *round == self.current_round {
                    let vk = VoteKey {
                        height: *height,
                        round: *round,
                        voter: *voter,
                        vote_type: VoteType::Precommit as u8,
                    };
                    self.known_votes.insert(vk, *block_hash);
                    self.round_state.precommits.insert(*voter, VoteRecord {
                        block_hash: *block_hash,
                        signature: Vec::new(),
                    });
                }
            }
            ConsensusEvent::PrevoteQuorum { height, round, block_hash } => {
                if *height == self.current_height && *round == self.current_round {
                    self.round_state.prevote_quorum = Some(*block_hash);
                    self.round_state.our_prevote = true; // we must have prevoted
                }
            }
            ConsensusEvent::PrecommitQuorum { height, round, block_hash } => {
                if *height == self.current_height && *round == self.current_round {
                    self.round_state.precommit_quorum = Some(*block_hash);
                    self.round_state.our_precommit = true; // we must have precommitted
                }
            }
            ConsensusEvent::BlockCommitted { height, block_hash } => {
                if *height == self.current_height {
                    self.round_state.committed = true;
                    self.round_state.precommit_quorum = Some(*block_hash);
                }
            }
            ConsensusEvent::HeightAdvanced { new_height } => {
                self.current_height = *new_height;
                self.current_round = 0;
                self.round_state = RoundState::new(*new_height, 0);
                self.known_proposals.clear();
                self.known_votes.clear();
            }
        }
    }

    /// Replay a sequence of events (recovery from WAL).
    pub fn replay_events(&mut self, events: &[ConsensusEvent]) {
        for event in events {
            self.replay_event(event);
        }
    }
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::falcon::{falcon_keygen, FalconKeyPair};
    use misaka_verify::ValidatorInfo;
    use misaka_store::{BlockHeader, Block, ChainState};
    use misaka_mempool::Mempool;

    // ── Helpers ──

    /// Generate N validator keypairs and infos.
    fn gen_validators(n: usize) -> Vec<(FalconKeyPair, ValidatorInfo)> {
        (0..n).map(|_| {
            let kp = falcon_keygen().unwrap();
            let info = ValidatorInfo {
                fingerprint: kp.fingerprint,
                falcon_pk: kp.public_key.clone(),
            };
            (kp, info)
        }).collect()
    }

    fn make_validator_set(vals: &[(FalconKeyPair, ValidatorInfo)]) -> ValidatorSet {
        let infos: Vec<ValidatorInfo> = vals.iter().map(|(_, info)| ValidatorInfo {
            fingerprint: info.fingerprint,
            falcon_pk: info.falcon_pk.clone(),
        }).collect();
        ValidatorSet::new(infos).unwrap()
    }

    fn make_block_simple(height: u64, prev_hash: [u8; 32]) -> Block {
        Block {
            header: BlockHeader {
                version: 2, height, round: 0, prev_hash, timestamp: 1000,
                tx_merkle_root: [0u8; 32], utxo_root: [0; 32], link_tag_root: [0; 32],
                proposer_id: [0xAA; 32], proposer_sig: vec![], bft_sigs: vec![],
            },
            transactions: vec![],
        }
    }

    fn seeded_chain_state() -> ChainState {
        ChainState::genesis()
    }

    // ════════════════════════════════════════════
    // Proposal tests
    // ════════════════════════════════════════════

    #[test]
    fn test_valid_proposal_accepted() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let proposer = vs.get_proposer(0, 0);
        let proposer_kp = vals.iter().find(|(_, i)| i.fingerprint == proposer.fingerprint).unwrap();

        let block = make_block_simple(0, [0u8; 32]);
        let block_hash = block.hash();
        let sign_bytes = proposal_sign_bytes(0, 0, &block_hash);
        let sig = falcon::falcon_sign(&proposer_kp.0.secret_key, &sign_bytes).unwrap();

        let proposal = Proposal {
            height: 0, round: 0, block_hash, block,
            proposer_id: proposer.fingerprint, signature: sig,
        };

        let (actions, events) = cm.handle_proposal(1, proposal, &vs);
        assert_eq!(cm.counters.proposals_accepted, 1);
        assert!(cm.has_proposal());
        assert_eq!(cm.proposal_block_hash(), Some(block_hash));
        assert!(events.iter().any(|e| matches!(e, ConsensusEvent::ProposalReceived { .. })));
    }

    #[test]
    fn test_invalid_proposer_signature_rejected() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let proposer = vs.get_proposer(0, 0);
        let block = make_block_simple(0, [0u8; 32]);
        let block_hash = block.hash();

        let proposal = Proposal {
            height: 0, round: 0, block_hash, block,
            proposer_id: proposer.fingerprint,
            signature: vec![0u8; 100], // bad signature
        };

        let (_, events) = cm.handle_proposal(1, proposal, &vs);
        assert_eq!(cm.counters.proposals_accepted, 0);
        assert!(!cm.has_proposal());
    }

    #[test]
    fn test_conflicting_proposal_rejected() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let proposer = vs.get_proposer(0, 0);
        let proposer_kp = vals.iter().find(|(_, i)| i.fingerprint == proposer.fingerprint).unwrap();

        // First proposal
        let block1 = make_block_simple(0, [0u8; 32]);
        let bh1 = block1.hash();
        let sig1 = falcon::falcon_sign(
            &proposer_kp.0.secret_key,
            &proposal_sign_bytes(0, 0, &bh1),
        ).unwrap();
        let p1 = Proposal {
            height: 0, round: 0, block_hash: bh1, block: block1,
            proposer_id: proposer.fingerprint, signature: sig1,
        };
        cm.handle_proposal(1, p1, &vs);
        assert_eq!(cm.counters.proposals_accepted, 1);

        // Second conflicting proposal (different block)
        let mut block2 = make_block_simple(0, [0u8; 32]);
        block2.header.timestamp = 9999; // different block
        let bh2 = block2.hash();
        let sig2 = falcon::falcon_sign(
            &proposer_kp.0.secret_key,
            &proposal_sign_bytes(0, 0, &bh2),
        ).unwrap();
        let p2 = Proposal {
            height: 0, round: 0, block_hash: bh2, block: block2,
            proposer_id: proposer.fingerprint, signature: sig2,
        };
        let (_, events) = cm.handle_proposal(1, p2, &vs);
        // Should be rejected (conflicting)
        assert_eq!(cm.counters.proposals_accepted, 1);
    }

    // ════════════════════════════════════════════
    // Prevote tests
    // ════════════════════════════════════════════

    #[test]
    fn test_valid_prevote_counted() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let bh = [0xAA; 32];
        let vote = create_signed_vote(
            VoteType::Prevote, 0, 0, Some(bh),
            vals[0].0.fingerprint, &vals[0].0.secret_key,
        ).unwrap();

        let (_, events) = cm.handle_prevote(1, vote, &vs);
        assert_eq!(cm.counters.prevotes_accepted, 1);
        assert_eq!(cm.prevote_count(), 1);
        assert!(events.iter().any(|e| matches!(e, ConsensusEvent::PrevoteRecorded { .. })));
    }

    #[test]
    fn test_duplicate_prevote_ignored() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let bh = [0xAA; 32];
        let vote = create_signed_vote(
            VoteType::Prevote, 0, 0, Some(bh),
            vals[0].0.fingerprint, &vals[0].0.secret_key,
        ).unwrap();

        cm.handle_prevote(1, vote.clone(), &vs);
        cm.handle_prevote(2, vote, &vs);
        assert_eq!(cm.counters.prevotes_accepted, 1); // second is duplicate
        assert_eq!(cm.prevote_count(), 1);
    }

    #[test]
    fn test_conflicting_prevote_rejected() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let vote1 = create_signed_vote(
            VoteType::Prevote, 0, 0, Some([0xAA; 32]),
            vals[0].0.fingerprint, &vals[0].0.secret_key,
        ).unwrap();
        let vote2 = create_signed_vote(
            VoteType::Prevote, 0, 0, Some([0xBB; 32]),
            vals[0].0.fingerprint, &vals[0].0.secret_key,
        ).unwrap();

        cm.handle_prevote(1, vote1, &vs);
        cm.handle_prevote(2, vote2, &vs);
        assert_eq!(cm.counters.prevotes_accepted, 1); // conflicting rejected
    }

    #[test]
    fn test_prevote_quorum_detected() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let bh = [0xAA; 32];
        let quorum = vs.quorum(); // 7

        for i in 0..quorum {
            let vote = create_signed_vote(
                VoteType::Prevote, 0, 0, Some(bh),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            cm.handle_prevote((i + 1) as u64, vote, &vs);
        }

        assert_eq!(cm.counters.prevote_quorums, 1);
        assert_eq!(cm.prevote_quorum_hash(), Some(Some(bh)));
    }

    // ════════════════════════════════════════════
    // Precommit tests
    // ════════════════════════════════════════════

    #[test]
    fn test_valid_precommit_counted() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let bh = [0xBB; 32];
        let vote = create_signed_vote(
            VoteType::Precommit, 0, 0, Some(bh),
            vals[0].0.fingerprint, &vals[0].0.secret_key,
        ).unwrap();

        let (_, events) = cm.handle_precommit(1, vote, &vs);
        assert_eq!(cm.counters.precommits_accepted, 1);
    }

    #[test]
    fn test_precommit_quorum_triggers_commit_event() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let bh = [0xBB; 32];
        let quorum = vs.quorum();

        let mut all_events = Vec::new();
        for i in 0..quorum {
            let vote = create_signed_vote(
                VoteType::Precommit, 0, 0, Some(bh),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            let (_, events) = cm.handle_precommit((i + 1) as u64, vote, &vs);
            all_events.extend(events);
        }

        assert_eq!(cm.counters.precommit_quorums, 1);
        assert_eq!(cm.precommit_quorum_hash(), Some(bh));
        assert!(all_events.iter().any(|e| matches!(e, ConsensusEvent::PrecommitQuorum { .. })));
    }

    // ════════════════════════════════════════════
    // Commit pipeline tests
    // ════════════════════════════════════════════

    #[test]
    fn test_commit_after_quorum_with_known_block() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);
        let mut state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();

        let block = make_block_simple(0, [0u8; 32]);
        let bh = block.hash();

        // Store the block candidate
        cm.candidates.insert(bh, block);

        // Reach precommit quorum
        let quorum = vs.quorum();
        for i in 0..quorum {
            let vote = create_signed_vote(
                VoteType::Precommit, 0, 0, Some(bh),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            cm.handle_precommit((i + 1) as u64, vote, &vs);
        }

        assert!(cm.precommit_quorum_hash().is_some());

        // Commit
        let (committed, events) = cm.try_commit(&mut state, &mut mempool);
        assert!(committed);
        assert!(cm.is_committed());
        assert_eq!(cm.counters.blocks_committed, 1);
        assert!(events.iter().any(|e| matches!(e, ConsensusEvent::BlockCommitted { .. })));
    }

    #[test]
    fn test_commit_only_once_per_height() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);
        let mut state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();

        let block = make_block_simple(0, [0u8; 32]);
        let bh = block.hash();
        cm.candidates.insert(bh, block);

        let quorum = vs.quorum();
        for i in 0..quorum {
            let vote = create_signed_vote(
                VoteType::Precommit, 0, 0, Some(bh),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            cm.handle_precommit((i + 1) as u64, vote, &vs);
        }

        let (first, _) = cm.try_commit(&mut state, &mut mempool);
        assert!(first);
        let (second, _) = cm.try_commit(&mut state, &mut mempool);
        assert!(!second);
        assert_eq!(cm.counters.blocks_committed, 1);
    }

    #[test]
    fn test_quorum_for_unknown_block_stays_pending() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);
        let mut state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();

        let bh = [0xDD; 32]; // no block stored for this hash

        let quorum = vs.quorum();
        for i in 0..quorum {
            let vote = create_signed_vote(
                VoteType::Precommit, 0, 0, Some(bh),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            cm.handle_precommit((i + 1) as u64, vote, &vs);
        }

        assert!(cm.precommit_quorum_hash().is_some());
        let (committed, _) = cm.try_commit(&mut state, &mut mempool);
        assert!(!committed); // block not available
    }

    #[test]
    fn test_next_height_initialized() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);
        let mut state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();

        let block = make_block_simple(0, [0u8; 32]);
        let bh = block.hash();
        cm.candidates.insert(bh, block);

        let quorum = vs.quorum();
        for i in 0..quorum {
            let vote = create_signed_vote(
                VoteType::Precommit, 0, 0, Some(bh),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            cm.handle_precommit((i + 1) as u64, vote, &vs);
        }

        cm.try_commit(&mut state, &mut mempool);
        let events = cm.advance_height();

        assert_eq!(cm.current_height(), 1);
        assert_eq!(cm.current_round(), 0);
        assert!(!cm.is_committed());
        assert_eq!(cm.prevote_count(), 0);
        assert_eq!(cm.precommit_count(), 0);
        assert!(events.iter().any(|e| matches!(e, ConsensusEvent::HeightAdvanced { new_height: 1 })));
    }

    // ════════════════════════════════════════════
    // Local validator tests
    // ════════════════════════════════════════════

    #[test]
    fn test_create_proposal() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let proposer = vs.get_proposer(0, 0);
        let proposer_kp = vals.iter().find(|(_, i)| i.fingerprint == proposer.fingerprint).unwrap();

        let block = make_block_simple(0, [0u8; 32]);
        let (proposal, actions) = cm.create_proposal(
            block.clone(), proposer.fingerprint, &proposer_kp.0.secret_key,
        ).unwrap();

        assert_eq!(proposal.height, 0);
        assert_eq!(proposal.round, 0);
        assert!(cm.has_proposal());

        // Verify signature
        let sign_bytes = proposal_sign_bytes(0, 0, &proposal.block_hash);
        let valid = falcon::falcon_verify(
            &proposer_kp.0.public_key, &sign_bytes, &proposal.signature,
        ).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_create_prevote_only_once() {
        let vals = gen_validators(10);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let bh = [0xAA; 32];
        let result1 = cm.create_prevote(
            Some(bh), vals[0].0.fingerprint, &vals[0].0.secret_key,
        ).unwrap();
        assert!(result1.is_some());

        let result2 = cm.create_prevote(
            Some(bh), vals[0].0.fingerprint, &vals[0].0.secret_key,
        ).unwrap();
        assert!(result2.is_none()); // already prevoted
    }

    #[test]
    fn test_create_precommit_only_once() {
        let vals = gen_validators(10);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        let bh = [0xBB; 32];
        let result1 = cm.create_precommit(
            Some(bh), vals[0].0.fingerprint, &vals[0].0.secret_key,
        ).unwrap();
        assert!(result1.is_some());

        let result2 = cm.create_precommit(
            Some(bh), vals[0].0.fingerprint, &vals[0].0.secret_key,
        ).unwrap();
        assert!(result2.is_none());
    }

    // ════════════════════════════════════════════
    // Full integration: proposal → prevote → precommit → commit
    // ════════════════════════════════════════════

    #[test]
    fn test_full_consensus_round() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);
        let mut state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();

        // 1. Proposer creates proposal
        let proposer = vs.get_proposer(0, 0);
        let proposer_kp = vals.iter().find(|(_, i)| i.fingerprint == proposer.fingerprint).unwrap();

        let block = make_block_simple(0, [0u8; 32]);
        let (proposal, _) = cm.create_proposal(
            block, proposer.fingerprint, &proposer_kp.0.secret_key,
        ).unwrap();
        let block_hash = proposal.block_hash;

        // 2. Other validators receive proposal + prevote
        // (in a real system, handle_proposal would be called on each validator)
        let quorum = vs.quorum(); // 7

        // Simulate: quorum validators prevote for this block
        for i in 0..quorum {
            let vote = create_signed_vote(
                VoteType::Prevote, 0, 0, Some(block_hash),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            cm.handle_prevote((i + 1) as u64, vote, &vs);
        }

        // 3. Prevote quorum should be reached
        assert_eq!(cm.prevote_quorum_hash(), Some(Some(block_hash)));

        // 4. Validators precommit
        for i in 0..quorum {
            let vote = create_signed_vote(
                VoteType::Precommit, 0, 0, Some(block_hash),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            cm.handle_precommit((i + 1) as u64, vote, &vs);
        }

        // 5. Precommit quorum reached
        assert_eq!(cm.precommit_quorum_hash(), Some(block_hash));

        // 6. Commit
        let (committed, events) = cm.try_commit(&mut state, &mut mempool);
        assert!(committed);
        assert!(events.iter().any(|e| matches!(e, ConsensusEvent::BlockCommitted { .. })));

        // 7. Advance height
        let adv_events = cm.advance_height();
        assert_eq!(cm.current_height(), 1);
        assert!(!cm.is_committed());

        // State should have advanced
        assert_eq!(state.tip_height(), 0); // height 0 was committed
    }

    #[test]
    fn test_votes_at_wrong_height_ignored() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 5);

        let vote = create_signed_vote(
            VoteType::Prevote, 0, 0, Some([0xAA; 32]),
            vals[0].0.fingerprint, &vals[0].0.secret_key,
        ).unwrap();

        cm.handle_prevote(1, vote, &vs);
        assert_eq!(cm.prevote_count(), 0); // height 0 ≠ 5
    }

    #[test]
    fn test_wrong_proposer_rejected() {
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new(ConsensusRelayConfig::default(), 0);

        // Find a validator that is NOT the proposer for h=0 r=0
        let proposer = vs.get_proposer(0, 0);
        let wrong_kp = vals.iter()
            .find(|(_, i)| i.fingerprint != proposer.fingerprint)
            .unwrap();

        let block = make_block_simple(0, [0u8; 32]);
        let bh = block.hash();
        let sig = falcon::falcon_sign(
            &wrong_kp.0.secret_key,
            &proposal_sign_bytes(0, 0, &bh),
        ).unwrap();

        let proposal = Proposal {
            height: 0, round: 0, block_hash: bh, block,
            proposer_id: wrong_kp.1.fingerprint,
            signature: sig,
        };

        cm.handle_proposal(1, proposal, &vs);
        assert_eq!(cm.counters.proposals_accepted, 0);
    }

    // ════════════════════════════════════════════
    // WAL persistence tests
    // ════════════════════════════════════════════

    fn wal_tmp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("misaka_consensus_wal_test");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn test_wal_events_persisted() {
        let path = wal_tmp_path("test_persist.wal");
        let _ = std::fs::remove_file(&path);

        let wal = misaka_wal::event_wal::EventWal::open(&path).unwrap();
        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut cm = ConsensusManager::new_with_wal(
            ConsensusRelayConfig::default(), 0, wal,
        );

        // Create proposal
        let proposer = vs.get_proposer(0, 0);
        let proposer_kp = vals.iter().find(|(_, i)| i.fingerprint == proposer.fingerprint).unwrap();
        let block = make_block_simple(0, [0u8; 32]);
        cm.create_proposal(block, proposer.fingerprint, &proposer_kp.0.secret_key).unwrap();

        // Add prevotes
        for i in 0..vs.quorum() {
            let bh = cm.proposal_block_hash().unwrap();
            let vote = create_signed_vote(
                VoteType::Prevote, 0, 0, Some(bh),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            cm.handle_prevote((i + 1) as u64, vote, &vs);
        }

        // Replay the WAL
        let events: Vec<ConsensusEvent> = misaka_wal::event_wal::replay_events(&path).unwrap();
        assert!(!events.is_empty());

        // Should contain ProposalReceived and PrevoteRecorded events
        let proposal_events = events.iter().filter(|e| matches!(e, ConsensusEvent::ProposalReceived { .. })).count();
        let prevote_events = events.iter().filter(|e| matches!(e, ConsensusEvent::PrevoteRecorded { .. })).count();
        assert!(proposal_events >= 1);
        assert!(prevote_events >= 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_wal_recovery_restores_height() {
        let path = wal_tmp_path("test_recover_height.wal");
        let _ = std::fs::remove_file(&path);

        // Write events simulating a committed height
        {
            let mut wal = misaka_wal::event_wal::EventWal::open(&path).unwrap();
            wal.append_event(&ConsensusEvent::ProposalReceived {
                height: 5, round: 0, block_hash: [0xAA; 32],
            }).unwrap();
            wal.append_event(&ConsensusEvent::BlockCommitted {
                height: 5, block_hash: [0xAA; 32],
            }).unwrap();
            wal.append_event(&ConsensusEvent::HeightAdvanced {
                new_height: 6,
            }).unwrap();
        }

        let cm = ConsensusManager::recover_from_wal(
            ConsensusRelayConfig::default(), &path, None,
        ).unwrap().unwrap();

        assert_eq!(cm.current_height(), 6);
        assert!(!cm.is_committed());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_wal_recovery_restores_votes() {
        let path = wal_tmp_path("test_recover_votes.wal");
        let _ = std::fs::remove_file(&path);

        {
            let mut wal = misaka_wal::event_wal::EventWal::open(&path).unwrap();
            wal.append_event(&ConsensusEvent::PrevoteRecorded {
                height: 0, round: 0, voter: [0x01; 32],
                block_hash: Some([0xAA; 32]),
            }).unwrap();
            wal.append_event(&ConsensusEvent::PrevoteRecorded {
                height: 0, round: 0, voter: [0x02; 32],
                block_hash: Some([0xAA; 32]),
            }).unwrap();
            wal.append_event(&ConsensusEvent::PrecommitRecorded {
                height: 0, round: 0, voter: [0x01; 32],
                block_hash: Some([0xAA; 32]),
            }).unwrap();
        }

        let cm = ConsensusManager::recover_from_wal(
            ConsensusRelayConfig::default(), &path, None,
        ).unwrap().unwrap();

        assert_eq!(cm.prevote_count(), 2);
        assert_eq!(cm.precommit_count(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_wal_recovery_restores_quorum() {
        let path = wal_tmp_path("test_recover_quorum.wal");
        let _ = std::fs::remove_file(&path);

        {
            let mut wal = misaka_wal::event_wal::EventWal::open(&path).unwrap();
            wal.append_event(&ConsensusEvent::PrevoteQuorum {
                height: 0, round: 0, block_hash: Some([0xBB; 32]),
            }).unwrap();
            wal.append_event(&ConsensusEvent::PrecommitQuorum {
                height: 0, round: 0, block_hash: [0xBB; 32],
            }).unwrap();
        }

        let cm = ConsensusManager::recover_from_wal(
            ConsensusRelayConfig::default(), &path, None,
        ).unwrap().unwrap();

        assert_eq!(cm.prevote_quorum_hash(), Some(Some([0xBB; 32])));
        assert_eq!(cm.precommit_quorum_hash(), Some([0xBB; 32]));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_wal_recovery_committed_state() {
        let path = wal_tmp_path("test_recover_commit.wal");
        let _ = std::fs::remove_file(&path);

        {
            let mut wal = misaka_wal::event_wal::EventWal::open(&path).unwrap();
            wal.append_event(&ConsensusEvent::BlockCommitted {
                height: 0, block_hash: [0xCC; 32],
            }).unwrap();
        }

        let cm = ConsensusManager::recover_from_wal(
            ConsensusRelayConfig::default(), &path, None,
        ).unwrap().unwrap();

        assert!(cm.is_committed());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_wal_empty_returns_none() {
        let path = wal_tmp_path("test_empty_wal.wal");
        let _ = std::fs::remove_file(&path);

        let result = ConsensusManager::recover_from_wal(
            ConsensusRelayConfig::default(), &path, None,
        ).unwrap();
        assert!(result.is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_wal_full_consensus_round_persist_and_recover() {
        let path = wal_tmp_path("test_full_round_wal.wal");
        let _ = std::fs::remove_file(&path);

        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let wal = misaka_wal::event_wal::EventWal::open(&path).unwrap();
        let mut cm = ConsensusManager::new_with_wal(
            ConsensusRelayConfig::default(), 0, wal,
        );
        let mut state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();

        // Proposer creates proposal
        let proposer = vs.get_proposer(0, 0);
        let proposer_kp = vals.iter().find(|(_, i)| i.fingerprint == proposer.fingerprint).unwrap();
        let block = make_block_simple(0, [0u8; 32]);
        cm.create_proposal(block, proposer.fingerprint, &proposer_kp.0.secret_key).unwrap();
        let bh = cm.proposal_block_hash().unwrap();

        // Prevotes reach quorum
        for i in 0..vs.quorum() {
            let vote = create_signed_vote(
                VoteType::Prevote, 0, 0, Some(bh),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            cm.handle_prevote((i + 1) as u64, vote, &vs);
        }

        // Precommits reach quorum
        for i in 0..vs.quorum() {
            let vote = create_signed_vote(
                VoteType::Precommit, 0, 0, Some(bh),
                vals[i].0.fingerprint, &vals[i].0.secret_key,
            ).unwrap();
            cm.handle_precommit((i + 1) as u64, vote, &vs);
        }

        // Commit
        let (committed, _) = cm.try_commit(&mut state, &mut mempool);
        assert!(committed);

        // Advance height
        cm.advance_height();
        assert_eq!(cm.current_height(), 1);

        // Now simulate crash: recover from WAL
        // The WAL was truncated on advance_height, so we should recover at height 1
        let recovered = ConsensusManager::recover_from_wal(
            ConsensusRelayConfig::default(), &path, None,
        ).unwrap().unwrap();

        assert_eq!(recovered.current_height(), 1);
        assert!(!recovered.is_committed());
        // Clean state for new height
        assert_eq!(recovered.prevote_count(), 0);
        assert_eq!(recovered.precommit_count(), 0);

        let _ = std::fs::remove_file(&path);
    }
}
