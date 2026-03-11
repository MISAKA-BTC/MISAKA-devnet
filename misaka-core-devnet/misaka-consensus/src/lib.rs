use misaka_crypto::falcon;
use misaka_crypto::hash::{Domain, domain_hash_multi};
use misaka_crypto::signing;
use misaka_verify::{self, CommitVote, ValidatorInfo};
use std::collections::{HashMap, HashSet};

// ════════════════════════════════════════════
// WAL Integration Guide
// ════════════════════════════════════════════
//
// The node runner (binary crate) MUST use misaka_wal::ConsensusWal
// to persist state transitions. The consensus module itself is pure
// (no I/O) — the runner is responsible for the WAL lifecycle:
//
//   1. On startup:
//      state = ConsensusWal::recover("consensus.wal")?;
//      if state.committed → apply block, advance to next height
//      if state.our_prevote → re-enter round, don't re-sign
//      if state.locked → restore lock
//
//   2. Before broadcasting any vote:
//      wal.write_entry(WalEntry::Vote { ... })?;  // fsync!
//      network.broadcast(vote);
//
//   3. On lock change:
//      wal.write_entry(WalEntry::Lock { ... })?;
//
//   4. On commit:
//      wal.write_entry(WalEntry::Commit { ... })?;
//      ledger_snapshot.save("state.json")?;
//
//   5. On new height:
//      wal.truncate_and_start_height(height + 1, block_hash)?;
//
// The invariant is: a validator NEVER broadcasts a vote that
// isn't in the WAL. This prevents equivocation after crash.
// ════════════════════════════════════════════

pub const MIN_VALIDATORS: usize = 10;
pub const MAX_VALIDATORS: usize = 30;
pub const PROPOSE_TIMEOUT_MS: u64 = 30_000;
pub const PREVOTE_TIMEOUT_MS: u64 = 30_000;
pub const PRECOMMIT_TIMEOUT_MS: u64 = 30_000;

/// Sentinel block hash for nil votes (all zeros).
/// Domain separation ensures this cannot collide with a real block hash.
const NIL_BLOCK_HASH: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase { Propose, Prevote, Precommit, Commit }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteType { Prevote = 1, Precommit = 2 }

#[derive(Debug, Clone)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height: u64,
    pub round: u32,
    pub block_hash: Option<[u8; 32]>,
    pub voter_id: [u8; 32],
    pub signature: Vec<u8>,
}

pub struct ValidatorSet {
    validators: Vec<ValidatorInfo>,
    fingerprint_set: HashSet<[u8; 32]>,
}

impl ValidatorSet {
    pub fn new(mut validators: Vec<ValidatorInfo>) -> Result<Self, &'static str> {
        if validators.len() < MIN_VALIDATORS { return Err("Too few validators"); }
        if validators.len() > MAX_VALIDATORS { return Err("Too many validators"); }
        validators.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        let fingerprint_set: HashSet<_> = validators.iter().map(|v| v.fingerprint).collect();
        if fingerprint_set.len() != validators.len() {
            return Err("Duplicate validator fingerprint");
        }
        Ok(Self { validators, fingerprint_set })
    }

    pub fn len(&self) -> usize { self.validators.len() }
    pub fn quorum(&self) -> usize { (2 * self.len()) / 3 + 1 }
    pub fn max_faults(&self) -> usize { (self.len() - 1) / 3 }
    pub fn contains(&self, fp: &[u8; 32]) -> bool { self.fingerprint_set.contains(fp) }
    /// Deterministic round-robin proposer selection.
    ///
    /// proposer = validators[(height + round) % N]
    ///
    /// Validators are sorted by fingerprint at construction time,
    /// so the ordering is canonical across all nodes. No VRF is used —
    /// the whitepaper (§12) specifies deterministic selection at this
    /// validator set scale (10-30). pqVRF is reserved for future use.
    pub fn get_proposer(&self, height: u64, round: u32) -> &ValidatorInfo {
        let idx = ((height as usize) + (round as usize)) % self.len();
        &self.validators[idx]
    }
    pub fn get_by_fingerprint(&self, fp: &[u8; 32]) -> Option<&ValidatorInfo> {
        self.validators.iter().find(|v| &v.fingerprint == fp)
    }
}

pub struct RoundState {
    pub height: u64,
    pub round: u32,
    pub phase: Phase,
    pub prevotes: HashMap<[u8; 32], Vote>,
    pub precommits: HashMap<[u8; 32], Vote>,
    pub proposal_hash: Option<[u8; 32]>,
    pub locked_hash: Option<[u8; 32]>,
    pub locked_round: Option<u32>,
}

impl RoundState {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            round: 0,
            phase: Phase::Propose,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            proposal_hash: None,
            locked_hash: None,
            locked_round: None,
        }
    }

    pub fn advance_round(&mut self) {
        self.round += 1;
        self.phase = Phase::Propose;
        self.prevotes.clear();
        self.precommits.clear();
        self.proposal_hash = None;
        // locked_hash, locked_round intentionally preserved (Tendermint lock rules)
    }

    pub fn insert_prevote(&mut self, vote: Vote, validator_set: &ValidatorSet) -> Result<(), &'static str> {
        if vote.vote_type != VoteType::Prevote { return Err("wrong vote type"); }
        if vote.height != self.height { return Err("vote height mismatch"); }
        if vote.round != self.round { return Err("vote round mismatch"); }
        if !verify_vote(&vote, validator_set) { return Err("invalid vote signature"); }
        self.prevotes.insert(vote.voter_id, vote);
        Ok(())
    }

    /// Insert a precommit vote.
    ///
    /// AUDIT FIX: Nil precommits (block_hash = None) are now accepted.
    /// Tendermint BFT requires nil precommits for timeout-driven round
    /// advancement. Without them, a round cannot progress when the
    /// proposer is offline or the proposal is invalid.
    pub fn insert_precommit(&mut self, vote: Vote, validator_set: &ValidatorSet) -> Result<(), &'static str> {
        if vote.vote_type != VoteType::Precommit { return Err("wrong vote type"); }
        if vote.height != self.height { return Err("vote height mismatch"); }
        if vote.round != self.round { return Err("vote round mismatch"); }
        if !verify_vote(&vote, validator_set) { return Err("invalid vote signature"); }
        self.precommits.insert(vote.voter_id, vote);
        Ok(())
    }

    /// Check if a prevote for `block_hash` is valid given the current lock state.
    ///
    /// Tendermint lock rule:
    ///   - If locked on a block at round R, can only prevote for that block
    ///     in rounds > R, UNLESS a POL (proof of lock change) is seen at a
    ///     higher round for a different block.
    ///   - Nil prevotes are always allowed (timeout case).
    pub fn is_valid_prevote(&self, block_hash: Option<[u8; 32]>, pol_round: Option<u32>) -> bool {
        // Nil prevote always allowed
        if block_hash.is_none() {
            return true;
        }

        // No lock → any prevote is fine
        let (locked, locked_r) = match (self.locked_hash, self.locked_round) {
            (Some(lh), Some(lr)) => (lh, lr),
            _ => return true,
        };

        let hash = block_hash.unwrap();

        // Prevoting for the locked block is always valid
        if hash == locked {
            return true;
        }

        // Prevoting for a different block requires a POL at round > locked_round
        match pol_round {
            Some(pr) if pr > locked_r => true,
            _ => false,
        }
    }

    /// Set lock on a block after seeing +2/3 prevotes for it.
    pub fn set_lock(&mut self, block_hash: [u8; 32], round: u32) {
        self.locked_hash = Some(block_hash);
        self.locked_round = Some(round);
    }

    /// Clear lock (after seeing +2/3 nil prevotes at a higher round).
    pub fn clear_lock(&mut self) {
        self.locked_hash = None;
        self.locked_round = None;
    }
}

/// Compute vote hash using unified SHAKE256 with Domain::Vote.
///
/// AUDIT FIX #6/#7: Previously used raw SHA3-256 without domain separation.
/// Now uses the same hash construction as misaka_verify::compute_vote_hash,
/// with nil votes using a zero sentinel hash.
///
/// For non-nil votes, this produces identical output to
/// misaka_verify::compute_vote_hash() — verified by the shared domain_hash_multi
/// call with Domain::Vote.
pub fn encode_vote_message(vote: &Vote) -> [u8; 32] {
    let block_hash = vote.block_hash.as_ref().unwrap_or(&NIL_BLOCK_HASH);
    domain_hash_multi(
        Domain::Vote,
        &[
            &[vote.vote_type as u8],
            &vote.height.to_le_bytes(),
            &vote.round.to_le_bytes(),
            block_hash.as_slice(),
        ],
        32,
    ).try_into().unwrap()
}

pub fn create_signed_vote(
    vote_type: VoteType,
    height: u64,
    round: u32,
    block_hash: Option<[u8; 32]>,
    voter_id: [u8; 32],
    falcon_sk: &[u8],
) -> Result<Vote, falcon::FalconError> {
    let mut vote = Vote { vote_type, height, round, block_hash, voter_id, signature: Vec::new() };
    let msg = encode_vote_message(&vote);
    vote.signature = falcon::falcon_sign(falcon_sk, &msg)?;
    Ok(vote)
}

pub fn verify_vote(vote: &Vote, validator_set: &ValidatorSet) -> bool {
    let validator = match validator_set.get_by_fingerprint(&vote.voter_id) {
        Some(v) => v,
        None => return false,
    };
    let msg = encode_vote_message(vote);
    match falcon::falcon_verify(&validator.falcon_pk, &msg, &vote.signature) {
        Ok(valid) => valid,
        Err(_) => false,
    }
}

// ════════════════════════════════════════════
// V2: Domain-separated vote signing (hardened)
// ════════════════════════════════════════════

/// Encode vote message using explicit prevote/precommit domain separation.
///
/// Unlike encode_vote_message() which uses a single Domain::Vote with
/// vote_type byte, this version uses separate domain prefixes:
///   - MISAKA_PREVOTE_V1 for prevotes
///   - MISAKA_PRECOMMIT_V1 for precommits
///
/// This ensures a prevote signature can never verify as a precommit
/// even with identical height/round/block_hash.
pub fn encode_vote_message_v2(vote: &Vote) -> [u8; 32] {
    let bh = vote.block_hash.as_ref();
    match vote.vote_type {
        VoteType::Prevote => signing::prevote_sign_bytes(vote.height, vote.round, bh),
        VoteType::Precommit => signing::precommit_sign_bytes(vote.height, vote.round, bh),
    }
}

/// Create a signed vote using V2 domain-separated encoding.
pub fn create_signed_vote_v2(
    vote_type: VoteType,
    height: u64,
    round: u32,
    block_hash: Option<[u8; 32]>,
    voter_id: [u8; 32],
    falcon_sk: &[u8],
) -> Result<Vote, falcon::FalconError> {
    let mut vote = Vote { vote_type, height, round, block_hash, voter_id, signature: Vec::new() };
    let msg = encode_vote_message_v2(&vote);
    vote.signature = falcon::falcon_sign(falcon_sk, &msg)?;
    Ok(vote)
}

/// Verify a vote using V2 domain-separated encoding.
pub fn verify_vote_v2(vote: &Vote, validator_set: &ValidatorSet) -> bool {
    let validator = match validator_set.get_by_fingerprint(&vote.voter_id) {
        Some(v) => v,
        None => return false,
    };
    let msg = encode_vote_message_v2(vote);
    match falcon::falcon_verify(&validator.falcon_pk, &msg, &vote.signature) {
        Ok(valid) => valid,
        Err(_) => false,
    }
}

pub fn check_prevote_quorum(state: &RoundState, validator_set: &ValidatorSet) -> Option<Option<[u8; 32]>> {
    let quorum = validator_set.quorum();
    let mut counts: HashMap<Option<[u8; 32]>, usize> = HashMap::new();
    for vote in state.prevotes.values() {
        if vote.height != state.height || vote.round != state.round || vote.vote_type != VoteType::Prevote { continue; }
        *counts.entry(vote.block_hash).or_insert(0) += 1;
    }
    for (hash, count) in &counts {
        if *count >= quorum { return Some(*hash); }
    }
    None
}

pub fn check_precommit_quorum(state: &RoundState, validator_set: &ValidatorSet) -> Option<Option<[u8; 32]>> {
    let quorum = validator_set.quorum();
    let mut counts: HashMap<Option<[u8; 32]>, usize> = HashMap::new();
    for vote in state.precommits.values() {
        if vote.height != state.height || vote.round != state.round || vote.vote_type != VoteType::Precommit { continue; }
        *counts.entry(vote.block_hash).or_insert(0) += 1;
    }
    for (hash, count) in &counts {
        if *count >= quorum { return Some(*hash); }
    }
    None
}

pub fn collect_bft_signatures(state: &RoundState, block_hash: &[u8; 32]) -> Vec<CommitVote> {
    state.precommits
        .values()
        .filter(|v| v.vote_type == VoteType::Precommit && v.block_hash.as_ref() == Some(block_hash))
        .map(|v| CommitVote {
            vote_type: VoteType::Precommit as u8,
            height: v.height,
            round: v.round,
            block_hash: v.block_hash.expect("filtered Some(block_hash) above"),
            validator_id: v.voter_id,
            signature: v.signature.clone(),
        })
        .collect()
}

pub fn verify_finalized_header(
    header: &misaka_verify::BlockHeaderRef,
    validator_set: &ValidatorSet,
    expected_prev_hash: &[u8; 32],
    expected_height: u64,
    prev_timestamp: Option<u64>,
    now_unix_secs: u64,
) -> Result<(), misaka_verify::VerifyError> {
    let expected_proposer = validator_set.get_proposer(header.height, header.round);
    misaka_verify::verify_block_header(
        header,
        &validator_set.validators,
        expected_prev_hash,
        expected_height,
        &expected_proposer.fingerprint,
        prev_timestamp,
        now_unix_secs,
    )
}
