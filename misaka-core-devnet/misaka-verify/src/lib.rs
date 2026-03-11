use misaka_crypto::falcon;
use misaka_crypto::hash::{Domain, domain_hash_multi};
use std::collections::HashSet;

pub const MAX_FUTURE_DRIFT_SECS: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("Invalid proposer signature")]
    InvalidProposerSig,
    #[error("Proposer {0} not in validator set")]
    UnknownProposer(String),
    #[error("Unexpected proposer: expected {expected}, got {got}")]
    UnexpectedProposer { expected: String, got: String },
    #[error("Unknown BFT voter: {0}")]
    UnknownBftVoter(String),
    #[error("BFT quorum not met: {got}/{required}")]
    InsufficientQuorum { got: usize, required: usize },
    #[error("Block hash mismatch")]
    HashMismatch,
    #[error("Block too large: {size} > {max}")]
    BlockTooLarge { size: usize, max: usize },
    #[error("Invalid block version: {0}")]
    InvalidVersion(u32),
    #[error("Height not sequential: expected {expected}, got {got}")]
    HeightGap { expected: u64, got: u64 },
    #[error("Prev hash mismatch")]
    PrevHashMismatch,
    #[error("Timestamp regression: prev={prev}, got={got}")]
    TimestampRegression { prev: u64, got: u64 },
    #[error("Block from too far in the future: now={now}, got={got}, max_drift={max_drift}")]
    FutureTimestamp { now: u64, got: u64, max_drift: u64 },
    #[error("Duplicate BFT voter: {0}")]
    DuplicateVoter(String),
    #[error("BFT vote height mismatch: expected {expected}, got {got}")]
    VoteHeightMismatch { expected: u64, got: u64 },
    #[error("BFT vote round mismatch: expected {expected}, got {got}")]
    VoteRoundMismatch { expected: u32, got: u32 },
    #[error("Expected precommit vote, got type={0}")]
    InvalidVoteType(u8),
    #[error("BFT vote block hash mismatch")]
    VoteBlockHashMismatch,
    #[error("Invalid BFT signature from {0}")]
    InvalidBftSig(String),
    #[error("Falcon error: {0}")]
    Falcon(#[from] falcon::FalconError),
}

pub struct BlockHeaderRef<'a> {
    pub version: u32,
    pub height: u64,
    pub round: u32,
    pub prev_hash: &'a [u8; 32],
    pub timestamp: u64,
    pub tx_merkle_root: &'a [u8; 32],
    pub utxo_root: &'a [u8; 32],
    pub link_tag_root: &'a [u8; 32],
    pub proposer_id: &'a [u8; 32],
    pub proposer_sig: &'a [u8],
    pub bft_sigs: Vec<BftSigRef<'a>>,
}

pub struct BftSigRef<'a> {
    pub vote_type: u8,
    pub height: u64,
    pub round: u32,
    pub block_hash: &'a [u8; 32],
    pub validator_id: &'a [u8; 32],
    pub signature: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct CommitVote {
    pub vote_type: u8,
    pub height: u64,
    pub round: u32,
    pub block_hash: [u8; 32],
    pub validator_id: [u8; 32],
    pub signature: Vec<u8>,
}

pub struct ValidatorInfo {
    pub fingerprint: [u8; 32],
    pub falcon_pk: Vec<u8>,
}

/// Block hash: SHAKE256("MISAKA_BLOCK" || version || height || round || prev_hash || ...)
///
/// AUDIT FIX #6: Unified SHAKE256 with Domain::Block separation.
/// Previously used raw SHA3-256 without domain tag.
pub fn compute_block_hash(header: &BlockHeaderRef) -> [u8; 32] {
    domain_hash_multi(
        Domain::Block,
        &[
            &header.version.to_le_bytes(),
            &header.height.to_le_bytes(),
            &header.round.to_le_bytes(),
            header.prev_hash.as_slice(),
            &header.timestamp.to_le_bytes(),
            header.tx_merkle_root.as_slice(),
            header.utxo_root.as_slice(),
            header.link_tag_root.as_slice(),
            header.proposer_id.as_slice(),
        ],
        32,
    ).try_into().unwrap()
}

/// Vote hash: SHAKE256("MISAKA_VOTE" || vote_type || height || round || block_hash)
///
/// AUDIT FIX #6/#7: Unified SHAKE256 with Domain::Vote separation.
/// Previously used raw SHA3-256 without domain tag.
pub fn compute_vote_hash(
    vote_type: u8,
    height: u64,
    round: u32,
    block_hash: &[u8; 32],
) -> [u8; 32] {
    domain_hash_multi(
        Domain::Vote,
        &[
            &[vote_type],
            &height.to_le_bytes(),
            &round.to_le_bytes(),
            block_hash.as_slice(),
        ],
        32,
    ).try_into().unwrap()
}

pub fn verify_block_header(
    header: &BlockHeaderRef,
    validators: &[ValidatorInfo],
    expected_prev_hash: &[u8; 32],
    expected_height: u64,
    expected_proposer_id: &[u8; 32],
    prev_timestamp: Option<u64>,
    now_unix_secs: u64,
) -> Result<(), VerifyError> {
    if header.version != 2 {
        return Err(VerifyError::InvalidVersion(header.version));
    }
    if header.height != expected_height {
        return Err(VerifyError::HeightGap { expected: expected_height, got: header.height });
    }
    if header.height > 0 && header.prev_hash != expected_prev_hash {
        return Err(VerifyError::PrevHashMismatch);
    }
    if let Some(prev_ts) = prev_timestamp {
        if header.timestamp < prev_ts {
            return Err(VerifyError::TimestampRegression { prev: prev_ts, got: header.timestamp });
        }
    }
    if header.timestamp > now_unix_secs.saturating_add(MAX_FUTURE_DRIFT_SECS) {
        return Err(VerifyError::FutureTimestamp { now: now_unix_secs, got: header.timestamp, max_drift: MAX_FUTURE_DRIFT_SECS });
    }
    if header.proposer_id != expected_proposer_id {
        return Err(VerifyError::UnexpectedProposer {
            expected: hex::encode(expected_proposer_id),
            got: hex::encode(header.proposer_id),
        });
    }

    let block_hash = compute_block_hash(header);

    let proposer = validators
        .iter()
        .find(|v| &v.fingerprint == header.proposer_id)
        .ok_or_else(|| VerifyError::UnknownProposer(hex::encode(header.proposer_id)))?;

    let proposer_valid = falcon::falcon_verify(&proposer.falcon_pk, &block_hash, header.proposer_sig)?;
    if !proposer_valid {
        return Err(VerifyError::InvalidProposerSig);
    }

    let quorum = (2 * validators.len()) / 3 + 1;
    let mut valid_votes = 0usize;
    let mut seen_voters: HashSet<[u8; 32]> = HashSet::new();

    for bft_sig in &header.bft_sigs {
        if bft_sig.vote_type != 2 {
            return Err(VerifyError::InvalidVoteType(bft_sig.vote_type));
        }
        if bft_sig.height != header.height {
            return Err(VerifyError::VoteHeightMismatch { expected: header.height, got: bft_sig.height });
        }
        if bft_sig.round != header.round {
            return Err(VerifyError::VoteRoundMismatch { expected: header.round, got: bft_sig.round });
        }
        if bft_sig.block_hash != &block_hash {
            return Err(VerifyError::VoteBlockHashMismatch);
        }

        let voter_hex = hex::encode(bft_sig.validator_id);
        if !seen_voters.insert(*bft_sig.validator_id) {
            return Err(VerifyError::DuplicateVoter(voter_hex));
        }

        let voter = validators
            .iter()
            .find(|v| &v.fingerprint == bft_sig.validator_id)
            .ok_or_else(|| VerifyError::UnknownBftVoter(voter_hex.clone()))?;

        let valid = verify_vote(
            bft_sig.vote_type,
            bft_sig.height,
            bft_sig.round,
            bft_sig.block_hash,
            &voter.falcon_pk,
            bft_sig.signature,
        )?;
        if !valid {
            return Err(VerifyError::InvalidBftSig(voter_hex));
        }
        valid_votes += 1;
    }

    if valid_votes < quorum {
        return Err(VerifyError::InsufficientQuorum { got: valid_votes, required: quorum });
    }

    Ok(())
}

pub fn verify_vote(
    vote_type: u8,
    height: u64,
    round: u32,
    block_hash: &[u8; 32],
    voter_pk: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let vote_hash = compute_vote_hash(vote_type, height, round, block_hash);
    Ok(falcon::falcon_verify(voter_pk, &vote_hash, signature)?)
}

/// Domain-separated Merkle root with second-preimage protection.
///
/// AUDIT FIX: Previously used raw SHA3-256 without leaf/node distinction.
/// Now delegates to misaka_crypto::hash::merkle_root which uses:
///   Leaf: SHAKE256("MISAKA_MERKLE" || 0x00 || item)
///   Node: SHAKE256("MISAKA_MERKLE" || 0x01 || left || right)
pub fn merkle_root(items: &[&[u8]]) -> [u8; 32] {
    misaka_crypto::hash::merkle_root(items)
}
