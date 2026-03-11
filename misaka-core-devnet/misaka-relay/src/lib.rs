// ============================================================
// MISAKA Network — P2P Relay Layer
// ============================================================
//
// Minimal announce/request/response relay for tx and block propagation.
//
// Components:
//   peer    — PeerState, scoring, rate limiting
//   orphan  — bounded orphan block buffer with parent-indexed reprocessing
//   relay   — RelayManager: message handling, mempool/block pipeline wiring
//
// Protocol flow:
//
//   TX relay:
//     NewTx(tx_id) → GetTx(tx_id) → Tx(tx) → mempool.admit_tx()
//     → if accepted: re-announce NewTx to other peers
//
//   Block relay:
//     NewBlock(hash, height) → GetBlock(hash) → Block(block)
//     → validate → if parent known: commit → re-announce
//                   if parent unknown: orphan buffer → retry on parent commit
//
// ============================================================

pub mod peer;
pub mod orphan;
pub mod relay;

use misaka_tx::{TxBody, TxId};
use misaka_store::Block;

// ════════════════════════════════════════════
// Types
// ════════════════════════════════════════════

/// Opaque peer identifier. In production this would be the Falcon fingerprint
/// or a session-specific ID. For now, a u64 for simplicity.
pub type PeerId = u64;

/// 32-byte hash used as block identifier.
pub type BlockHash = [u8; 32];

// ════════════════════════════════════════════
// Protocol messages
// ════════════════════════════════════════════

/// Relay protocol messages.
///
/// Announce-request-response pattern:
///   announce small metadata → request full object if needed → process
#[derive(Debug, Clone)]
pub enum RelayMessage {
    // ── TX relay ──
    /// Announce a new transaction by ID.
    NewTx { tx_id: TxId },
    /// Request a full transaction by ID.
    GetTx { tx_id: TxId },
    /// Full transaction payload.
    Tx { tx: Box<TxBody> },

    // ── Block relay ──
    /// Announce a new block by hash and height.
    NewBlock { block_hash: BlockHash, height: u64 },
    /// Request a full block by hash.
    GetBlock { block_hash: BlockHash },
    /// Full block payload.
    BlockMsg { block: Box<Block> },

    // ── Keepalive / status ──
    Ping { nonce: u64 },
    Pong { nonce: u64 },
    PeerStatus { height: u64, tip_hash: BlockHash },
}

// ════════════════════════════════════════════
// Outbound actions
// ════════════════════════════════════════════

/// Actions the relay manager asks the transport layer to perform.
///
/// The relay crate is transport-agnostic. It produces `OutboundAction`s
/// that the network layer (future async runtime) dispatches.
#[derive(Debug, Clone)]
pub enum OutboundAction {
    /// Send a message to a specific peer.
    Send { peer: PeerId, msg: RelayMessage },
    /// Broadcast a message to all connected peers except the excluded one.
    Broadcast { exclude: Option<PeerId>, msg: RelayMessage },
    /// Disconnect a peer (score depleted).
    Disconnect { peer: PeerId, reason: String },
}

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("Oversized object: {kind} is {size} bytes (max {max})")]
    OversizedObject { kind: &'static str, size: usize, max: usize },
    #[error("Unexpected object from peer {peer}: {detail}")]
    UnexpectedObject { peer: PeerId, detail: String },
    #[error("Duplicate object: {0}")]
    DuplicateObject(String),
    #[error("Rate limited: peer {peer} exceeded {kind} limit")]
    RateLimited { peer: PeerId, kind: &'static str },
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    #[error("Parent unknown: {0}")]
    ParentUnknown(String),
    #[error("Orphan buffer full")]
    OrphanBufferFull,
    #[error("Unknown peer: {0}")]
    UnknownPeer(PeerId),
    #[error("Malformed message: {0}")]
    MalformedMessage(String),
}

// ════════════════════════════════════════════
// Penalty reasons
// ════════════════════════════════════════════

/// Reasons for penalizing a peer. Each maps to a score deduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyReason {
    /// Sending announces for already-known objects at high rate.
    Spam,
    /// Message that doesn't parse or has invalid structure.
    MalformedMessage,
    /// Sending an object we didn't request.
    UnexpectedResponse,
    /// TX larger than MAX_TX_SIZE.
    OversizedTx,
    /// Block larger than max block size.
    OversizedBlock,
    /// TX that fails structural or proof validation.
    InvalidTx,
    /// Block that fails validation (bad merkle, duplicate tx_ids, etc).
    InvalidBlock,
    /// Block with invalid proposer signature.
    InvalidSignature,
    /// Block with incorrect merkle root.
    InvalidMerkleRoot,
}

impl PenaltyReason {
    /// Score deduction for this reason.
    pub fn penalty(self) -> u32 {
        match self {
            Self::Spam => 5,
            Self::MalformedMessage => 20,
            Self::UnexpectedResponse => 10,
            Self::OversizedTx => 15,
            Self::OversizedBlock => 15,
            Self::InvalidTx => 25,
            Self::InvalidBlock => 50,
            Self::InvalidSignature => 50,
            Self::InvalidMerkleRoot => 50,
        }
    }
}

// ════════════════════════════════════════════
// Configuration
// ════════════════════════════════════════════

/// Relay layer configuration with conservative testnet defaults.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    // ── Orphan buffer ──
    pub max_orphan_blocks: usize,
    pub max_children_per_parent: usize,

    // ── Known-object caches ──
    pub max_known_tx_cache: usize,
    pub max_known_block_cache: usize,
    pub max_recent_requests: usize,

    // ── Rate limits (messages per window) ──
    pub rate_window_secs: u64,
    pub tx_announce_rate_limit: u32,
    pub block_announce_rate_limit: u32,
    pub request_rate_limit: u32,
    pub object_rate_limit: u32,

    // ── Peer scoring ──
    pub initial_peer_score: u32,
    pub disconnect_score: u32,

    // ── Block size ──
    pub max_block_bytes: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_orphan_blocks: 256,
            max_children_per_parent: 16,
            max_known_tx_cache: 8192,
            max_known_block_cache: 1024,
            max_recent_requests: 1024,
            rate_window_secs: 60,
            tx_announce_rate_limit: 500,
            block_announce_rate_limit: 60,
            request_rate_limit: 200,
            object_rate_limit: 100,
            initial_peer_score: 100,
            disconnect_score: 0,
            max_block_bytes: 2 * 1024 * 1024,
        }
    }
}

// ════════════════════════════════════════════
// Counters / observability
// ════════════════════════════════════════════

/// Simple counters for relay observability. No metrics framework needed yet.
#[derive(Debug, Default, Clone)]
pub struct RelayCounters {
    pub tx_announced: u64,
    pub tx_requested: u64,
    pub tx_accepted: u64,
    pub tx_rejected: u64,
    pub block_announced: u64,
    pub block_requested: u64,
    pub block_committed: u64,
    pub orphan_inserted: u64,
    pub orphan_resolved: u64,
    pub peer_penalized: u64,
    pub peer_disconnected: u64,
}
