// ============================================================
// MISAKA Network — Multi-Node Testnet Orchestration
// ============================================================
//
// In-process virtual node network for testing.
//
// Each "node" is a struct with its own:
//   ChainState, Mempool, RelayManager, ConsensusManager, Falcon keys
//
// The TestnetRunner dispatches messages between virtual nodes
// by routing OutboundActions through an in-memory message bus.
//
// Usage:
//   let mut testnet = TestnetRunner::launch(10, 1)?;  // 10 validators + 1 observer
//   testnet.produce_blocks(5)?;
//   assert!(testnet.all_at_height(5));
//   testnet.shutdown();
//
// ============================================================

pub mod config;
pub mod keygen;
pub mod runner;

use serde::{Serialize, Deserialize};

// ════════════════════════════════════════════
// Types
// ════════════════════════════════════════════

/// Unique node identifier within the testnet.
pub type NodeId = u64;

/// Role of a testnet node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    Validator,
    Observer,
}

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum TestnetError {
    #[error("Testnet start failed: {0}")]
    StartFailed(String),
    #[error("Node launch failed: node {node_id}: {reason}")]
    NodeLaunchFailed { node_id: NodeId, reason: String },
    #[error("Consensus stalled at height {height} after {ticks} ticks")]
    ConsensusStalled { height: u64, ticks: u64 },
    #[error("Node crashed: {0}")]
    NodeCrashed(NodeId),
    #[error("Keygen error: {0}")]
    KeygenError(String),
    #[error("Height mismatch: node {node_id} at {actual}, expected {expected}")]
    HeightMismatch { node_id: NodeId, actual: u64, expected: u64 },
    #[error("Block error: {0}")]
    BlockError(String),
}

// ════════════════════════════════════════════
// Status
// ════════════════════════════════════════════

/// Per-node status snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatus {
    pub node_id: NodeId,
    pub role: NodeRole,
    pub chain_height: u64,
    pub consensus_height: u64,
    pub mempool_size: usize,
    pub is_committed: bool,
}

/// Testnet-wide status.
#[derive(Debug, Clone, Serialize)]
pub struct TestnetStatus {
    pub nodes: Vec<NodeStatus>,
    pub min_height: u64,
    pub max_height: u64,
    pub blocks_produced: u64,
}
