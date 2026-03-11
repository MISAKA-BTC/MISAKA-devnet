// ============================================================
// MISAKA Network — Node Startup & Recovery
// ============================================================
//
// Orchestrates safe node startup after crash/restart:
//
//   1. Load chain state from store
//   2. Open + replay WAL
//   3. Reconstruct ConsensusManager with anti-equivocation flags
//   4. Reconcile chain tip vs consensus WAL state
//   5. Initialize mempool (empty)
//   6. Gate: only then enable networking/consensus
//
// Safety invariants:
//   - No votes/proposals emitted during recovery
//   - No mempool cleanup or relay rebroadcast during recovery
//   - No chain state mutation except controlled reconciliation
//   - Anti-equivocation flags (our_prevote/our_precommit) always restored
//   - Networking starts ONLY after successful recovery
//
// ============================================================

pub mod recovery;
pub mod rpc;
pub mod wallet_store;
pub mod wallet_scan;
pub mod genesis;

// ════════════════════════════════════════════
// Node lifecycle phases
// ════════════════════════════════════════════

/// Lifecycle phase of the node runtime.
///
/// Transitions: Recovering → Recovered → NetworkingStarted
///
/// Rules:
///   - Recovering: no networking, no voting, no proposals
///   - Recovered: safe to start networking
///   - NetworkingStarted: full operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStartupPhase {
    /// WAL replay + reconciliation in progress. No external I/O.
    Recovering,
    /// Recovery succeeded. Safe to start networking.
    Recovered,
    /// Networking and consensus loops active.
    NetworkingStarted,
}

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("WAL replay failed: {0}")]
    WalReplayFailed(String),

    #[error("Chain tip / consensus mismatch: chain_height={chain_height}, wal_height={wal_height}")]
    ChainTipConsensusMismatch { chain_height: u64, wal_height: u64 },

    #[error("Consensus state inconsistent: {0}")]
    ConsensusStateInconsistent(String),

    #[error("WAL says committed at height {0} but chain store has not applied it")]
    CommittedButNotApplied(u64),

    #[error("Partial WAL tail recovered — {valid_events} valid events, last entry corrupted")]
    PartialWalTailRecovered { valid_events: usize },

    #[error("Recovery not ready: node is still in phase {0:?}")]
    RecoveryNotReady(NodeStartupPhase),

    #[error("Networking started too early: recovery not complete")]
    NetworkingStartedTooEarly,

    #[error("Store error: {0}")]
    StoreError(String),
}

// ════════════════════════════════════════════
// Recovered node state
// ════════════════════════════════════════════

/// Result of the startup recovery pipeline.
///
/// Contains everything needed to resume safe operation.
#[derive(Debug)]
pub struct RecoveredNodeState {
    /// Chain tip hash from the store.
    pub chain_tip_hash: [u8; 32],
    /// Chain height from the store.
    pub chain_height: u64,
    /// Consensus height after WAL replay.
    pub consensus_height: u64,
    /// Whether a block was committed in the WAL at consensus_height.
    pub wal_committed: bool,
    /// Whether height was advanced after commit in WAL (clean shutdown).
    pub wal_height_advanced: bool,
    /// Number of events replayed from WAL.
    pub events_replayed: usize,
    /// Whether our_prevote flag was restored.
    pub our_prevote_restored: bool,
    /// Whether our_precommit flag was restored.
    pub our_precommit_restored: bool,
    /// Warnings accumulated during recovery (non-fatal).
    pub warnings: Vec<String>,
    /// The reconciliation action taken.
    pub reconciliation: ReconciliationAction,
}

/// What reconciliation was performed between chain state and WAL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationAction {
    /// Chain tip and WAL agree — normal startup.
    Normal,
    /// WAL has partial consensus state for a height not yet committed.
    /// Node resumes at that height with pending state.
    PendingConsensus,
    /// WAL committed but height not advanced; node will advance.
    CommittedNeedAdvance,
    /// WAL is older than chain; consensus rebuilt from chain tip + 1.
    WalBehindChain,
    /// WAL is empty; fresh start at chain tip + 1.
    FreshStart,
}
