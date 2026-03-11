// ============================================================
// MISAKA Relay — Peer State, Scoring, Rate Limiting
// ============================================================

use crate::{PeerId, PenaltyReason, RelayConfig, BlockHash};
use misaka_tx::TxId;
use std::collections::{HashMap, HashSet, VecDeque};

// ════════════════════════════════════════════
// Rate limiter (fixed window)
// ════════════════════════════════════════════

/// Simple fixed-window rate limiter.
///
/// Tracks message counts within a time window. When the window
/// expires, the counter resets. No sliding window complexity.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    window_secs: u64,
    limit: u32,
    count: u32,
    window_start: u64,
}

impl RateLimiter {
    pub fn new(window_secs: u64, limit: u32) -> Self {
        Self { window_secs, limit, count: 0, window_start: 0 }
    }

    /// Try to consume one token. Returns true if allowed, false if rate limited.
    pub fn try_consume(&mut self, now_secs: u64) -> bool {
        if now_secs >= self.window_start + self.window_secs {
            // New window
            self.window_start = now_secs;
            self.count = 0;
        }
        if self.count >= self.limit {
            return false;
        }
        self.count += 1;
        true
    }

    /// Check if the peer is greatly exceeding the limit (2x).
    /// Used to decide whether to apply a penalty vs just dropping.
    pub fn is_hard_exceeded(&self, now_secs: u64) -> bool {
        if now_secs >= self.window_start + self.window_secs {
            return false; // new window, not exceeded
        }
        self.count >= self.limit * 2
    }

    pub fn count(&self) -> u32 { self.count }
}

// ════════════════════════════════════════════
// Per-peer state
// ════════════════════════════════════════════

/// State tracked per connected peer.
#[derive(Debug)]
pub struct PeerState {
    pub peer_id: PeerId,
    pub score: u32,

    // ── Rate limiters ──
    pub announce_limiter: RateLimiter,
    pub request_limiter: RateLimiter,
    pub object_limiter: RateLimiter,

    // ── Known objects (what this peer has announced to us) ──
    pub known_tx_ids: BoundedHashSet<TxId>,
    pub known_block_hashes: BoundedHashSet<BlockHash>,

    // ── Outstanding requests we sent to this peer ──
    pub pending_tx_requests: HashSet<TxId>,
    pub pending_block_requests: HashSet<BlockHash>,

    // ── Peer's reported chain state ──
    pub reported_height: u64,
    pub reported_tip_hash: BlockHash,
}

impl PeerState {
    pub fn new(peer_id: PeerId, config: &RelayConfig) -> Self {
        Self {
            peer_id,
            score: config.initial_peer_score,
            announce_limiter: RateLimiter::new(config.rate_window_secs, config.tx_announce_rate_limit),
            request_limiter: RateLimiter::new(config.rate_window_secs, config.request_rate_limit),
            object_limiter: RateLimiter::new(config.rate_window_secs, config.object_rate_limit),
            known_tx_ids: BoundedHashSet::new(config.max_known_tx_cache),
            known_block_hashes: BoundedHashSet::new(config.max_known_block_cache),
            pending_tx_requests: HashSet::new(),
            pending_block_requests: HashSet::new(),
            reported_height: 0,
            reported_tip_hash: [0u8; 32],
        }
    }

    /// Apply a penalty to this peer. Returns true if peer should be disconnected.
    pub fn apply_penalty(&mut self, reason: PenaltyReason) -> bool {
        let penalty = reason.penalty();
        self.score = self.score.saturating_sub(penalty);
        self.score == 0
    }

    /// Check if peer is at or below disconnect threshold.
    pub fn should_disconnect(&self, threshold: u32) -> bool {
        self.score <= threshold
    }
}

// ════════════════════════════════════════════
// Peer registry
// ════════════════════════════════════════════

/// Registry of all connected peers.
pub struct PeerRegistry {
    peers: HashMap<PeerId, PeerState>,
    config: RelayConfig,
}

impl PeerRegistry {
    pub fn new(config: RelayConfig) -> Self {
        Self { peers: HashMap::new(), config }
    }

    pub fn register(&mut self, peer_id: PeerId) {
        self.peers.entry(peer_id)
            .or_insert_with(|| PeerState::new(peer_id, &self.config));
    }

    pub fn unregister(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerState> {
        self.peers.get(peer_id)
    }

    pub fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerState> {
        self.peers.get_mut(peer_id)
    }

    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.peers.keys().copied().collect()
    }

    pub fn len(&self) -> usize { self.peers.len() }
    pub fn is_empty(&self) -> bool { self.peers.is_empty() }

    pub fn config(&self) -> &RelayConfig { &self.config }
}

// ════════════════════════════════════════════
// Bounded hash set (FIFO eviction)
// ════════════════════════════════════════════

/// A HashSet with a bounded capacity. When full, the oldest entry is evicted.
#[derive(Debug, Clone)]
pub struct BoundedHashSet<T: std::hash::Hash + Eq + Copy> {
    set: HashSet<T>,
    order: VecDeque<T>,
    max_size: usize,
}

impl<T: std::hash::Hash + Eq + Copy> BoundedHashSet<T> {
    pub fn new(max_size: usize) -> Self {
        Self {
            set: HashSet::with_capacity(max_size.min(1024)),
            order: VecDeque::with_capacity(max_size.min(1024)),
            max_size,
        }
    }

    /// Insert an item. Returns true if it was new (not already present).
    pub fn insert(&mut self, item: T) -> bool {
        if self.set.contains(&item) {
            return false;
        }
        // Evict oldest if full
        while self.set.len() >= self.max_size {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            } else {
                break;
            }
        }
        self.set.insert(item);
        self.order.push_back(item);
        true
    }

    pub fn contains(&self, item: &T) -> bool {
        self.set.contains(item)
    }

    pub fn len(&self) -> usize { self.set.len() }
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut rl = RateLimiter::new(60, 5);
        for _ in 0..5 {
            assert!(rl.try_consume(100));
        }
        // 6th should fail
        assert!(!rl.try_consume(100));
    }

    #[test]
    fn test_rate_limiter_resets_on_new_window() {
        let mut rl = RateLimiter::new(60, 3);
        assert!(rl.try_consume(100));
        assert!(rl.try_consume(100));
        assert!(rl.try_consume(100));
        assert!(!rl.try_consume(100));

        // New window
        assert!(rl.try_consume(161));
        assert_eq!(rl.count(), 1);
    }

    #[test]
    fn test_rate_limiter_hard_exceeded() {
        let mut rl = RateLimiter::new(60, 3);
        for _ in 0..6 {
            rl.try_consume(100);
        }
        assert!(rl.is_hard_exceeded(100));
        assert!(!rl.is_hard_exceeded(200)); // new window
    }

    #[test]
    fn test_peer_penalty_disconnect() {
        let config = RelayConfig::default(); // initial_score = 100
        let mut peer = PeerState::new(1, &config);

        // InvalidBlock = 50 penalty, twice → 0
        assert!(!peer.apply_penalty(PenaltyReason::InvalidBlock));
        assert_eq!(peer.score, 50);
        assert!(peer.apply_penalty(PenaltyReason::InvalidBlock));
        assert_eq!(peer.score, 0);
        assert!(peer.should_disconnect(0));
    }

    #[test]
    fn test_peer_penalty_small_does_not_disconnect() {
        let config = RelayConfig::default();
        let mut peer = PeerState::new(1, &config);

        // Spam = 5, so 20 of them = 100 penalty → disconnect
        for _ in 0..19 {
            assert!(!peer.apply_penalty(PenaltyReason::Spam));
        }
        assert_eq!(peer.score, 5);
        assert!(peer.apply_penalty(PenaltyReason::Spam));
    }

    #[test]
    fn test_bounded_hash_set_eviction() {
        let mut set = BoundedHashSet::new(3);
        assert!(set.insert(1u64));
        assert!(set.insert(2));
        assert!(set.insert(3));
        assert_eq!(set.len(), 3);

        // Insert 4 → evicts 1
        assert!(set.insert(4));
        assert_eq!(set.len(), 3);
        assert!(!set.contains(&1));
        assert!(set.contains(&4));
    }

    #[test]
    fn test_bounded_hash_set_no_duplicate() {
        let mut set = BoundedHashSet::new(5);
        assert!(set.insert(42u64));
        assert!(!set.insert(42)); // already present
        assert_eq!(set.len(), 1);
    }
}
