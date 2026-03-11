// ============================================================
// MISAKA Relay — Orphan Block Buffer
// ============================================================
//
// Buffers blocks whose parent is not yet known.
//
// Indexes:
//   by_block_hash   — quick lookup / dedup
//   by_parent_hash  — find children to reprocess after parent commit
//   insertion_order  — FIFO eviction when buffer is full
//
// After a block is committed, the relay manager calls pop_children()
// to retrieve and process any orphans that are now unblocked.
//
// ============================================================

use crate::{BlockHash, RelayConfig, PeerId};
use misaka_store::Block;
use std::collections::{HashMap, VecDeque};

/// An orphan block entry.
#[derive(Debug, Clone)]
pub struct OrphanEntry {
    pub block: Block,
    pub block_hash: BlockHash,
    pub parent_hash: BlockHash,
    pub height: u64,
    /// Peer that sent us this block (for penalty tracking).
    pub from_peer: PeerId,
}

/// Bounded orphan block buffer.
pub struct OrphanBlockPool {
    /// Primary index: block_hash → entry
    by_block_hash: HashMap<BlockHash, OrphanEntry>,
    /// Secondary index: parent_hash → list of child block_hashes
    by_parent_hash: HashMap<BlockHash, Vec<BlockHash>>,
    /// FIFO order for eviction
    insertion_order: VecDeque<BlockHash>,
    /// Config limits
    max_orphans: usize,
    max_children_per_parent: usize,
}

impl OrphanBlockPool {
    pub fn new(config: &RelayConfig) -> Self {
        Self {
            by_block_hash: HashMap::new(),
            by_parent_hash: HashMap::new(),
            insertion_order: VecDeque::new(),
            max_orphans: config.max_orphan_blocks,
            max_children_per_parent: config.max_children_per_parent,
        }
    }

    /// Insert an orphan block. Returns Ok(()) if inserted, or an error reason.
    pub fn insert(&mut self, entry: OrphanEntry) -> Result<(), OrphanInsertError> {
        let bh = entry.block_hash;
        let ph = entry.parent_hash;

        // Duplicate check
        if self.by_block_hash.contains_key(&bh) {
            return Err(OrphanInsertError::Duplicate);
        }

        // Check children-per-parent limit
        if let Some(children) = self.by_parent_hash.get(&ph) {
            if children.len() >= self.max_children_per_parent {
                return Err(OrphanInsertError::TooManyChildren);
            }
        }

        // Evict oldest if at capacity
        while self.by_block_hash.len() >= self.max_orphans {
            self.evict_oldest();
        }

        // Insert
        self.by_parent_hash.entry(ph).or_default().push(bh);
        self.insertion_order.push_back(bh);
        self.by_block_hash.insert(bh, entry);

        Ok(())
    }

    /// Remove and return all orphans whose parent matches `parent_hash`.
    ///
    /// Returns children sorted by height then block_hash for deterministic
    /// processing order.
    pub fn pop_children(&mut self, parent_hash: &BlockHash) -> Vec<OrphanEntry> {
        let child_hashes = match self.by_parent_hash.remove(parent_hash) {
            Some(hashes) => hashes,
            None => return Vec::new(),
        };

        let mut children: Vec<OrphanEntry> = child_hashes.iter()
            .filter_map(|bh| self.by_block_hash.remove(bh))
            .collect();

        // Remove from insertion_order (lazy — we'll skip missing entries on evict)
        // For correctness, we mark them as removed by their absence in by_block_hash.

        // Sort deterministically: height ascending, then block_hash ascending
        children.sort_by(|a, b| {
            a.height.cmp(&b.height)
                .then_with(|| a.block_hash.cmp(&b.block_hash))
        });

        children
    }

    /// Check if a block hash is already in the orphan buffer.
    pub fn contains(&self, block_hash: &BlockHash) -> bool {
        self.by_block_hash.contains_key(block_hash)
    }

    /// Remove a specific orphan by block hash (e.g., if it was invalidated).
    pub fn remove(&mut self, block_hash: &BlockHash) -> Option<OrphanEntry> {
        let entry = self.by_block_hash.remove(block_hash)?;

        // Clean parent index
        if let Some(children) = self.by_parent_hash.get_mut(&entry.parent_hash) {
            children.retain(|h| h != block_hash);
            if children.is_empty() {
                self.by_parent_hash.remove(&entry.parent_hash);
            }
        }

        Some(entry)
    }

    pub fn len(&self) -> usize { self.by_block_hash.len() }
    pub fn is_empty(&self) -> bool { self.by_block_hash.is_empty() }

    /// Evict the oldest orphan (FIFO).
    fn evict_oldest(&mut self) {
        // Skip entries that were already removed via pop_children/remove
        while let Some(bh) = self.insertion_order.pop_front() {
            if self.by_block_hash.contains_key(&bh) {
                self.remove(&bh);
                return;
            }
        }
    }

    /// Number of distinct parent hashes tracked.
    pub fn parent_count(&self) -> usize { self.by_parent_hash.len() }

    /// Number of children for a specific parent.
    pub fn children_count(&self, parent_hash: &BlockHash) -> usize {
        self.by_parent_hash.get(parent_hash).map_or(0, |v| v.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanInsertError {
    Duplicate,
    TooManyChildren,
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_store::{BlockHeader, Block};

    fn make_orphan(block_byte: u8, parent_byte: u8, height: u64) -> OrphanEntry {
        let block_hash = [block_byte; 32];
        let parent_hash = [parent_byte; 32];
        let block = Block {
            header: BlockHeader {
                version: 2,
                height,
                round: 0,
                prev_hash: parent_hash,
                timestamp: 1000,
                tx_merkle_root: [0; 32],
                utxo_root: [0; 32],
                link_tag_root: [0; 32],
                proposer_id: [0xAA; 32],
                proposer_sig: vec![],
                bft_sigs: vec![],
            },
            transactions: vec![],
        };
        OrphanEntry { block, block_hash, parent_hash, height, from_peer: 0 }
    }

    fn test_config(max_orphans: usize, max_children: usize) -> RelayConfig {
        RelayConfig {
            max_orphan_blocks: max_orphans,
            max_children_per_parent: max_children,
            ..RelayConfig::default()
        }
    }

    #[test]
    fn test_insert_and_pop_children() {
        let config = test_config(256, 16);
        let mut pool = OrphanBlockPool::new(&config);

        // Parent is 0xAA, children are 0x01 and 0x02
        let o1 = make_orphan(0x01, 0xAA, 5);
        let o2 = make_orphan(0x02, 0xAA, 5);

        assert!(pool.insert(o1).is_ok());
        assert!(pool.insert(o2).is_ok());
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.children_count(&[0xAA; 32]), 2);

        // Pop children of parent 0xAA
        let children = pool.pop_children(&[0xAA; 32]);
        assert_eq!(children.len(), 2);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.parent_count(), 0);
    }

    #[test]
    fn test_duplicate_rejected() {
        let config = test_config(256, 16);
        let mut pool = OrphanBlockPool::new(&config);

        let o1 = make_orphan(0x01, 0xAA, 5);
        assert!(pool.insert(o1.clone()).is_ok());
        assert_eq!(pool.insert(o1), Err(OrphanInsertError::Duplicate));
    }

    #[test]
    fn test_too_many_children() {
        let config = test_config(256, 2);
        let mut pool = OrphanBlockPool::new(&config);

        assert!(pool.insert(make_orphan(0x01, 0xAA, 5)).is_ok());
        assert!(pool.insert(make_orphan(0x02, 0xAA, 5)).is_ok());
        assert_eq!(
            pool.insert(make_orphan(0x03, 0xAA, 5)),
            Err(OrphanInsertError::TooManyChildren)
        );
    }

    #[test]
    fn test_eviction_when_full() {
        let config = test_config(3, 16);
        let mut pool = OrphanBlockPool::new(&config);

        assert!(pool.insert(make_orphan(0x01, 0xA0, 1)).is_ok());
        assert!(pool.insert(make_orphan(0x02, 0xA1, 2)).is_ok());
        assert!(pool.insert(make_orphan(0x03, 0xA2, 3)).is_ok());
        assert_eq!(pool.len(), 3);

        // 4th insert should evict oldest (0x01)
        assert!(pool.insert(make_orphan(0x04, 0xA3, 4)).is_ok());
        assert_eq!(pool.len(), 3);
        assert!(!pool.contains(&[0x01; 32]));
        assert!(pool.contains(&[0x04; 32]));
    }

    #[test]
    fn test_remove_specific() {
        let config = test_config(256, 16);
        let mut pool = OrphanBlockPool::new(&config);

        assert!(pool.insert(make_orphan(0x01, 0xAA, 5)).is_ok());
        assert!(pool.insert(make_orphan(0x02, 0xAA, 5)).is_ok());

        let removed = pool.remove(&[0x01; 32]);
        assert!(removed.is_some());
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.children_count(&[0xAA; 32]), 1);
    }

    #[test]
    fn test_children_reprocessed_deterministic_order() {
        let config = test_config(256, 16);
        let mut pool = OrphanBlockPool::new(&config);

        // Different heights — should sort by height
        assert!(pool.insert(make_orphan(0x03, 0xAA, 7)).is_ok());
        assert!(pool.insert(make_orphan(0x01, 0xAA, 5)).is_ok());
        assert!(pool.insert(make_orphan(0x02, 0xAA, 6)).is_ok());

        let children = pool.pop_children(&[0xAA; 32]);
        assert_eq!(children.len(), 3);
        assert_eq!(children[0].height, 5);
        assert_eq!(children[1].height, 6);
        assert_eq!(children[2].height, 7);
    }

    #[test]
    fn test_pop_nonexistent_parent() {
        let config = test_config(256, 16);
        let mut pool = OrphanBlockPool::new(&config);

        let children = pool.pop_children(&[0xFF; 32]);
        assert!(children.is_empty());
    }
}
