// ============================================================
// MISAKA Node — Wallet Store (local scan state)
// ============================================================
//
// Wallet-local persistence for recovered enotes and balances.
// Completely separate from chain state — no secret keys exposed.
//
// ============================================================

use misaka_tx::{TxId, EnoteId, AmountCommitment, NoteCommitment, LinkTag};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// ════════════════════════════════════════════
// Types
// ════════════════════════════════════════════

/// A wallet-owned enote recovered by scanning the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletOwnedEnote {
    pub enote_id: EnoteId,
    pub tx_id: TxId,
    pub block_height: u64,
    pub output_index: u32,
    pub amount: u64,
    pub asset_id: [u8; 32],
    pub one_time_address: [u8; 32],
    pub note_commitment: NoteCommitment,
    pub amount_commitment: AmountCommitment,
    /// One-time key recovered during stealth scan.
    /// Used to derive the expected link tag for spend tracking.
    /// Wallet-local — never exposed via public RPC.
    #[serde(skip_serializing)]
    pub one_time_key: [u8; 32],
    /// Expected link tag: the link tag that will appear in a tx input
    /// when this enote is spent. Derived from wallet spend seed + one_time_key.
    /// Used for automatic spend detection during chain scanning.
    /// Wallet-local — never exposed via public RPC.
    #[serde(skip_serializing)]
    pub expected_link_tag: Option<LinkTag>,
    /// True if this enote has been consumed (link tag observed in chain).
    pub spent: bool,
    /// TX that consumed this enote, if known.
    pub spend_tx_id: Option<TxId>,
    /// Block height at which the spend was observed.
    pub spend_height: Option<u64>,
}

/// Wallet balance summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletBalance {
    /// Total amount of all recovered enotes (spent + spendable).
    pub total: u128,
    /// Amount of unspent enotes available for spending.
    pub spendable: u128,
    /// Amount of enotes that have been consumed.
    pub spent: u128,
}

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum WalletStoreError {
    #[error("Wallet store error: {0}")]
    Internal(String),
    #[error("Enote not found: {0}")]
    EnoteNotFound(String),
}

// ════════════════════════════════════════════
// Trait
// ════════════════════════════════════════════

/// Wallet-local persistence for scan results.
///
/// Implementations: in-memory (testing), SQLite (future), etc.
/// Completely separate from chain state store.
pub trait WalletStore {
    fn last_scanned_height(&self) -> Result<u64, WalletStoreError>;
    fn set_last_scanned_height(&mut self, height: u64) -> Result<(), WalletStoreError>;

    fn upsert_enote(&mut self, enote: WalletOwnedEnote) -> Result<(), WalletStoreError>;
    fn mark_enote_spent(
        &mut self,
        enote_id: &EnoteId,
        spend_tx_id: Option<&TxId>,
        spend_height: Option<u64>,
    ) -> Result<(), WalletStoreError>;

    /// Find an owned enote by its expected link tag.
    ///
    /// Returns the enote whose expected_link_tag matches, if any.
    /// Used during spend detection: when a tx input link tag is observed,
    /// look up whether it matches any of our owned enotes.
    fn find_by_expected_link_tag(&self, tag: &LinkTag) -> Result<Option<WalletOwnedEnote>, WalletStoreError>;

    fn list_enotes(&self) -> Result<Vec<WalletOwnedEnote>, WalletStoreError>;
    fn get_balance(&self) -> Result<WalletBalance, WalletStoreError>;
    fn enote_count(&self) -> usize;
}

// ════════════════════════════════════════════
// In-memory implementation
// ════════════════════════════════════════════

/// In-memory wallet store for testing and lightweight usage.
pub struct InMemoryWalletStore {
    enotes: HashMap<EnoteId, WalletOwnedEnote>,
    /// Index: expected_link_tag → enote_id for O(1) spend detection.
    link_tag_index: HashMap<LinkTag, EnoteId>,
    last_scanned: u64,
}

impl InMemoryWalletStore {
    pub fn new() -> Self {
        Self {
            enotes: HashMap::new(),
            link_tag_index: HashMap::new(),
            last_scanned: 0,
        }
    }
}

impl WalletStore for InMemoryWalletStore {
    fn last_scanned_height(&self) -> Result<u64, WalletStoreError> {
        Ok(self.last_scanned)
    }

    fn set_last_scanned_height(&mut self, height: u64) -> Result<(), WalletStoreError> {
        self.last_scanned = height;
        Ok(())
    }

    fn upsert_enote(&mut self, enote: WalletOwnedEnote) -> Result<(), WalletStoreError> {
        // Maintain link tag index
        if let Some(tag) = enote.expected_link_tag {
            self.link_tag_index.insert(tag, enote.enote_id);
        }
        self.enotes.insert(enote.enote_id, enote);
        Ok(())
    }

    fn mark_enote_spent(
        &mut self,
        enote_id: &EnoteId,
        spend_tx_id: Option<&TxId>,
        spend_height: Option<u64>,
    ) -> Result<(), WalletStoreError> {
        if let Some(e) = self.enotes.get_mut(enote_id) {
            e.spent = true;
            e.spend_tx_id = spend_tx_id.copied();
            e.spend_height = spend_height;
            Ok(())
        } else {
            Err(WalletStoreError::EnoteNotFound(hex::encode(enote_id.0)))
        }
    }

    fn find_by_expected_link_tag(&self, tag: &LinkTag) -> Result<Option<WalletOwnedEnote>, WalletStoreError> {
        if let Some(enote_id) = self.link_tag_index.get(tag) {
            Ok(self.enotes.get(enote_id).cloned())
        } else {
            Ok(None)
        }
    }

    fn list_enotes(&self) -> Result<Vec<WalletOwnedEnote>, WalletStoreError> {
        let mut enotes: Vec<_> = self.enotes.values().cloned().collect();
        enotes.sort_by_key(|e| (e.block_height, e.output_index));
        Ok(enotes)
    }

    fn get_balance(&self) -> Result<WalletBalance, WalletStoreError> {
        let mut total: u128 = 0;
        let mut spendable: u128 = 0;
        let mut spent: u128 = 0;
        for e in self.enotes.values() {
            total += e.amount as u128;
            if e.spent {
                spent += e.amount as u128;
            } else {
                spendable += e.amount as u128;
            }
        }
        Ok(WalletBalance { total, spendable, spent })
    }

    fn enote_count(&self) -> usize { self.enotes.len() }
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_tx::ASSET_NATIVE;

    fn dummy_enote(id_byte: u8, amount: u64, height: u64) -> WalletOwnedEnote {
        WalletOwnedEnote {
            enote_id: EnoteId([id_byte; 32]),
            tx_id: TxId([id_byte; 32]),
            block_height: height,
            output_index: 0,
            amount,
            asset_id: ASSET_NATIVE,
            one_time_address: [id_byte; 32],
            note_commitment: NoteCommitment([0; 32]),
            amount_commitment: AmountCommitment([0; 32]),
            one_time_key: [id_byte; 32],
            expected_link_tag: Some(LinkTag([id_byte; 32])),
            spent: false,
            spend_tx_id: None,
            spend_height: None,
        }
    }

    #[test]
    fn test_upsert_and_list() {
        let mut store = InMemoryWalletStore::new();
        store.upsert_enote(dummy_enote(1, 100, 0)).unwrap();
        store.upsert_enote(dummy_enote(2, 200, 1)).unwrap();

        let enotes = store.list_enotes().unwrap();
        assert_eq!(enotes.len(), 2);
        assert_eq!(enotes[0].amount, 100);
        assert_eq!(enotes[1].amount, 200);
    }

    #[test]
    fn test_upsert_dedup() {
        let mut store = InMemoryWalletStore::new();
        store.upsert_enote(dummy_enote(1, 100, 0)).unwrap();
        store.upsert_enote(dummy_enote(1, 100, 0)).unwrap();
        assert_eq!(store.enote_count(), 1);
    }

    #[test]
    fn test_mark_spent() {
        let mut store = InMemoryWalletStore::new();
        store.upsert_enote(dummy_enote(1, 100, 0)).unwrap();
        store.mark_enote_spent(&EnoteId([1; 32]), Some(&TxId([0xFF; 32])), Some(5)).unwrap();

        let enotes = store.list_enotes().unwrap();
        assert!(enotes[0].spent);
        assert_eq!(enotes[0].spend_tx_id, Some(TxId([0xFF; 32])));
        assert_eq!(enotes[0].spend_height, Some(5));
    }

    #[test]
    fn test_balance() {
        let mut store = InMemoryWalletStore::new();
        store.upsert_enote(dummy_enote(1, 100, 0)).unwrap();
        store.upsert_enote(dummy_enote(2, 200, 1)).unwrap();
        store.mark_enote_spent(&EnoteId([1; 32]), None, None).unwrap();

        let bal = store.get_balance().unwrap();
        assert_eq!(bal.total, 300);
        assert_eq!(bal.spendable, 200);
        assert_eq!(bal.spent, 100);
    }

    #[test]
    fn test_last_scanned_height() {
        let mut store = InMemoryWalletStore::new();
        assert_eq!(store.last_scanned_height().unwrap(), 0);
        store.set_last_scanned_height(42).unwrap();
        assert_eq!(store.last_scanned_height().unwrap(), 42);
    }

    #[test]
    fn test_find_by_expected_link_tag() {
        let mut store = InMemoryWalletStore::new();
        store.upsert_enote(dummy_enote(1, 100, 0)).unwrap();
        store.upsert_enote(dummy_enote(2, 200, 1)).unwrap();

        let found = store.find_by_expected_link_tag(&LinkTag([1; 32])).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().enote_id, EnoteId([1; 32]));

        let not_found = store.find_by_expected_link_tag(&LinkTag([99; 32])).unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_mark_spent_updates_balance() {
        let mut store = InMemoryWalletStore::new();
        store.upsert_enote(dummy_enote(1, 500, 0)).unwrap();

        let bal = store.get_balance().unwrap();
        assert_eq!(bal.spendable, 500);

        store.mark_enote_spent(&EnoteId([1; 32]), Some(&TxId([0xAA; 32])), Some(3)).unwrap();

        let bal = store.get_balance().unwrap();
        assert_eq!(bal.spendable, 0);
        assert_eq!(bal.spent, 500);
    }
}
