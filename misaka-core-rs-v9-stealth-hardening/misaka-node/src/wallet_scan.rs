// ============================================================
// MISAKA Node — Wallet Scan / Recipient Recovery + Spend Tracking
// ============================================================
//
// Two-pass scan pipeline per block:
//
//   Pass A — Outputs:
//     1. For each tx output: stealth scan
//     2. If owned: recover amount, derive expected link tag
//     3. Upsert WalletOwnedEnote with spend-tracking metadata
//
//   Pass B — Inputs:
//     1. For each tx input: extract link tag
//     2. Look up in wallet store by expected_link_tag
//     3. If match: mark owned enote as spent
//
// Privacy:
//   - expected_link_tag is wallet-local, never exposed via RPC
//   - spend_seed is never included in scan results
//   - one_time_key is stored locally but serde-skipped
//
// Restart safety / idempotency:
//   - upsert is idempotent (same enote_id -> update)
//   - mark_enote_spent is idempotent (re-marking is safe)
//   - last_scanned_height tracks progress
//
// ============================================================

use crate::wallet_store::{WalletStore, WalletOwnedEnote, WalletStoreError};
use misaka_tx::{TxBody, TxId, EnoteId, LinkTag};
use misaka_store::NodeStore;
use misaka_crypto::stealth::{StealthOutput, scan_output, derive_expected_link_tag};

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum WalletScanError {
    #[error("Scan height out of range: requested {requested}, chain tip {tip}")]
    ScanHeightOutOfRange { requested: u64, tip: u64 },
    #[error("Block not available at height {0}")]
    BlockNotAvailable(u64),
    #[error("Wallet store error: {0}")]
    StoreError(#[from] WalletStoreError),
    #[error("Recipient recovery failed: {0}")]
    RecipientRecoveryFailed(String),
    #[error("Link tag derivation failed: {0}")]
    LinkTagDerivationFailed(String),
}

// ════════════════════════════════════════════
// Scan context (wallet-local keys)
// ════════════════════════════════════════════

/// Context for wallet scanning + spend tracking.
///
/// Contains only the keys needed to detect, decrypt, and track
/// owned outputs. Created from JamtisWallet or directly.
///
/// `spend_seed`: optional. If provided, enables expected link tag
/// derivation for automatic spend detection. Without it, the wallet
/// can detect owned outputs but cannot automatically track spends.
pub struct WalletScanContext {
    /// Kyber-768 secret key for KEM decapsulation.
    pub view_sk: Vec<u8>,
    /// K1 = H(FINGERPRINT || spend_pk) -- identifies our stealth addresses.
    pub spend_pk_hash: [u8; 32],
    /// Spend seed for link tag derivation (first 32 bytes of wallet spend seed).
    /// Required for spend tracking. Optional for view-only wallets.
    pub spend_seed: Option<Vec<u8>>,
}

// ════════════════════════════════════════════
// Scan result
// ════════════════════════════════════════════

/// Result of scanning a block range.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub scanned_from: u64,
    pub scanned_to: u64,
    pub new_enotes_found: usize,
    pub spent_updates: usize,
}

// ════════════════════════════════════════════
// Scanner
// ════════════════════════════════════════════

/// Scan a range of blocks for owned outputs and spent inputs.
///
/// Two-pass pipeline per block:
///   Pass A: scan outputs for owned enotes + derive expected link tags
///   Pass B: scan inputs for matching link tags -> mark spends
///
/// Order: outputs scanned before inputs within each block, so
/// receive-and-spend in the same block is handled correctly.
///
/// Idempotent: re-scanning produces the same result.
pub fn scan_blocks<W: WalletStore>(
    store: &NodeStore,
    wallet: &WalletScanContext,
    wallet_store: &mut W,
    start_height: u64,
    end_height: u64,
) -> Result<ScanResult, WalletScanError> {
    let tip = store.tip_height();
    if end_height > tip {
        return Err(WalletScanError::ScanHeightOutOfRange {
            requested: end_height,
            tip,
        });
    }

    let mut new_enotes = 0usize;
    let mut spent_updates = 0usize;

    for height in start_height..=end_height {
        let block = store.get_block(height)
            .ok_or(WalletScanError::BlockNotAvailable(height))?;

        // -- Pass A: scan outputs for owned enotes --
        for tx in &block.transactions {
            let found = scan_tx_outputs(tx, height, wallet);
            for enote in found {
                wallet_store.upsert_enote(enote)?;
                new_enotes += 1;
            }
        }

        // -- Pass B: scan inputs for spend detection --
        for tx in &block.transactions {
            let updates = scan_tx_inputs_for_spends(tx, height, wallet_store)?;
            spent_updates += updates;
        }

        wallet_store.set_last_scanned_height(height)?;
    }

    Ok(ScanResult {
        scanned_from: start_height,
        scanned_to: end_height,
        new_enotes_found: new_enotes,
        spent_updates,
    })
}

/// Scan a single transaction's outputs for owned enotes.
fn scan_tx_outputs(
    tx: &TxBody,
    block_height: u64,
    wallet: &WalletScanContext,
) -> Vec<WalletOwnedEnote> {
    let mut found = Vec::new();

    for (idx, output) in tx.outputs.iter().enumerate() {
        let enote = &output.enote;

        let stealth = StealthOutput {
            stealth_address: enote.one_time_address,
            ephemeral_ct: enote.recipient_payload.ephemeral_ct.clone(),
            view_tag: enote.view_tag,
            amount_commitment: enote.amount_commitment.0,
            encrypted_amount: enote.recipient_payload.encrypted_amount,
            output_index: enote.recipient_payload.output_index,
            integrity_tag: vec![], // legacy: integrity verified at tx level
        };

        if let Some(received) = scan_output(&stealth, &wallet.view_sk, &wallet.spend_pk_hash) {
            let expected_link_tag = wallet.spend_seed.as_ref().map(|seed| {
                let tag_bytes = derive_expected_link_tag(seed, &received.one_time_key);
                LinkTag(tag_bytes)
            });

            found.push(WalletOwnedEnote {
                enote_id: enote.enote_id,
                tx_id: tx.tx_id,
                block_height,
                output_index: idx as u32,
                amount: received.amount,
                asset_id: enote.asset_id,
                one_time_address: enote.one_time_address,
                note_commitment: enote.note_commitment,
                amount_commitment: enote.amount_commitment,
                one_time_key: received.one_time_key,
                expected_link_tag,
                spent: false,
                spend_tx_id: None,
                spend_height: None,
            });
        }
    }

    found
}

/// Scan a transaction's inputs for link tags matching wallet-owned enotes.
fn scan_tx_inputs_for_spends<W: WalletStore>(
    tx: &TxBody,
    block_height: u64,
    wallet_store: &mut W,
) -> Result<usize, WalletScanError> {
    let mut updates = 0;

    for input in &tx.inputs {
        let tag = &input.link_tag;

        if let Some(owned) = wallet_store.find_by_expected_link_tag(tag)? {
            if owned.spent {
                continue; // idempotent
            }
            wallet_store.mark_enote_spent(
                &owned.enote_id,
                Some(&tx.tx_id),
                Some(block_height),
            )?;
            updates += 1;
        }
    }

    Ok(updates)
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_store::InMemoryWalletStore;
    use misaka_tx::*;
    use misaka_crypto::keys::JamtisWallet;
    use misaka_crypto::stealth::{create_stealth_output, JamtisAddress, derive_expected_link_tag as crypto_derive_tag};
    use misaka_crypto::ring_sig::{larrs_keygen, RingSignature};
    use misaka_crypto::commitment;
    use misaka_crypto::proof_backend::{TestnetBackend, RangeProofBackend, BalanceProofBackend};
    use misaka_crypto::hash::merkle_root;
    use misaka_store::{NodeStore, NodeRole, Block, BlockHeader};

    fn make_wallet() -> JamtisWallet { JamtisWallet::generate().unwrap() }

    fn make_scan_context(wallet: &JamtisWallet) -> WalletScanContext {
        let spend_seed = wallet.spend_keys.secret_key[..32].to_vec();
        WalletScanContext {
            view_sk: wallet.view_keys.secret_key.clone(),
            spend_pk_hash: wallet.k1,
            spend_seed: Some(spend_seed),
        }
    }

    fn make_view_only_context(wallet: &JamtisWallet) -> WalletScanContext {
        WalletScanContext {
            view_sk: wallet.view_keys.secret_key.clone(),
            spend_pk_hash: wallet.k1,
            spend_seed: None,
        }
    }

    fn make_tx_to_recipient(id_byte: u8, recipient: &JamtisAddress, amount: u64) -> TxBody {
        let kp = larrs_keygen(&[id_byte; 32]);
        let ring_proof = RingSignature {
            ring: vec![vec![0; 64]; 4], key_image: kp.key_image,
            c0: [0; 32], responses: vec![vec![0; 64]; 4],
        };
        let rpkh = TxInput::compute_ring_pk_hash(&ring_proof);
        let inp = TxInput {
            ring: RingMembers {
                members: [EnoteId([1; 32]), EnoteId([2; 32]), EnoteId([3; 32]), EnoteId([4; 32])],
                member_commitments: [AmountCommitment([0; 32]); 4],
            },
            ring_proof, link_tag: LinkTag(kp.key_image),
            pseudo_output_commitment: AmountCommitment([0; 32]), ring_pk_hash: rpkh,
        };
        let opening = commitment::commit(amount, 42);
        let stealth = create_stealth_output(recipient, amount, opening.hash, 0).unwrap();
        let payload = RecipientPayload::encrypt(
            &stealth.shared_secret, stealth.output.ephemeral_ct.clone(),
            amount, 42, b"", 0,
        );
        let ph = payload.hash();
        let nc = NoteCommitment::compute(
            &stealth.output.stealth_address,
            &AmountCommitment(stealth.output.amount_commitment),
            stealth.output.view_tag, &ph, &ASSET_NATIVE, ENOTE_VERSION,
        );
        let enote = Enote {
            enote_id: EnoteId([0xF0 + id_byte; 32]), enote_version: ENOTE_VERSION,
            asset_id: ASSET_NATIVE, one_time_address: stealth.output.stealth_address,
            amount_commitment: AmountCommitment(stealth.output.amount_commitment),
            note_commitment: nc, view_tag: stealth.output.view_tag,
            recipient_payload: payload, created_at: 0,
        };
        let out = TxOutput { enote };
        let fee = FeeStatement::compute(2000, 1);
        let bh = compute_tx_body_hash(&[inp.clone()], &[out.clone()], &fee);
        let bp = BalanceProofBackend::prove(&TestnetBackend,
            &[commitment::commit(100, 10)], &[commitment::commit(100, 10)], 0).unwrap();
        let rp = RangeProofBackend::prove(&TestnetBackend, &opening).unwrap();
        let proofs = TxProofBundle {
            balance_proof: bp, range_proofs: vec![rp],
            fee_proof: FeeProof::new(fee.total_fee), proof_backend_id: TestnetBackend::BACKEND_ID,
        };
        let proof_hash = compute_tx_proof_hash(&proofs);
        let binding_hash = compute_tx_binding_hash(&bh, &proof_hash, TX_VERSION, &[]);
        let tx_id = compute_tx_id(&binding_hash);
        TxBody {
            tx_id, tx_body_hash: bh, tx_proof_hash: proof_hash,
            tx_binding_hash: binding_hash, version: TX_VERSION,
            inputs: vec![inp], outputs: vec![out], proofs, fee,
            tx_extra: vec![], size_bytes: 2000,
        }
    }

    fn make_spending_tx(id_byte: u8, spend_link_tag: LinkTag, recipient: &JamtisAddress, amount: u64) -> TxBody {
        let kp = larrs_keygen(&[id_byte; 32]);
        let ring_proof = RingSignature {
            ring: vec![vec![0; 64]; 4], key_image: spend_link_tag.0,
            c0: [0; 32], responses: vec![vec![0; 64]; 4],
        };
        let rpkh = TxInput::compute_ring_pk_hash(&ring_proof);
        let inp = TxInput {
            ring: RingMembers {
                members: [EnoteId([1; 32]), EnoteId([2; 32]), EnoteId([3; 32]), EnoteId([4; 32])],
                member_commitments: [AmountCommitment([0; 32]); 4],
            },
            ring_proof, link_tag: spend_link_tag,
            pseudo_output_commitment: AmountCommitment([0; 32]), ring_pk_hash: rpkh,
        };
        let opening = commitment::commit(amount, 99);
        let stealth = create_stealth_output(recipient, amount, opening.hash, 0).unwrap();
        let payload = RecipientPayload::encrypt(
            &stealth.shared_secret, stealth.output.ephemeral_ct.clone(),
            amount, 99, b"", 0,
        );
        let ph = payload.hash();
        let nc = NoteCommitment::compute(
            &stealth.output.stealth_address,
            &AmountCommitment(stealth.output.amount_commitment),
            stealth.output.view_tag, &ph, &ASSET_NATIVE, ENOTE_VERSION,
        );
        let enote = Enote {
            enote_id: EnoteId([0xE0 + id_byte; 32]), enote_version: ENOTE_VERSION,
            asset_id: ASSET_NATIVE, one_time_address: stealth.output.stealth_address,
            amount_commitment: AmountCommitment(stealth.output.amount_commitment),
            note_commitment: nc, view_tag: stealth.output.view_tag,
            recipient_payload: payload, created_at: 0,
        };
        let out = TxOutput { enote };
        let fee = FeeStatement::compute(2000, 1);
        let bh = compute_tx_body_hash(&[inp.clone()], &[out.clone()], &fee);
        let bp = BalanceProofBackend::prove(&TestnetBackend,
            &[commitment::commit(100, 10)], &[commitment::commit(100, 10)], 0).unwrap();
        let rp = RangeProofBackend::prove(&TestnetBackend, &opening).unwrap();
        let proofs = TxProofBundle {
            balance_proof: bp, range_proofs: vec![rp],
            fee_proof: FeeProof::new(fee.total_fee), proof_backend_id: TestnetBackend::BACKEND_ID,
        };
        let proof_hash = compute_tx_proof_hash(&proofs);
        let binding_hash = compute_tx_binding_hash(&bh, &proof_hash, TX_VERSION, &[]);
        let tx_id = compute_tx_id(&binding_hash);
        TxBody {
            tx_id, tx_body_hash: bh, tx_proof_hash: proof_hash,
            tx_binding_hash: binding_hash, version: TX_VERSION,
            inputs: vec![inp], outputs: vec![out], proofs, fee,
            tx_extra: vec![], size_bytes: 2000,
        }
    }

    fn make_block(txs: Vec<TxBody>, height: u64, prev_hash: [u8; 32]) -> Block {
        let root = if txs.is_empty() { [0u8; 32] } else {
            let s: Vec<&[u8]> = txs.iter().map(|t| t.tx_id.0.as_slice()).collect();
            merkle_root(&s)
        };
        Block {
            header: BlockHeader {
                version: 2, height, round: 0, prev_hash, timestamp: 1000,
                tx_merkle_root: root, utxo_root: [0; 32], link_tag_root: [0; 32],
                proposer_id: [0xAA; 32], proposer_sig: vec![], bft_sigs: vec![],
            },
            transactions: txs,
        }
    }

    fn make_store_with_blocks(blocks: &[Block]) -> NodeStore {
        let mut ns = NodeStore::new(NodeRole::Archive);
        for id in [1u8, 2, 3, 4] {
            ns.state.insert_enote(&StoredEnote {
                enote_id: EnoteId([id; 32]), one_time_address: [id; 32],
                amount_commitment: AmountCommitment([0xCC; 32]),
                note_commitment: NoteCommitment([0; 32]), view_tag: 0,
                asset_id: ASSET_NATIVE, enote_version: ENOTE_VERSION, created_at: 0,
            }).unwrap();
        }
        for block in blocks { ns.commit_block(block, &TestnetBackend).unwrap(); }
        ns
    }

    // ── Link tag derivation ──

    #[test]
    fn test_expected_link_tag_deterministic() {
        let seed = [0x42u8; 32];
        let otk = [0xAA; 32];
        assert_eq!(crypto_derive_tag(&seed, &otk), crypto_derive_tag(&seed, &otk));
    }

    #[test]
    fn test_different_otk_different_tag() {
        let seed = [0x42u8; 32];
        assert_ne!(crypto_derive_tag(&seed, &[0xAA; 32]), crypto_derive_tag(&seed, &[0xBB; 32]));
    }

    // ── Output scan ──

    #[test]
    fn test_scan_finds_owned_with_link_tag() {
        let w = make_wallet();
        let ctx = make_scan_context(&w);
        let tx = make_tx_to_recipient(0x01, &w.receive_address(), 5000);
        let block = make_block(vec![tx], 0, [0u8; 32]);
        let ns = make_store_with_blocks(&[block]);
        let mut ws = InMemoryWalletStore::new();
        scan_blocks(&ns, &ctx, &mut ws, 0, 0).unwrap();
        let enotes = ws.list_enotes().unwrap();
        assert_eq!(enotes.len(), 1);
        assert_eq!(enotes[0].amount, 5000);
        assert!(enotes[0].expected_link_tag.is_some());
        assert!(!enotes[0].spent);
    }

    #[test]
    fn test_scan_ignores_foreign() {
        let wa = make_wallet(); let wb = make_wallet();
        let ctx = make_scan_context(&wa);
        let tx = make_tx_to_recipient(0x01, &wb.receive_address(), 1000);
        let block = make_block(vec![tx], 0, [0u8; 32]);
        let ns = make_store_with_blocks(&[block]);
        let mut ws = InMemoryWalletStore::new();
        assert_eq!(scan_blocks(&ns, &ctx, &mut ws, 0, 0).unwrap().new_enotes_found, 0);
    }

    #[test]
    fn test_repeated_scan_no_dup() {
        let w = make_wallet();
        let ctx = make_scan_context(&w);
        let tx = make_tx_to_recipient(0x01, &w.receive_address(), 3000);
        let block = make_block(vec![tx], 0, [0u8; 32]);
        let ns = make_store_with_blocks(&[block]);
        let mut ws = InMemoryWalletStore::new();
        scan_blocks(&ns, &ctx, &mut ws, 0, 0).unwrap();
        scan_blocks(&ns, &ctx, &mut ws, 0, 0).unwrap();
        assert_eq!(ws.enote_count(), 1);
    }

    #[test]
    fn test_view_only_no_link_tag() {
        let w = make_wallet();
        let ctx = make_view_only_context(&w);
        let tx = make_tx_to_recipient(0x01, &w.receive_address(), 2000);
        let block = make_block(vec![tx], 0, [0u8; 32]);
        let ns = make_store_with_blocks(&[block]);
        let mut ws = InMemoryWalletStore::new();
        scan_blocks(&ns, &ctx, &mut ws, 0, 0).unwrap();
        assert!(ws.list_enotes().unwrap()[0].expected_link_tag.is_none());
    }

    // ── Spend detection ──

    #[test]
    fn test_spend_detected() {
        let w = make_wallet();
        let ctx = make_scan_context(&w);
        let other = make_wallet();
        let tx_recv = make_tx_to_recipient(0x01, &w.receive_address(), 5000);
        let block0 = make_block(vec![tx_recv], 0, [0u8; 32]);

        // First scan to get expected tag
        let ns0 = make_store_with_blocks(&[block0.clone()]);
        let mut ws_tmp = InMemoryWalletStore::new();
        scan_blocks(&ns0, &ctx, &mut ws_tmp, 0, 0).unwrap();
        let tag = ws_tmp.list_enotes().unwrap()[0].expected_link_tag.unwrap();

        let tx_spend = make_spending_tx(0x02, tag, &other.receive_address(), 4000);
        let block1 = make_block(vec![tx_spend], 1, block0.hash());
        let ns = make_store_with_blocks(&[block0, block1]);

        let mut ws = InMemoryWalletStore::new();
        let r = scan_blocks(&ns, &ctx, &mut ws, 0, 1).unwrap();
        assert_eq!(r.spent_updates, 1);
        let e = &ws.list_enotes().unwrap()[0];
        assert!(e.spent);
        assert_eq!(e.spend_height, Some(1));
        let bal = ws.get_balance().unwrap();
        assert_eq!(bal.spendable, 0);
        assert_eq!(bal.spent, 5000);
    }

    #[test]
    fn test_foreign_spend_no_mark() {
        let w = make_wallet();
        let ctx = make_scan_context(&w);
        let tx_recv = make_tx_to_recipient(0x01, &w.receive_address(), 3000);
        let block0 = make_block(vec![tx_recv], 0, [0u8; 32]);
        let fkp = larrs_keygen(&[0x99; 32]);
        let other = make_wallet();
        let tx_foreign = make_spending_tx(0x03, LinkTag(fkp.key_image), &other.receive_address(), 1000);
        let block1 = make_block(vec![tx_foreign], 1, block0.hash());
        let ns = make_store_with_blocks(&[block0, block1]);
        let mut ws = InMemoryWalletStore::new();
        let r = scan_blocks(&ns, &ctx, &mut ws, 0, 1).unwrap();
        assert_eq!(r.spent_updates, 0);
        assert!(!ws.list_enotes().unwrap()[0].spent);
    }

    #[test]
    fn test_repeated_spend_scan_idempotent() {
        let w = make_wallet();
        let ctx = make_scan_context(&w);
        let other = make_wallet();
        let tx_recv = make_tx_to_recipient(0x01, &w.receive_address(), 4000);
        let block0 = make_block(vec![tx_recv], 0, [0u8; 32]);
        let ns0 = make_store_with_blocks(&[block0.clone()]);
        let mut ws_tmp = InMemoryWalletStore::new();
        scan_blocks(&ns0, &ctx, &mut ws_tmp, 0, 0).unwrap();
        let tag = ws_tmp.list_enotes().unwrap()[0].expected_link_tag.unwrap();
        let tx_spend = make_spending_tx(0x02, tag, &other.receive_address(), 3000);
        let block1 = make_block(vec![tx_spend], 1, block0.hash());
        let ns = make_store_with_blocks(&[block0, block1]);
        let mut ws = InMemoryWalletStore::new();
        scan_blocks(&ns, &ctx, &mut ws, 0, 1).unwrap();
        scan_blocks(&ns, &ctx, &mut ws, 0, 1).unwrap();
        assert_eq!(ws.get_balance().unwrap().spent, 4000);
    }

    #[test]
    fn test_receive_and_spend_same_range() {
        let w = make_wallet();
        let ctx = make_scan_context(&w);
        let other = make_wallet();
        let tx_recv = make_tx_to_recipient(0x01, &w.receive_address(), 6000);
        let block0 = make_block(vec![tx_recv], 0, [0u8; 32]);
        let ns0 = make_store_with_blocks(&[block0.clone()]);
        let mut ws_tmp = InMemoryWalletStore::new();
        scan_blocks(&ns0, &ctx, &mut ws_tmp, 0, 0).unwrap();
        let tag = ws_tmp.list_enotes().unwrap()[0].expected_link_tag.unwrap();
        let tx_spend = make_spending_tx(0x02, tag, &other.receive_address(), 5000);
        let block1 = make_block(vec![tx_spend], 1, block0.hash());
        let ns = make_store_with_blocks(&[block0, block1]);
        let mut ws = InMemoryWalletStore::new();
        let r = scan_blocks(&ns, &ctx, &mut ws, 0, 1).unwrap();
        assert_eq!(r.new_enotes_found, 1);
        assert_eq!(r.spent_updates, 1);
        assert_eq!(ws.get_balance().unwrap().spendable, 0);
    }

    #[test]
    fn test_balance_reflects_scan() {
        let w = make_wallet();
        let ctx = make_scan_context(&w);
        let tx = make_tx_to_recipient(0x01, &w.receive_address(), 7000);
        let block = make_block(vec![tx], 0, [0u8; 32]);
        let ns = make_store_with_blocks(&[block]);
        let mut ws = InMemoryWalletStore::new();
        scan_blocks(&ns, &ctx, &mut ws, 0, 0).unwrap();
        let bal = ws.get_balance().unwrap();
        assert_eq!(bal.total, 7000);
        assert_eq!(bal.spendable, 7000);
        assert_eq!(bal.spent, 0);
    }

    #[test]
    fn test_scan_height_out_of_range() {
        let w = make_wallet();
        let ctx = make_scan_context(&w);
        let ns = NodeStore::new(NodeRole::Archive);
        let mut ws = InMemoryWalletStore::new();
        assert!(matches!(scan_blocks(&ns, &ctx, &mut ws, 0, 100),
            Err(WalletScanError::ScanHeightOutOfRange { .. })));
    }

    #[test]
    fn test_last_scanned_height() {
        let w = make_wallet();
        let ctx = make_scan_context(&w);
        let tx = make_tx_to_recipient(0x01, &w.receive_address(), 1000);
        let block = make_block(vec![tx], 0, [0u8; 32]);
        let ns = make_store_with_blocks(&[block]);
        let mut ws = InMemoryWalletStore::new();
        scan_blocks(&ns, &ctx, &mut ws, 0, 0).unwrap();
        assert_eq!(ws.last_scanned_height().unwrap(), 0);
    }
}
