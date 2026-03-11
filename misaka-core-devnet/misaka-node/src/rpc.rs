// ============================================================
// MISAKA Node — Minimal RPC / Node API
// ============================================================
//
// Transport-agnostic RPC handler. Produces typed responses that
// can be serialized to JSON by any HTTP/WS framework.
//
// Privacy:
//   - Public chain data only via chain RPCs
//   - Wallet scan results are local wallet state
//   - No secret keys exposed in any response
//
// Startup gating:
//   - State-mutating RPCs (submit_tx) reject with RecoveryNotReady
//     if the node hasn't finished recovery
//   - Read-only RPCs work any time
//
// ============================================================

use crate::{NodeStartupPhase, wallet_store::{WalletStore, WalletOwnedEnote, WalletBalance}};
use crate::wallet_scan::{scan_blocks, WalletScanContext, ScanResult, WalletScanError};
use misaka_tx::{TxBody, TxId};
use misaka_store::{NodeStore, Block, BlockHeader};
use misaka_mempool::{Mempool, MempoolStoreView, AdmitResult};
use serde::{Serialize, Deserialize};

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("Recovery not ready: node is in phase {0:?}")]
    RecoveryNotReady(NodeStartupPhase),
    #[error("Transaction submission rejected: {0}")]
    TxSubmissionRejected(String),
    #[error("Block not found at height {0}")]
    BlockNotFound(u64),
    #[error("Transaction not found: {0}")]
    TxNotFound(String),
    #[error("Invalid scan range: {0}")]
    InvalidScanRange(String),
    #[error("Wallet scan error: {0}")]
    WalletScanError(#[from] WalletScanError),
    #[error("Wallet store error: {0}")]
    WalletStoreError(#[from] crate::wallet_store::WalletStoreError),
}

// ════════════════════════════════════════════
// Response types (JSON-serializable)
// ════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeightResponse {
    pub height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTipResponse {
    pub height: u64,
    pub tip_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetChainStatusResponse {
    pub height: u64,
    pub tip_hash: String,
    pub mempool_tx_count: usize,
    pub startup_phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetMempoolInfoResponse {
    pub tx_count: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxResponse {
    pub accepted: bool,
    pub tx_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutputsResponse {
    pub scanned_from: u64,
    pub scanned_to: u64,
    pub new_enotes_found: usize,
    pub total_owned_enotes: usize,
    pub spendable_balance: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListEnotesResponse {
    pub enotes: Vec<EnoteInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnoteInfo {
    pub enote_id: String,
    pub tx_id: String,
    pub block_height: u64,
    pub output_index: u32,
    pub amount: u64,
    pub spent: bool,
    pub spend_tx_id: Option<String>,
    pub spend_height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBalanceResponse {
    pub total: u128,
    pub spendable: u128,
    pub spent: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetWalletStatusResponse {
    pub last_scanned_height: u64,
    pub owned_enotes: usize,
    pub spendable_balance: u128,
}

// ════════════════════════════════════════════
// RPC handler
// ════════════════════════════════════════════

/// Transport-agnostic RPC handler.
///
/// Holds references to node state. Caller provides &mut references
/// for each call. No internal mutexes — the caller manages concurrency.
pub struct RpcHandler;

impl RpcHandler {
    // ── Chain / node RPCs (read-only, always available) ──

    pub fn get_height(store: &NodeStore) -> GetHeightResponse {
        GetHeightResponse { height: store.tip_height() }
    }

    pub fn get_tip(store: &NodeStore) -> GetTipResponse {
        GetTipResponse {
            height: store.tip_height(),
            tip_hash: hex::encode(store.state.tip_hash()),
        }
    }

    pub fn get_chain_status(
        store: &NodeStore,
        mempool: &Mempool,
        phase: NodeStartupPhase,
    ) -> GetChainStatusResponse {
        GetChainStatusResponse {
            height: store.tip_height(),
            tip_hash: hex::encode(store.state.tip_hash()),
            mempool_tx_count: mempool.len(),
            startup_phase: format!("{:?}", phase),
        }
    }

    pub fn get_mempool_info(mempool: &Mempool) -> GetMempoolInfoResponse {
        GetMempoolInfoResponse {
            tx_count: mempool.len(),
            total_bytes: mempool.total_bytes(),
        }
    }

    pub fn get_block(store: &NodeStore, height: u64) -> Result<Block, RpcError> {
        store.get_block(height)
            .ok_or(RpcError::BlockNotFound(height))
    }

    // ── Transaction submission (requires Recovered+ phase) ──

    /// Submit a transaction through the mempool admission path.
    ///
    /// Rejects if node is still in Recovering phase.
    /// Does NOT bypass any existing validation rules.
    pub fn submit_tx<S, V>(
        tx: TxBody,
        mempool: &mut Mempool,
        store_view: &S,
        verify_proofs: V,
        phase: NodeStartupPhase,
    ) -> Result<SubmitTxResponse, RpcError>
    where
        S: MempoolStoreView,
        V: FnOnce(&TxBody) -> Result<(), String>,
    {
        if phase == NodeStartupPhase::Recovering {
            return Err(RpcError::RecoveryNotReady(phase));
        }

        let tx_id = tx.tx_id;
        match mempool.admit_tx(tx, store_view, verify_proofs) {
            AdmitResult::Accepted { .. } => Ok(SubmitTxResponse {
                accepted: true,
                tx_id: Some(hex::encode(tx_id.0)),
                error: None,
            }),
            AdmitResult::Rejected(err) => Ok(SubmitTxResponse {
                accepted: false,
                tx_id: None,
                error: Some(err.to_string()),
            }),
        }
    }

    // ── Wallet RPCs (local wallet state, requires scan context) ──

    /// Scan a block range for wallet-owned outputs.
    pub fn scan_outputs<W: WalletStore>(
        store: &NodeStore,
        wallet_ctx: &WalletScanContext,
        wallet_store: &mut W,
        start_height: u64,
        end_height: u64,
    ) -> Result<ScanOutputsResponse, RpcError> {
        let result = scan_blocks(store, wallet_ctx, wallet_store, start_height, end_height)?;
        let balance = wallet_store.get_balance()?;

        Ok(ScanOutputsResponse {
            scanned_from: result.scanned_from,
            scanned_to: result.scanned_to,
            new_enotes_found: result.new_enotes_found,
            total_owned_enotes: wallet_store.enote_count(),
            spendable_balance: balance.spendable,
        })
    }

    /// List all wallet-owned enotes.
    ///
    /// No secret keys in response — only public enote metadata + amounts.
    pub fn list_enotes<W: WalletStore>(
        wallet_store: &W,
    ) -> Result<ListEnotesResponse, RpcError> {
        let enotes = wallet_store.list_enotes()?;
        let infos: Vec<EnoteInfo> = enotes.into_iter().map(|e| EnoteInfo {
            enote_id: hex::encode(e.enote_id.0),
            tx_id: hex::encode(e.tx_id.0),
            block_height: e.block_height,
            output_index: e.output_index,
            amount: e.amount,
            spent: e.spent,
            spend_tx_id: e.spend_tx_id.map(|id| hex::encode(id.0)),
            spend_height: e.spend_height,
        }).collect();
        Ok(ListEnotesResponse { enotes: infos })
    }

    /// Get wallet balance.
    pub fn get_balance<W: WalletStore>(
        wallet_store: &W,
    ) -> Result<GetBalanceResponse, RpcError> {
        let bal = wallet_store.get_balance()?;
        Ok(GetBalanceResponse {
            total: bal.total,
            spendable: bal.spendable,
            spent: bal.spent,
        })
    }

    /// Get wallet scan status.
    pub fn get_wallet_status<W: WalletStore>(
        wallet_store: &W,
    ) -> Result<GetWalletStatusResponse, RpcError> {
        let height = wallet_store.last_scanned_height()?;
        let balance = wallet_store.get_balance()?;
        Ok(GetWalletStatusResponse {
            last_scanned_height: height,
            owned_enotes: wallet_store.enote_count(),
            spendable_balance: balance.spendable,
        })
    }
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
    use misaka_crypto::stealth::create_stealth_output;
    use misaka_crypto::commitment;
    use misaka_crypto::proof_backend::{TestnetBackend, RangeProofBackend, BalanceProofBackend};
    use misaka_crypto::ring_sig::{RingSignature, larrs_keygen};
    use misaka_crypto::hash::merkle_root;
    use misaka_store::{NodeStore, NodeRole, BlockHeader};

    // ── Helpers ──

    fn make_wallet() -> JamtisWallet { JamtisWallet::generate().unwrap() }
    fn make_ctx(w: &JamtisWallet) -> WalletScanContext {
        WalletScanContext {
            view_sk: w.view_keys.secret_key.clone(),
            spend_pk_hash: w.k1,
            spend_seed: Some(w.spend_keys.secret_key[..32].to_vec()),
        }
    }

    fn make_tx_to(addr: &misaka_crypto::stealth::JamtisAddress, amount: u64, id_byte: u8) -> TxBody {
        let kp = larrs_keygen(&[id_byte; 32]);
        let ring_proof = RingSignature {
            ring: vec![vec![0; 64]; 4],
            key_image: kp.key_image,
            c0: [0; 32],
            responses: vec![vec![0; 64]; 4],
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
        let stealth = create_stealth_output(addr, amount, opening.hash, 0).unwrap();
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
            enote_id: EnoteId([0xF0 + id_byte; 32]),
            enote_version: ENOTE_VERSION, asset_id: ASSET_NATIVE,
            one_time_address: stealth.output.stealth_address,
            amount_commitment: AmountCommitment(stealth.output.amount_commitment),
            note_commitment: nc, view_tag: stealth.output.view_tag,
            recipient_payload: payload, created_at: 0,
        };
        let out = TxOutput { enote };
        let fee = FeeStatement::compute(2000, 1);
        let body_hash = compute_tx_body_hash(&[inp.clone()], &[out.clone()], &fee);
        let bp = BalanceProofBackend::prove(&TestnetBackend,
            &[commitment::commit(100, 10)], &[commitment::commit(100, 10)], 0).unwrap();
        let rp = RangeProofBackend::prove(&TestnetBackend, &opening).unwrap();
        let proofs = TxProofBundle {
            balance_proof: bp, range_proofs: vec![rp],
            fee_proof: FeeProof::new(fee.total_fee),
            proof_backend_id: TestnetBackend::BACKEND_ID,
        };
        let proof_hash = compute_tx_proof_hash(&proofs);
        let binding_hash = compute_tx_binding_hash(&body_hash, &proof_hash, TX_VERSION, &[]);
        let tx_id = compute_tx_id(&binding_hash);
        TxBody {
            tx_id, tx_body_hash: body_hash, tx_proof_hash: proof_hash,
            tx_binding_hash: binding_hash, version: TX_VERSION,
            inputs: vec![inp], outputs: vec![out], proofs, fee,
            tx_extra: vec![], size_bytes: 2000,
        }
    }

    fn seeded_archive_store(block: &Block) -> NodeStore {
        let mut ns = NodeStore::new(NodeRole::Archive);
        for id in [1u8, 2, 3, 4] {
            ns.state.insert_enote(&StoredEnote {
                enote_id: EnoteId([id; 32]),
                one_time_address: [id; 32],
                amount_commitment: AmountCommitment([0xCC; 32]),
                note_commitment: NoteCommitment([0; 32]),
                view_tag: 0, asset_id: ASSET_NATIVE,
                enote_version: ENOTE_VERSION, created_at: 0,
            }).unwrap();
        }
        ns.commit_block(block, &TestnetBackend).unwrap();
        ns
    }

    fn make_block(txs: Vec<TxBody>, h: u64, prev: [u8; 32]) -> Block {
        let root = if txs.is_empty() { [0u8; 32] } else {
            let s: Vec<&[u8]> = txs.iter().map(|t| t.tx_id.0.as_slice()).collect();
            merkle_root(&s)
        };
        Block {
            header: BlockHeader {
                version: 2, height: h, round: 0, prev_hash: prev, timestamp: 1000,
                tx_merkle_root: root, utxo_root: [0; 32], link_tag_root: [0; 32],
                proposer_id: [0xAA; 32], proposer_sig: vec![], bft_sigs: vec![],
            },
            transactions: txs,
        }
    }

    // ════════════════════════════════════════════
    // Chain RPC tests
    // ════════════════════════════════════════════

    #[test]
    fn test_get_height() {
        let ns = NodeStore::new(NodeRole::Archive);
        let resp = RpcHandler::get_height(&ns);
        assert_eq!(resp.height, 0);
    }

    #[test]
    fn test_get_tip() {
        let ns = NodeStore::new(NodeRole::Archive);
        let resp = RpcHandler::get_tip(&ns);
        assert_eq!(resp.height, 0);
    }

    #[test]
    fn test_get_chain_status() {
        let ns = NodeStore::new(NodeRole::Archive);
        let mp = Mempool::with_defaults();
        let resp = RpcHandler::get_chain_status(&ns, &mp, NodeStartupPhase::Recovered);
        assert_eq!(resp.height, 0);
        assert_eq!(resp.startup_phase, "Recovered");
    }

    #[test]
    fn test_get_block_found() {
        let w = make_wallet();
        let tx = make_tx_to(&w.receive_address(), 1000, 0x01);
        let block = make_block(vec![tx], 0, [0u8; 32]);
        let ns = seeded_archive_store(&block);

        let result = RpcHandler::get_block(&ns, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_block_not_found() {
        let ns = NodeStore::new(NodeRole::Archive);
        let result = RpcHandler::get_block(&ns, 999);
        assert!(matches!(result, Err(RpcError::BlockNotFound(999))));
    }

    // ════════════════════════════════════════════
    // Submit TX tests
    // ════════════════════════════════════════════

    #[test]
    fn test_submit_tx_rejected_during_recovery() {
        let mut mp = Mempool::with_defaults();
        let tx = TxBody {
            tx_id: TxId([0; 32]),
            tx_body_hash: misaka_tx::TxBodyHash([0; 32]),
            tx_proof_hash: misaka_tx::TxProofHash([0; 32]),
            tx_binding_hash: misaka_tx::TxBindingHash([0; 32]),
            version: 2, inputs: vec![], outputs: vec![],
            proofs: misaka_tx::TxProofBundle {
                balance_proof: misaka_crypto::proof_backend::BalanceProofData { proof: vec![] },
                range_proofs: vec![],
                fee_proof: misaka_tx::FeeProof::new(0),
                proof_backend_id: 1,
            },
            fee: misaka_tx::FeeStatement::compute(100, 1),
            tx_extra: vec![], size_bytes: 100,
        };

        struct DummyView;
        impl MempoolStoreView for DummyView {
            fn has_link_tag(&self, _: &misaka_tx::LinkTag) -> Result<bool, String> { Ok(false) }
            fn ring_member_exists(&self, _: &misaka_tx::EnoteId) -> Result<bool, String> { Ok(true) }
        }

        let result = RpcHandler::submit_tx(
            tx, &mut mp, &DummyView, |_| Ok(()),
            NodeStartupPhase::Recovering,
        );
        assert!(matches!(result, Err(RpcError::RecoveryNotReady(_))));
    }

    // ════════════════════════════════════════════
    // Wallet RPC integration tests
    // ════════════════════════════════════════════

    #[test]
    fn test_scan_and_list_and_balance() {
        let w = make_wallet();
        let ctx = make_ctx(&w);
        let addr = w.receive_address();

        let tx = make_tx_to(&addr, 8000, 0x01);
        let block = make_block(vec![tx], 0, [0u8; 32]);
        let ns = seeded_archive_store(&block);
        let mut ws = InMemoryWalletStore::new();

        // Scan
        let scan_resp = RpcHandler::scan_outputs(&ns, &ctx, &mut ws, 0, 0).unwrap();
        assert_eq!(scan_resp.new_enotes_found, 1);
        assert_eq!(scan_resp.total_owned_enotes, 1);
        assert_eq!(scan_resp.spendable_balance, 8000);

        // List
        let list_resp = RpcHandler::list_enotes(&ws).unwrap();
        assert_eq!(list_resp.enotes.len(), 1);
        assert_eq!(list_resp.enotes[0].amount, 8000);
        assert!(!list_resp.enotes[0].spent);
        // No secret keys in response
        assert!(list_resp.enotes[0].enote_id.len() == 64); // hex-encoded

        // Balance
        let bal_resp = RpcHandler::get_balance(&ws).unwrap();
        assert_eq!(bal_resp.spendable, 8000);
        assert_eq!(bal_resp.spent, 0);

        // Wallet status
        let status = RpcHandler::get_wallet_status(&ws).unwrap();
        assert_eq!(status.owned_enotes, 1);
    }

    #[test]
    fn test_rpc_responses_no_secrets() {
        let w = make_wallet();
        let ctx = make_ctx(&w);
        let addr = w.receive_address();

        let tx = make_tx_to(&addr, 1000, 0x01);
        let block = make_block(vec![tx], 0, [0u8; 32]);
        let ns = seeded_archive_store(&block);
        let mut ws = InMemoryWalletStore::new();

        RpcHandler::scan_outputs(&ns, &ctx, &mut ws, 0, 0).unwrap();
        let list = RpcHandler::list_enotes(&ws).unwrap();

        // Serialize to JSON and verify no secret-key-like fields
        let json = serde_json::to_string(&list).unwrap();
        assert!(!json.contains("view_sk"));
        assert!(!json.contains("spend_sk"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("private"));
        assert!(!json.contains("one_time_key"));
        assert!(!json.contains("expected_link_tag"));
        assert!(!json.contains("spend_seed"));
    }
}
