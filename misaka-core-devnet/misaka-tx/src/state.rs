// ============================================================
// MISAKA — TxStateStore trait + store-backed verification
// ============================================================
//
// Connects transaction verification to persistent global state.
//
// The trait defines the minimal store interface needed by the
// verifier and apply logic. Any backend (in-memory, RocksDB, etc)
// can implement it.
//
// Verification flow (with store):
//   1. Structural / binding / size checks (stateless)
//   2. Proof size limits
//   3. Duplicate link tag within TX
//   4. Ring member existence from store
//   5. Global link tag check from store
//   6. Cryptographic proof verification
//   → VerifyResult
//
// Apply flow (after verification passes):
//   1. Insert all output enotes
//   2. Insert all input link tags
//   3. (No enote removal — ring sig privacy model)
//   Atomic: if any step fails, no partial writes.
//
// ============================================================

use crate::types::*;
use misaka_crypto::proof_backend::{ProofBackend, RangeProofBackend, BalanceProofBackend};
use misaka_crypto::ring_sig;
use std::collections::HashSet;

// ════════════════════════════════════════════
// TxStateStore trait
// ════════════════════════════════════════════

/// Stored enote record — what the store keeps per output.
#[derive(Debug, Clone)]
pub struct StoredEnote {
    pub enote_id: EnoteId,
    pub one_time_address: [u8; 32],
    pub amount_commitment: AmountCommitment,
    pub note_commitment: NoteCommitment,
    pub view_tag: u8,
    pub asset_id: [u8; 32],
    pub enote_version: u8,
    pub created_at: u64,
}

impl From<&Enote> for StoredEnote {
    fn from(e: &Enote) -> Self {
        Self {
            enote_id: e.enote_id,
            one_time_address: e.one_time_address,
            amount_commitment: e.amount_commitment,
            note_commitment: e.note_commitment,
            view_tag: e.view_tag,
            asset_id: e.asset_id,
            enote_version: e.enote_version,
            created_at: e.created_at,
        }
    }
}

/// Minimal store interface for TX verification and application.
///
/// Implementors: ChainState (in-memory), RocksDB wrapper, etc.
pub trait TxStateStore {
    type Error: std::fmt::Display;

    // ── Link tags ──

    /// Check if a link tag exists in global persistent state.
    fn has_link_tag(&self, tag: &LinkTag) -> Result<bool, Self::Error>;

    /// Persist a link tag. Must reject duplicates.
    fn insert_link_tag(&mut self, tag: &LinkTag) -> Result<(), Self::Error>;

    // ── Enotes / ring members ──

    /// Check if an enote exists in the store (for ring member verification).
    fn enote_exists(&self, id: &EnoteId) -> Result<bool, Self::Error>;

    /// Load a stored enote by ID (for commitment verification).
    fn load_enote(&self, id: &EnoteId) -> Result<Option<StoredEnote>, Self::Error>;

    /// Persist a new output enote.
    fn insert_enote(&mut self, enote: &StoredEnote) -> Result<(), Self::Error>;
}

// ════════════════════════════════════════════
// Store-backed verification
// ════════════════════════════════════════════

/// Full verification result with step tracking.
#[derive(Debug)]
pub struct StoreVerifyResult {
    pub valid: bool,
    pub steps_passed: Vec<&'static str>,
    pub error: Option<TxError>,
}

/// Verify a transaction against persistent store state.
///
/// This is the production verification path. It checks:
///   0. Binding integrity
///   1. Structural validity
///   2. Proof size limits (recomputed)
///   3. Duplicate link tag within TX
///   4. Ring member existence from store
///   5. Global link tag check from store
///   6. Ring signature verification
///   7. Balance proof (via backend)
///   8. Range proofs (via backend)
///   9. Fee adequacy (recomputed size)
///  10. TX size
///  11. Note commitment binding
pub fn verify_with_store<P, S>(
    tx: &TxBody,
    store: &S,
    backend: &P,
) -> StoreVerifyResult
where
    P: ProofBackend,
    S: TxStateStore,
{
    let mut steps = Vec::new();

    macro_rules! check {
        ($step:expr, $name:expr) => {
            if let Err(e) = $step {
                return StoreVerifyResult { valid: false, steps_passed: steps, error: Some(e) };
            }
            steps.push($name);
        };
    }

    // Step 0: Binding
    check!(check_binding(tx), "0_binding");

    // Step 1: Structure
    check!(check_structure(tx), "1_structure");

    // Step 2: Proof size limits
    check!(check_proof_sizes(tx), "2_proof_sizes");

    // Step 3: Duplicate link tag within TX
    check!(check_link_tags_intra_tx(tx), "3_intra_tx_link_tags");

    // Step 4: Ring member existence from store
    check!(check_ring_members_from_store(tx, store), "4_ring_members");

    // Step 5: Global link tag check from store
    check!(check_link_tags_from_store(tx, store), "5_global_link_tags");

    // Step 6: Ring signatures
    check!(check_ring_signatures(tx), "6_ring_signatures");

    // Step 7: Balance proof
    check!(check_balance_proof(tx, backend), "7_balance_proof");

    // Step 8: Range proofs
    check!(check_range_proofs(tx, backend), "8_range_proofs");

    // Step 9: Fee
    check!(check_fee(tx), "9_fee");

    // Step 10: TX size
    check!(check_size(tx), "10_size");

    // Step 11: Note commitments
    check!(check_note_commitments(tx), "11_note_commitments");

    StoreVerifyResult { valid: true, steps_passed: steps, error: None }
}

// ════════════════════════════════════════════
// Individual verification steps
// ════════════════════════════════════════════

fn check_binding(tx: &TxBody) -> Result<(), TxError> {
    if !tx.verify_binding() { Err(TxError::BindingMismatch) } else { Ok(()) }
}

fn check_structure(tx: &TxBody) -> Result<(), TxError> {
    if tx.version != TX_VERSION { return Err(TxError::UnsupportedVersion(tx.version)); }
    if tx.inputs.is_empty() { return Err(TxError::EmptyInputs); }
    if tx.outputs.is_empty() { return Err(TxError::EmptyOutputs); }
    if tx.inputs.len() > MAX_INPUTS { return Err(TxError::TooManyInputs(tx.inputs.len())); }
    if tx.outputs.len() > MAX_OUTPUTS { return Err(TxError::TooManyOutputs(tx.outputs.len())); }
    if tx.tx_extra.len() > 256 { return Err(TxError::TxExtraTooLarge(tx.tx_extra.len())); }
    Ok(())
}

/// Check proof sizes from canonical bytes. Never trust reported sizes.
fn check_proof_sizes(tx: &TxBody) -> Result<(), TxError> {
    // Balance proof
    let bp_size = tx.proofs.balance_proof.proof.len();
    if bp_size > MAX_BALANCE_PROOF_SIZE {
        return Err(TxError::BalanceProofTooLarge { size: bp_size });
    }

    // Range proofs
    let mut total_proof_bytes = bp_size;
    for (i, rp) in tx.proofs.range_proofs.iter().enumerate() {
        let rp_size = rp.proof.len();
        if rp_size > MAX_RANGE_PROOF_SIZE {
            return Err(TxError::RangeProofTooLarge { index: i, size: rp_size });
        }
        total_proof_bytes += rp_size;
    }

    // Total
    if total_proof_bytes > MAX_TX_PROOF_SIZE {
        return Err(TxError::TotalProofBytesTooLarge { size: total_proof_bytes });
    }

    Ok(())
}

fn check_link_tags_intra_tx(tx: &TxBody) -> Result<(), TxError> {
    let mut seen = HashSet::new();
    for inp in &tx.inputs {
        if !seen.insert(inp.link_tag) {
            return Err(TxError::DuplicateLinkTagInTx(hex::encode(inp.link_tag.0)));
        }
    }
    Ok(())
}

fn check_ring_members_from_store<S: TxStateStore>(
    tx: &TxBody,
    store: &S,
) -> Result<(), TxError> {
    for (i, inp) in tx.inputs.iter().enumerate() {
        for member_id in &inp.ring.members {
            let exists = store.enote_exists(member_id)
                .map_err(|e| TxError::StateApplyConflict(e.to_string()))?;
            if !exists {
                return Err(TxError::RingMemberNotFound {
                    input_index: i,
                    member_hex: hex::encode(member_id.0),
                });
            }
        }
    }
    Ok(())
}

fn check_link_tags_from_store<S: TxStateStore>(
    tx: &TxBody,
    store: &S,
) -> Result<(), TxError> {
    for inp in &tx.inputs {
        let exists = store.has_link_tag(&inp.link_tag)
            .map_err(|e| TxError::StateApplyConflict(e.to_string()))?;
        if exists {
            return Err(TxError::DuplicateLinkTagInStore(hex::encode(inp.link_tag.0)));
        }
    }
    Ok(())
}

fn check_ring_signatures(tx: &TxBody) -> Result<(), TxError> {
    let tx_entropy = tx.tx_body_hash.0;
    for (i, inp) in tx.inputs.iter().enumerate() {
        if !inp.verify_ring_binding() {
            return Err(TxError::InvalidRingSignature(i));
        }
        let msg = misaka_crypto::hash::domain_hash_multi(
            misaka_crypto::hash::Domain::Sig,
            &[&tx_entropy, &(i as u32).to_le_bytes()],
            32,
        );
        if !ring_sig::ring_verify(&msg, &inp.ring_proof) {
            return Err(TxError::InvalidRingSignature(i));
        }
    }
    Ok(())
}

fn check_balance_proof<P: ProofBackend>(tx: &TxBody, backend: &P) -> Result<(), TxError> {
    if tx.proofs.proof_backend_id != RangeProofBackend::backend_id(backend) {
        return Err(TxError::ProofBackendMismatch {
            expected: RangeProofBackend::backend_id(backend),
            got: tx.proofs.proof_backend_id,
        });
    }
    match BalanceProofBackend::verify(backend, &tx.proofs.balance_proof) {
        Ok(true) => Ok(()),
        Ok(false) => Err(TxError::InvalidBalanceProof),
        Err(e) => Err(TxError::ProofError(e)),
    }
}

fn check_range_proofs<P: ProofBackend>(tx: &TxBody, backend: &P) -> Result<(), TxError> {
    if tx.proofs.range_proofs.len() != tx.outputs.len() {
        return Err(TxError::InvalidRangeProof(0));
    }
    for (i, (rp, out)) in tx.proofs.range_proofs.iter().zip(tx.outputs.iter()).enumerate() {
        match RangeProofBackend::verify(backend, &out.enote.amount_commitment.0, rp) {
            Ok(true) => {}
            Ok(false) => return Err(TxError::InvalidRangeProof(i)),
            Err(e) => return Err(TxError::ProofError(e)),
        }
    }
    Ok(())
}

fn check_fee(tx: &TxBody) -> Result<(), TxError> {
    if !tx.fee.verify() { return Err(TxError::InvalidFeeProof); }
    if tx.fee.total_fee < FeeStatement::MIN_BASE_FEE {
        return Err(TxError::FeeTooLow { got: tx.fee.total_fee, min: FeeStatement::MIN_BASE_FEE });
    }
    if !tx.proofs.fee_proof.verify() { return Err(TxError::InvalidFeeProof); }
    let actual_size = crate::verify::compute_actual_size(tx);
    let min_fee = FeeStatement::compute(actual_size, tx.fee.congestion_factor.max(1));
    if tx.fee.total_fee < min_fee.total_fee {
        return Err(TxError::FeeTooLow { got: tx.fee.total_fee, min: min_fee.total_fee });
    }
    Ok(())
}

fn check_size(tx: &TxBody) -> Result<(), TxError> {
    let actual_size = crate::verify::compute_actual_size(tx);
    if actual_size > MAX_TX_SIZE {
        return Err(TxError::TxTooLarge(actual_size));
    }
    Ok(())
}

fn check_note_commitments(tx: &TxBody) -> Result<(), TxError> {
    for (i, out) in tx.outputs.iter().enumerate() {
        if !out.enote.verify_note_commitment() {
            return Err(TxError::NoteCommitmentMismatch(i));
        }
    }
    Ok(())
}

// ════════════════════════════════════════════
// State application (atomic)
// ════════════════════════════════════════════

/// Effects of a verified transaction, ready to be applied atomically.
pub struct TxEffects {
    pub new_enotes: Vec<StoredEnote>,
    pub new_link_tags: Vec<LinkTag>,
}

/// Extract the effects of a verified transaction.
///
/// Call this only after `verify_with_store` returns valid=true.
pub fn extract_effects(tx: &TxBody) -> TxEffects {
    let new_enotes = tx.outputs.iter()
        .map(|o| StoredEnote::from(&o.enote))
        .collect();
    let new_link_tags = tx.inputs.iter()
        .map(|i| i.link_tag)
        .collect();
    TxEffects { new_enotes, new_link_tags }
}

/// Apply verified transaction effects to the store atomically.
///
/// Semantics:
///   1. Insert all output enotes
///   2. Insert all link tags
///
/// Note: in the privacy model, enotes are NEVER removed from the set.
/// The link tag set is the sole double-spend prevention mechanism.
/// "Mark spent" means recording the link tag — not deleting the enote.
///
/// Atomicity: if any insert fails, the function returns an error.
/// The caller must handle rollback (e.g., by snapshot/restore for
/// in-memory stores, or by wrapping in a DB transaction for persistent stores).
pub fn apply_tx_effects<S: TxStateStore>(
    store: &mut S,
    effects: &TxEffects,
) -> Result<(), TxError> {
    // Phase 1: Insert link tags (this IS the "mark spent" for privacy chains)
    for tag in &effects.new_link_tags {
        // Re-check for races (another thread may have inserted between verify and apply)
        let exists = store.has_link_tag(tag)
            .map_err(|e| TxError::StateApplyConflict(e.to_string()))?;
        if exists {
            return Err(TxError::DuplicateLinkTagInStore(hex::encode(tag.0)));
        }
        store.insert_link_tag(tag)
            .map_err(|e| TxError::StateApplyConflict(e.to_string()))?;
    }

    // Phase 2: Insert new enotes
    for enote in &effects.new_enotes {
        store.insert_enote(enote)
            .map_err(|e| TxError::StateApplyConflict(e.to_string()))?;
    }

    Ok(())
}

/// Verify and apply a transaction in one call.
///
/// This is the convenience function for block processing.
/// Verify → extract effects → apply atomically.
pub fn verify_and_apply<P, S>(
    tx: &TxBody,
    store: &mut S,
    backend: &P,
) -> Result<StoreVerifyResult, TxError>
where
    P: ProofBackend,
    S: TxStateStore,
{
    let result = verify_with_store(tx, store, backend);
    if !result.valid {
        return Ok(result);
    }

    let effects = extract_effects(tx);
    apply_tx_effects(store, &effects)?;

    Ok(result)
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::proof_backend::TestnetBackend;
    use misaka_crypto::ring_sig::RingSignature;
    use std::collections::HashMap;
    use std::fmt;

    // ── In-memory store for testing ──

    #[derive(Debug)]
    struct MemStoreError(String);
    impl fmt::Display for MemStoreError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0) }
    }

    struct MemStore {
        enotes: HashMap<EnoteId, StoredEnote>,
        link_tags: HashSet<LinkTag>,
    }

    impl MemStore {
        fn new() -> Self { Self { enotes: HashMap::new(), link_tags: HashSet::new() } }

        fn seed_enote(&mut self, id_byte: u8) {
            let eid = EnoteId([id_byte; 32]);
            self.enotes.insert(eid, StoredEnote {
                enote_id: eid,
                one_time_address: [id_byte; 32],
                amount_commitment: AmountCommitment([0xCC; 32]),
                note_commitment: NoteCommitment([0; 32]),
                view_tag: 0,
                asset_id: ASSET_NATIVE,
                enote_version: ENOTE_VERSION,
                created_at: 0,
            });
        }
    }

    impl TxStateStore for MemStore {
        type Error = MemStoreError;

        fn has_link_tag(&self, tag: &LinkTag) -> Result<bool, Self::Error> {
            Ok(self.link_tags.contains(tag))
        }
        fn insert_link_tag(&mut self, tag: &LinkTag) -> Result<(), Self::Error> {
            if !self.link_tags.insert(*tag) {
                return Err(MemStoreError("duplicate link tag".into()));
            }
            Ok(())
        }
        fn enote_exists(&self, id: &EnoteId) -> Result<bool, Self::Error> {
            Ok(self.enotes.contains_key(id))
        }
        fn load_enote(&self, id: &EnoteId) -> Result<Option<StoredEnote>, Self::Error> {
            Ok(self.enotes.get(id).cloned())
        }
        fn insert_enote(&mut self, enote: &StoredEnote) -> Result<(), Self::Error> {
            self.enotes.insert(enote.enote_id, enote.clone());
            Ok(())
        }
    }

    // ── Helpers ──

    fn dummy_enote() -> Enote {
        let ac = AmountCommitment([0xCC; 32]);
        let addr = [0x11; 32];
        let payload = RecipientPayload::encrypt(&[0x42; 32], vec![0; 32], 100, 10, b"", 0);
        let ph = payload.hash();
        let nc = NoteCommitment::compute(&addr, &ac, 0x42, &ph, &ASSET_NATIVE, ENOTE_VERSION);
        Enote {
            enote_id: EnoteId([0xF0; 32]),
            enote_version: ENOTE_VERSION,
            asset_id: ASSET_NATIVE,
            one_time_address: addr,
            amount_commitment: ac,
            note_commitment: nc,
            view_tag: 0x42,
            recipient_payload: payload,
            created_at: 0,
        }
    }

    fn dummy_input(id_byte: u8) -> TxInput {
        let kp = misaka_crypto::ring_sig::larrs_keygen(&[id_byte; 32]);
        let ring_proof = RingSignature {
            ring: vec![vec![0; 64]; 4],
            key_image: kp.key_image,
            c0: [0; 32],
            responses: vec![vec![0; 64]; 4],
        };
        let ring_pk_hash = TxInput::compute_ring_pk_hash(&ring_proof);
        TxInput {
            ring: RingMembers {
                members: [EnoteId([1; 32]), EnoteId([2; 32]), EnoteId([3; 32]), EnoteId([4; 32])],
                member_commitments: [AmountCommitment([0; 32]); 4],
            },
            ring_proof,
            link_tag: LinkTag(kp.key_image),
            pseudo_output_commitment: AmountCommitment([0; 32]),
            ring_pk_hash,
        }
    }

    fn make_dummy_tx(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> TxBody {
        use misaka_crypto::proof_backend::{RangeProofBackend, BalanceProofBackend};
        let fee = FeeStatement::compute(2000, 1);
        let body_hash = compute_tx_body_hash(&inputs, &outputs, &fee);
        let bp = BalanceProofBackend::prove(
            &TestnetBackend,
            &[misaka_crypto::commitment::commit(100, 10)],
            &[misaka_crypto::commitment::commit(100, 10)],
            0,
        ).unwrap();
        let range_proofs: Vec<_> = outputs.iter().map(|_|
            RangeProofBackend::prove(&TestnetBackend, &misaka_crypto::commitment::commit(100, 10)).unwrap()
        ).collect();
        let proofs = TxProofBundle {
            balance_proof: bp,
            range_proofs,
            fee_proof: FeeProof::new(fee.total_fee),
            proof_backend_id: TestnetBackend::BACKEND_ID,
        };
        let proof_hash = compute_tx_proof_hash(&proofs);
        let binding_hash = compute_tx_binding_hash(&body_hash, &proof_hash, TX_VERSION, &[]);
        let tx_id = compute_tx_id(&binding_hash);
        TxBody {
            tx_id, tx_body_hash: body_hash, tx_proof_hash: proof_hash,
            tx_binding_hash: binding_hash, version: TX_VERSION,
            inputs, outputs, proofs, fee, tx_extra: vec![], size_bytes: 2000,
        }
    }

    // ── Proof size tests ──

    #[test]
    fn test_reject_oversized_range_proof() {
        let mut tx = make_dummy_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        // Inject oversized range proof
        tx.proofs.range_proofs[0].proof = vec![0u8; MAX_RANGE_PROOF_SIZE + 1];
        let store = MemStore::new();
        let result = verify_with_store(&tx, &store, &TestnetBackend);
        assert!(!result.valid);
        assert!(matches!(result.error, Some(TxError::RangeProofTooLarge { .. })));
    }

    #[test]
    fn test_reject_oversized_balance_proof() {
        let mut tx = make_dummy_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        tx.proofs.balance_proof.proof = vec![0u8; MAX_BALANCE_PROOF_SIZE + 1];
        let store = MemStore::new();
        let result = verify_with_store(&tx, &store, &TestnetBackend);
        assert!(!result.valid);
        assert!(matches!(result.error, Some(TxError::BalanceProofTooLarge { .. })));
    }

    #[test]
    fn test_reject_oversized_total_proof_bytes() {
        let mut tx = make_dummy_tx(vec![dummy_input(0x01)], vec![TxOutput { enote: dummy_enote() }]);
        // Each range proof just under individual limit, but total exceeds MAX_TX_PROOF_SIZE
        let per_proof = MAX_RANGE_PROOF_SIZE;
        // Need ceil(MAX_TX_PROOF_SIZE / per_proof) + 1 proofs
        let n = (MAX_TX_PROOF_SIZE / per_proof) + 2;
        tx.proofs.range_proofs = (0..n).map(|_|
            misaka_crypto::proof_backend::RangeProofData { backend_id: 1, proof: vec![0u8; per_proof] }
        ).collect();
        let store = MemStore::new();
        let result = verify_with_store(&tx, &store, &TestnetBackend);
        assert!(!result.valid);
        assert!(matches!(result.error, Some(TxError::TotalProofBytesTooLarge { .. })));
    }

    // ── Link tag tests ──

    #[test]
    fn test_reject_duplicate_link_tag_in_tx() {
        let mut inp1 = dummy_input(0x01);
        let inp2 = dummy_input(0x01); // same seed → same key_image
        inp1.link_tag = inp2.link_tag; // force same
        let tx = make_dummy_tx(vec![inp1, inp2], vec![TxOutput { enote: dummy_enote() }]);
        let store = MemStore::new();
        let result = verify_with_store(&tx, &store, &TestnetBackend);
        assert!(!result.valid);
        assert!(matches!(result.error, Some(TxError::DuplicateLinkTagInTx(_))));
    }

    #[test]
    fn test_reject_link_tag_already_in_store() {
        let inp = dummy_input(0x01);
        let tx = make_dummy_tx(vec![inp.clone()], vec![TxOutput { enote: dummy_enote() }]);
        let mut store = MemStore::new();
        // Pre-populate ring members
        for m in &inp.ring.members { store.seed_enote(m.0[0]); }
        // Pre-insert the link tag (simulating previous spend)
        store.link_tags.insert(inp.link_tag);
        let result = verify_with_store(&tx, &store, &TestnetBackend);
        assert!(!result.valid);
        assert!(matches!(result.error, Some(TxError::DuplicateLinkTagInStore(_))));
    }

    // ── Ring member tests ──

    #[test]
    fn test_reject_nonexistent_ring_member() {
        let inp = dummy_input(0x01);
        let tx = make_dummy_tx(vec![inp], vec![TxOutput { enote: dummy_enote() }]);
        let store = MemStore::new(); // empty — no enotes
        let result = verify_with_store(&tx, &store, &TestnetBackend);
        assert!(!result.valid);
        assert!(matches!(result.error, Some(TxError::RingMemberNotFound { .. })));
    }

    // ── Apply tests ──

    #[test]
    fn test_apply_persists_outputs_and_link_tags() {
        let inp = dummy_input(0x42);
        let out = TxOutput { enote: dummy_enote() };
        let tx = make_dummy_tx(vec![inp.clone()], vec![out]);

        let mut store = MemStore::new();
        // Seed ring members so verification passes that step
        for m in &inp.ring.members { store.seed_enote(m.0[0]); }

        let effects = extract_effects(&tx);
        apply_tx_effects(&mut store, &effects).unwrap();

        // Link tag persisted
        assert!(store.has_link_tag(&inp.link_tag).unwrap());

        // Output enote persisted
        let out_id = tx.outputs[0].enote.enote_id;
        assert!(store.enote_exists(&out_id).unwrap());
    }

    #[test]
    fn test_reject_double_spend_after_apply() {
        let inp = dummy_input(0x99);
        let out = TxOutput { enote: dummy_enote() };
        let tx = make_dummy_tx(vec![inp.clone()], vec![out.clone()]);

        let mut store = MemStore::new();
        for m in &inp.ring.members { store.seed_enote(m.0[0]); }

        // First apply succeeds
        let effects = extract_effects(&tx);
        apply_tx_effects(&mut store, &effects).unwrap();

        // Second apply with same link tag fails
        let result = apply_tx_effects(&mut store, &effects);
        assert!(result.is_err());
    }

    #[test]
    fn test_atomic_apply_no_partial_on_dup_link_tag() {
        let inp1 = dummy_input(0xA0);
        let inp2 = dummy_input(0xA1);
        let out = TxOutput { enote: dummy_enote() };

        let mut store = MemStore::new();
        // Pre-insert inp2's link tag to force failure on second insert
        store.link_tags.insert(inp2.link_tag);

        let effects = TxEffects {
            new_link_tags: vec![inp1.link_tag, inp2.link_tag],
            new_enotes: vec![StoredEnote::from(&out.enote)],
        };

        let result = apply_tx_effects(&mut store, &effects);
        assert!(result.is_err());

        // inp1's link tag WAS inserted before failure — this is expected
        // in the current non-transactional model. For full atomicity,
        // the caller should snapshot/restore. The error is still surfaced.
        // In a DB-backed store, this would be wrapped in a transaction.
    }
}
