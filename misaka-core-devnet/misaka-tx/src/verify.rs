// ============================================================
// MISAKA — Transaction Verification (v2)
// ============================================================
//
// Validator pipeline (WP §A.6):
//
//   Step 0: Binding integrity (tx_body_hash → tx_proof_hash → tx_binding_hash → tx_id)
//   Step 1: Structural validity
//   Step 2: Link tag uniqueness (global + intra-TX)
//   Step 3: Ring member existence in enote set
//   Step 4: Ring signatures (LaRRS verify per input)
//   Step 5: Balance proof (via backend)
//   Step 6: Range proofs (via backend)
//   Step 7: Fee adequacy
//   Step 8: TX size
//   Step 9: Note commitment binding (all enote fields)
//
// ============================================================

use crate::types::*;
use misaka_crypto::ring_sig;
use misaka_crypto::proof_backend::{ProofBackend, RangeProofBackend, BalanceProofBackend};
use std::collections::HashSet;

#[derive(Debug)]
pub struct VerifyResult {
    pub valid: bool,
    pub steps_passed: Vec<&'static str>,
    pub error: Option<TxError>,
}

/// Verify a transaction using the given proof backend.
///
/// Takes a single `ProofBackend` (same type for range + balance).
pub fn verify_transaction<P, F>(
    tx: &TxBody,
    known_link_tags: &HashSet<LinkTag>,
    enote_exists: F,
    backend: &P,
) -> VerifyResult
where
    P: ProofBackend,
    F: Fn(&EnoteId) -> bool,
{
    let mut steps = Vec::new();

    macro_rules! check {
        ($step:expr, $name:expr) => {
            if let Err(e) = $step {
                return VerifyResult { valid: false, steps_passed: steps, error: Some(e) };
            }
            steps.push($name);
        };
    }

    check!(check_binding(tx), "0_binding");
    check!(check_structure(tx), "1_structure");
    check!(check_proof_sizes(tx), "2_proof_sizes");
    check!(check_link_tags(tx, known_link_tags), "3_link_tags");
    check!(check_ring_membership(tx, &enote_exists), "4_ring_membership");
    check!(check_ring_signatures(tx), "5_ring_signatures");
    check!(check_balance_proof(tx, backend), "6_balance");
    check!(check_range_proofs(tx, backend), "7_range");
    check!(check_fee(tx), "8_fee");
    check!(check_size(tx), "9_size");
    check!(check_note_commitments(tx), "10_note_commitments");

    VerifyResult { valid: true, steps_passed: steps, error: None }
}

// ── Step 0: Binding integrity (anti-malleability) ──

fn check_binding(tx: &TxBody) -> Result<(), TxError> {
    if !tx.verify_binding() {
        return Err(TxError::BindingMismatch);
    }
    Ok(())
}

// ── Step 1: Structure ──

fn check_structure(tx: &TxBody) -> Result<(), TxError> {
    if tx.version != TX_VERSION { return Err(TxError::UnsupportedVersion(tx.version)); }
    if tx.inputs.is_empty() { return Err(TxError::EmptyInputs); }
    if tx.outputs.is_empty() { return Err(TxError::EmptyOutputs); }
    if tx.inputs.len() > MAX_INPUTS { return Err(TxError::TooManyInputs(tx.inputs.len())); }
    if tx.outputs.len() > MAX_OUTPUTS { return Err(TxError::TooManyOutputs(tx.outputs.len())); }
    if tx.tx_extra.len() > 256 { return Err(TxError::TxExtraTooLarge(tx.tx_extra.len())); }
    Ok(())
}

// ── Step 2: Proof sizes ──

fn check_proof_sizes(tx: &TxBody) -> Result<(), TxError> {
    let bp_size = tx.proofs.balance_proof.proof.len();
    if bp_size > MAX_BALANCE_PROOF_SIZE {
        return Err(TxError::BalanceProofTooLarge { size: bp_size });
    }
    let mut total = bp_size;
    for (i, rp) in tx.proofs.range_proofs.iter().enumerate() {
        let s = rp.proof.len();
        if s > MAX_RANGE_PROOF_SIZE {
            return Err(TxError::RangeProofTooLarge { index: i, size: s });
        }
        total += s;
    }
    if total > MAX_TX_PROOF_SIZE {
        return Err(TxError::TotalProofBytesTooLarge { size: total });
    }
    Ok(())
}

// ── Step 3: Link tags ──

fn check_link_tags(tx: &TxBody, known: &HashSet<LinkTag>) -> Result<(), TxError> {
    let mut seen = HashSet::new();
    for inp in &tx.inputs {
        if known.contains(&inp.link_tag) {
            return Err(TxError::DuplicateLinkTag(hex::encode(inp.link_tag.0)));
        }
        if !seen.insert(inp.link_tag) {
            return Err(TxError::DuplicateLinkTag(hex::encode(inp.link_tag.0)));
        }
    }
    Ok(())
}

// ── Step 3: Ring membership ──

fn check_ring_membership<F: Fn(&EnoteId) -> bool>(tx: &TxBody, exists: &F) -> Result<(), TxError> {
    for (i, inp) in tx.inputs.iter().enumerate() {
        for m in &inp.ring.members {
            if !exists(m) { return Err(TxError::InvalidRingSignature(i)); }
        }
    }
    Ok(())
}

// ── Step 4: Ring signatures ──

fn check_ring_signatures(tx: &TxBody) -> Result<(), TxError> {
    let tx_entropy = tx.tx_body_hash.0;
    for (i, inp) in tx.inputs.iter().enumerate() {
        // Step 4a: Verify ring_pk_hash matches the PKs in ring_proof.
        // Without this, an attacker could sign with different PKs than declared.
        if !inp.verify_ring_binding() {
            return Err(TxError::InvalidRingSignature(i));
        }

        // Step 4b: Verify the ring signature itself.
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

// ── Step 5: Balance proof (via backend) ──

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

// ── Step 6: Range proofs (via backend) ──

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

// ── Step 7: Fee ──

fn check_fee(tx: &TxBody) -> Result<(), TxError> {
    if !tx.fee.verify() { return Err(TxError::InvalidFeeProof); }
    if tx.fee.total_fee < FeeStatement::MIN_BASE_FEE {
        return Err(TxError::FeeTooLow { got: tx.fee.total_fee, min: FeeStatement::MIN_BASE_FEE });
    }
    if !tx.proofs.fee_proof.verify() { return Err(TxError::InvalidFeeProof); }

    // Verify fee covers the actual TX size (not the declared size).
    // This prevents fee underpayment via spoofed size_bytes.
    let actual_size = compute_actual_size(tx);
    let min_fee = FeeStatement::compute(actual_size, tx.fee.congestion_factor.max(1));
    if tx.fee.total_fee < min_fee.total_fee {
        return Err(TxError::FeeTooLow { got: tx.fee.total_fee, min: min_fee.total_fee });
    }

    Ok(())
}

// ── Step 8: Size (recomputed, NOT trusting tx.size_bytes) ──

fn check_size(tx: &TxBody) -> Result<(), TxError> {
    // Recompute actual size from TX structure.
    // Never trust the self-reported size_bytes — it could be spoofed
    // to avoid higher fees.
    let actual_size = compute_actual_size(tx);
    if actual_size > MAX_TX_SIZE {
        return Err(TxError::TxTooLarge(actual_size));
    }
    Ok(())
}

/// Compute the actual serialized size of a transaction from its fields.
///
/// This is what validators use instead of trusting tx.size_bytes.
/// The fee is validated against THIS size, not the declared one.
pub fn compute_actual_size(tx: &TxBody) -> u32 {
    let mut size: u32 = 0;

    // Fixed fields: tx_id(32) + hashes(3×32) + version(1) + size_bytes(4)
    size += 32 + 32 + 32 + 32 + 1 + 4;

    // Inputs
    for inp in &tx.inputs {
        // ring members: 4 × 32 (IDs) + 4 × 32 (commitments) = 256
        size += 256;
        // ring_proof: ring(4 × ~64) + key_image(32) + c0(32) + responses(4 × ~64)
        size += 32 + 32; // key_image + c0
        for pk in &inp.ring_proof.ring { size += pk.len() as u32; }
        for z in &inp.ring_proof.responses { size += z.len() as u32; }
        // link_tag(32) + pseudo_commit(32) + ring_pk_hash(32)
        size += 32 + 32 + 32;
    }

    // Outputs
    for out in &tx.outputs {
        let e = &out.enote;
        // enote_id(32) + version(1) + asset_id(32) + one_time_address(32)
        // + amount_commitment(32) + note_commitment(32) + view_tag(1)
        // + created_at(8)
        size += 32 + 1 + 32 + 32 + 32 + 32 + 1 + 8;
        // recipient_payload
        size += e.recipient_payload.ephemeral_ct.len() as u32; // ~1088
        size += 8 + 8 + 4; // encrypted_amount + encrypted_blinding + output_index
        size += e.recipient_payload.encrypted_memo.len() as u32;
    }

    // Proofs
    size += 1; // proof_backend_id
    size += 4 + tx.proofs.balance_proof.proof.len() as u32; // balance
    for rp in &tx.proofs.range_proofs {
        size += 1 + 4 + rp.proof.len() as u32; // backend_id + len + data
    }
    size += 8 + 32; // fee_proof: amount + commitment

    // Fee statement
    size += 8 + 8 + 8 + 1 + 32; // base + size + total + congestion + commitment

    // tx_extra
    size += tx.tx_extra.len() as u32;

    size
}

// ── Step 9: Note commitment binding (Task 2 verification) ──

fn check_note_commitments(tx: &TxBody) -> Result<(), TxError> {
    for (i, out) in tx.outputs.iter().enumerate() {
        if !out.enote.verify_note_commitment() {
            return Err(TxError::NoteCommitmentMismatch(i));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::proof_backend::TestnetBackend;

    fn dummy_enote() -> Enote {
        let ac = AmountCommitment([0xCC; 32]);
        let addr = [0x11; 32];
        let payload = RecipientPayload::encrypt(&[0x42; 32], vec![0; 32], 100, 10, b"", 0);
        let ph = payload.hash();
        let nc = NoteCommitment::compute(&addr, &ac, 0x42, &ph, &ASSET_NATIVE, ENOTE_VERSION);
        Enote {
            enote_id: EnoteId([0; 32]),
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

    fn dummy_input() -> TxInput {
        let kp = misaka_crypto::ring_sig::larrs_keygen(b"dummy-signer-key-32-bytes-long!!");
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

    #[test]
    fn test_verify_binding_mismatch() {
        let fee = FeeStatement::compute(1000, 1);
        let body_hash = compute_tx_body_hash(&[dummy_input()], &[TxOutput { enote: dummy_enote() }], &fee);
        let bp = TestnetBackend.prove(
            &[misaka_crypto::commitment::commit(100, 10)],
            &[misaka_crypto::commitment::commit(100, 10)],
            0,
        ).unwrap();
        let proofs = TxProofBundle {
            balance_proof: bp,
            range_proofs: vec![TestnetBackend.prove(&misaka_crypto::commitment::commit(100, 10)).unwrap()],
            fee_proof: FeeProof::new(fee.total_fee),
            proof_backend_id: TestnetBackend::BACKEND_ID,
        };
        let proof_hash = compute_tx_proof_hash(&proofs);
        let binding_hash = compute_tx_binding_hash(&body_hash, &proof_hash, TX_VERSION, &[]);
        let tx_id = compute_tx_id(&binding_hash);

        let mut tx = TxBody {
            tx_id,
            tx_body_hash: body_hash,
            tx_proof_hash: proof_hash,
            tx_binding_hash: binding_hash,
            version: TX_VERSION,
            inputs: vec![dummy_input()],
            outputs: vec![TxOutput { enote: dummy_enote() }],
            proofs,
            fee,
            tx_extra: vec![],
            size_bytes: 1000,
        };

        // Tamper with tx_id
        tx.tx_id.0[0] ^= 0xFF;

        let result = verify_transaction(
            &tx, &HashSet::new(), |_| true,
            &TestnetBackend,
        );
        assert!(!result.valid);
        assert!(matches!(result.error, Some(TxError::BindingMismatch)));
    }

    #[test]
    fn test_verify_duplicate_link_tag() {
        let fee = FeeStatement::compute(1000, 1);
        let mut inp1 = dummy_input();
        let mut inp2 = dummy_input();
        inp1.link_tag = LinkTag([0xAA; 32]);
        inp2.link_tag = LinkTag([0xAA; 32]);

        let body_hash = compute_tx_body_hash(&[inp1.clone(), inp2.clone()], &[TxOutput { enote: dummy_enote() }], &fee);
        let bp = TestnetBackend.prove(
            &[misaka_crypto::commitment::commit(100, 10)],
            &[misaka_crypto::commitment::commit(100, 10)],
            0,
        ).unwrap();
        let proofs = TxProofBundle {
            balance_proof: bp,
            range_proofs: vec![TestnetBackend.prove(&misaka_crypto::commitment::commit(100, 10)).unwrap()],
            fee_proof: FeeProof::new(fee.total_fee),
            proof_backend_id: TestnetBackend::BACKEND_ID,
        };
        let proof_hash = compute_tx_proof_hash(&proofs);
        let binding_hash = compute_tx_binding_hash(&body_hash, &proof_hash, TX_VERSION, &[]);
        let tx_id = compute_tx_id(&binding_hash);

        let tx = TxBody {
            tx_id, tx_body_hash: body_hash, tx_proof_hash: proof_hash,
            tx_binding_hash: binding_hash, version: TX_VERSION,
            inputs: vec![inp1, inp2],
            outputs: vec![TxOutput { enote: dummy_enote() }],
            proofs, fee, tx_extra: vec![], size_bytes: 1000,
        };

        let result = verify_transaction(
            &tx, &HashSet::new(), |_| true,
            &TestnetBackend,
        );
        assert!(!result.valid);
        assert!(matches!(result.error, Some(TxError::DuplicateLinkTag(_))));
    }

    #[test]
    fn test_note_commitment_mismatch_detected() {
        let mut enote = dummy_enote();
        // Tamper with view_tag after NoteCommitment was computed
        enote.view_tag = 0xFF;
        assert!(!enote.verify_note_commitment(), "Tampered enote must fail NoteCommitment check");
    }

    use misaka_crypto::proof_backend::{RangeProofBackend, BalanceProofBackend};
}
