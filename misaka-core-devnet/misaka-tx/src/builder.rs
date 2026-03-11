// ============================================================
// MISAKA — Transaction Builder (v2)
// ============================================================
//
// Uses proof backend traits for swappable proof generation.
// Computes the full binding hash chain:
//   tx_body_hash → tx_proof_hash → tx_binding_hash → tx_id
//
// End-to-end stealth flow:
//   1. Kyber.Encaps → shared_secret
//   2. RecipientPayload::encrypt(ss, amount, blinding, memo)
//   3. payload.hash() → included in NoteCommitment
//   4. NoteCommitment → included in tx_body_hash
//
// ============================================================

use crate::types::*;
use misaka_crypto::commitment::{self, CommitmentOpening};
use misaka_crypto::ring_sig;
use misaka_crypto::stealth;
use misaka_crypto::hash::{Domain, domain_hash_32, domain_hash_multi};
use misaka_crypto::proof_backend::{ProofBackend, RangeProofBackend, BalanceProofBackend};

/// A planned spend.
pub struct PlannedInput {
    pub real_enote_id: EnoteId,
    pub real_index: usize,
    pub ring_member_ids: [EnoteId; 4],
    pub ring_member_commitments: [AmountCommitment; 4],
    pub amount: u64,
    pub blinding: u64,
    pub ring_keys: ring_sig::LarrsKeyPair,
    pub ring_pks: [ring_sig::ZqVec; 4],
}

/// A planned output.
pub struct PlannedOutput {
    pub recipient: stealth::JamtisAddress,
    pub amount: u64,
    pub memo: Vec<u8>,
    pub asset_id: [u8; 32],
}

/// Build a complete TxBody.
///
/// Takes a single `ProofBackend` — the same backend generates
/// both range and balance proofs. This prevents mismatched
/// backend_ids between proof types.
pub fn build_transaction<P: ProofBackend>(
    inputs: &[PlannedInput],
    outputs: &[PlannedOutput],
    congestion_factor: u8,
    backend: &P,
) -> Result<TxBody, TxError>
{
    // ── Validation ──
    if inputs.is_empty() { return Err(TxError::EmptyInputs); }
    if outputs.is_empty() { return Err(TxError::EmptyOutputs); }
    if inputs.len() > MAX_INPUTS { return Err(TxError::TooManyInputs(inputs.len())); }
    if outputs.len() > MAX_OUTPUTS { return Err(TxError::TooManyOutputs(outputs.len())); }

    let estimated_size = estimate_tx_size(inputs.len(), outputs.len());
    if estimated_size > MAX_TX_SIZE { return Err(TxError::TxTooLarge(estimated_size)); }

    // ── Fee ──
    let fee = FeeStatement::compute(estimated_size, congestion_factor);

    // ── TX entropy (for deterministic derivation within this TX) ──
    let tx_entropy = build_tx_entropy(inputs, outputs);

    // ── Build outputs with stealth + commitments ──
    let mut tx_outputs = Vec::with_capacity(outputs.len());
    let mut output_openings = Vec::with_capacity(outputs.len());
    let mut range_proofs = Vec::new();

    for (idx, planned) in outputs.iter().enumerate() {
        // Random blinding
        let blinding = commitment::random_blinding(
            &domain_hash_multi(Domain::Commitment, &[&tx_entropy, &(idx as u32).to_le_bytes()], 32),
        );
        let opening = commitment::commit(planned.amount, blinding);

        // Kyber encaps → stealth output + shared secret
        let stealth_result = stealth::create_stealth_output(
            &planned.recipient, planned.amount, opening.hash, idx as u32,
        ).map_err(|_| TxError::InvalidRangeProof(idx))?;
        let stealth_out = &stealth_result.output;

        // Encrypt payload using the KEM shared secret (Task 3: unified encryption)
        let recipient_payload = RecipientPayload::encrypt(
            &stealth_result.shared_secret,
            stealth_out.ephemeral_ct.clone(),
            planned.amount,
            blinding,
            &planned.memo,
            idx as u32,
        );

        // Payload hash → included in NoteCommitment
        let payload_hash = recipient_payload.hash();

        // NoteCommitment (Task 2: strengthened)
        let note_commitment = NoteCommitment::compute(
            &stealth_out.stealth_address,
            &AmountCommitment(opening.hash),
            stealth_out.view_tag,
            &payload_hash,
            &planned.asset_id,
            ENOTE_VERSION,
        );

        // Range proof via backend (Task 4)
        // Range proof via backend
        let rp = RangeProofBackend::prove(backend, &opening)?;
        range_proofs.push(rp);

        tx_outputs.push(TxOutput {
            enote: Enote {
                enote_id: EnoteId([0; 32]), // placeholder, set after binding hash
                enote_version: ENOTE_VERSION,
                asset_id: planned.asset_id,
                one_time_address: stealth_out.stealth_address,
                amount_commitment: AmountCommitment(opening.hash),
                note_commitment,
                view_tag: stealth_out.view_tag,
                recipient_payload,
                created_at: 0,
            },
        });

        output_openings.push(opening);
    }

    // ── Build inputs with ring signatures ──
    let mut tx_inputs = Vec::with_capacity(inputs.len());
    let mut input_openings: Vec<CommitmentOpening> = Vec::with_capacity(inputs.len());

    for (idx, planned) in inputs.iter().enumerate() {
        // Pseudo-output commitment
        let pseudo_blinding = if idx == inputs.len() - 1 {
            // Last input: adjust blinding for balance
            let out_sum: u64 = output_openings.iter().map(|o| o.blinding).sum::<u64>() % ring_sig::LARRS_Q;
            let prev_sum: u64 = input_openings.iter().map(|o| o.blinding).sum::<u64>() % ring_sig::LARRS_Q;
            (out_sum + ring_sig::LARRS_Q - prev_sum) % ring_sig::LARRS_Q
        } else {
            commitment::random_blinding(
                &domain_hash_multi(Domain::Commitment, &[&tx_entropy, b"pseudo", &(idx as u32).to_le_bytes()], 32),
            )
        };
        let pseudo_opening = commitment::commit(planned.amount, pseudo_blinding);

        // Ring signature (signs tx_entropy, not tx_id — tx_id doesn't exist yet)
        let msg = domain_hash_multi(
            Domain::Sig,
            &[&tx_entropy, &(idx as u32).to_le_bytes()],
            32,
        );
        let ring_sig_result = ring_sig::ring_sign(&planned.ring_keys, &msg, &planned.ring_pks, planned.real_index);
        let ring_pk_hash = TxInput::compute_ring_pk_hash(&ring_sig_result);

        tx_inputs.push(TxInput {
            ring: RingMembers {
                members: planned.ring_member_ids,
                member_commitments: planned.ring_member_commitments,
            },
            ring_proof: ring_sig_result,
            link_tag: LinkTag(planned.ring_keys.key_image),
            pseudo_output_commitment: AmountCommitment(pseudo_opening.hash),
            ring_pk_hash,
        });

        input_openings.push(pseudo_opening);
    }

    // ── Balance proof via backend ──
    let balance_proof = BalanceProofBackend::prove(backend, &input_openings, &output_openings, fee.total_fee)?;

    let proofs = TxProofBundle {
        balance_proof,
        range_proofs,
        fee_proof: FeeProof::new(fee.total_fee),
        proof_backend_id: RangeProofBackend::backend_id(backend),
    };

    // ── Compute binding hash chain (Task 1) ──
    let tx_body_hash = compute_tx_body_hash(&tx_inputs, &tx_outputs, &fee);
    let tx_proof_hash = compute_tx_proof_hash(&proofs);
    let tx_binding_hash = compute_tx_binding_hash(&tx_body_hash, &tx_proof_hash, TX_VERSION, &[]);
    let tx_id = compute_tx_id(&tx_binding_hash);

    // ── Fix enote IDs (derived from binding hash, not tx_id) ──
    for (idx, out) in tx_outputs.iter_mut().enumerate() {
        out.enote.enote_id = EnoteId::compute(&tx_binding_hash, idx as u32);
    }

    Ok(TxBody {
        tx_id,
        tx_body_hash,
        tx_proof_hash,
        tx_binding_hash,
        version: TX_VERSION,
        inputs: tx_inputs,
        outputs: tx_outputs,
        proofs,
        fee,
        tx_extra: Vec::new(),
        size_bytes: estimated_size,
    })
}

// ── Helpers ──

fn build_tx_entropy(inputs: &[PlannedInput], outputs: &[PlannedOutput]) -> [u8; 32] {
    let mut data = Vec::new();
    for inp in inputs { data.extend_from_slice(&inp.real_enote_id.0); }
    for out in outputs { data.extend_from_slice(&out.amount.to_le_bytes()); }
    domain_hash_32(Domain::Tx, &data)
}

pub fn estimate_tx_size(num_inputs: usize, num_outputs: usize) -> u32 {
    let base = 320u32; // hashes + version + fee
    let per_input = 800u32; // ring + proof + link_tag + pseudo_commit
    let per_output = 1250u32; // enote + payload + commitment
    base + (num_inputs as u32) * per_input + (num_outputs as u32) * per_output
}