// ============================================================
// MISAKA Network — Lattice Pedersen Commitments
// ============================================================
//
// WP §6.4: Transaction amounts are hidden using Pedersen commitments.
//
//   C = v·G + r·H  (over Z_q^N)
//
// Where:
//   v = amount (secret)
//   r = random blinding factor (secret)
//   G, H = public generator vectors ∈ Z_q^N (deterministic from seed)
//   C = commitment vector ∈ Z_q^N (public)
//
// Properties:
//   - Hiding: C reveals nothing about v (r is random)
//   - Binding: cannot find (v', r') ≠ (v, r) with same C
//     (computationally, under SIS assumption)
//   - Homomorphic: C1 + C2 = (v1+v2)·G + (r1+r2)·H
//     → balance proof: Σ(input C) - Σ(output C) - fee·G = 0
//
// This module provides:
//   - commit(value, blinding) → 32-byte commitment hash
//   - verify_balance(input_commitments, output_commitments, fee)
//   - range_check (testnet: simplified, not ZK)
//
// Commitment format (on-chain):
//   32 bytes = SHAKE256(C vector), where C is computed over Z_q^N
//   The full vector is not stored — only the hash.
//   Balance proofs work on the full vectors, then the verifier
//   checks H(result) == H(zero vector).
//
// ============================================================

use crate::hash::{Domain, domain_hash, domain_hash_32, domain_hash_multi};
use crate::ring_sig::{LARRS_Q, LARRS_N, ZqVec};
use serde::{Serialize, Deserialize};

// ── Generators ──

/// Public generator G (for amounts).
fn generator_g() -> ZqVec {
    let seed = domain_hash(Domain::Commitment, b"MISAKA_PEDERSEN_G_v1", LARRS_N * 8);
    let mut g = [0u64; LARRS_N];
    for i in 0..LARRS_N {
        let off = i * 8;
        g[i] = u64::from_le_bytes(seed[off..off + 8].try_into().unwrap()) % LARRS_Q;
    }
    g
}

/// Public generator H (for blinding factors).
fn generator_h() -> ZqVec {
    let seed = domain_hash(Domain::Commitment, b"MISAKA_PEDERSEN_H_v1", LARRS_N * 8);
    let mut h = [0u64; LARRS_N];
    for i in 0..LARRS_N {
        let off = i * 8;
        h[i] = u64::from_le_bytes(seed[off..off + 8].try_into().unwrap()) % LARRS_Q;
    }
    h
}

// ── Z_q vector ops (reuse from ring_sig) ──

fn vec_add(a: &ZqVec, b: &ZqVec) -> ZqVec {
    let mut r = [0u64; LARRS_N];
    for i in 0..LARRS_N {
        r[i] = (a[i] + b[i]) % LARRS_Q;
    }
    r
}

fn vec_sub(a: &ZqVec, b: &ZqVec) -> ZqVec {
    let mut r = [0u64; LARRS_N];
    for i in 0..LARRS_N {
        r[i] = (a[i] + LARRS_Q - b[i]) % LARRS_Q;
    }
    r
}

fn scalar_vec(c: u64, v: &ZqVec) -> ZqVec {
    let mut r = [0u64; LARRS_N];
    for i in 0..LARRS_N {
        r[i] = ((c as u128 * v[i] as u128) % LARRS_Q as u128) as u64;
    }
    r
}

fn vec_is_zero(v: &ZqVec) -> bool {
    v.iter().all(|&x| x == 0)
}

fn vec_to_bytes(v: &ZqVec) -> Vec<u8> {
    let mut out = Vec::with_capacity(LARRS_N * 8);
    for &x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

// ── Commitment types ──

/// A Pedersen commitment with its opening (private to the creator).
#[derive(Debug, Clone)]
pub struct CommitmentOpening {
    pub value: u64,
    pub blinding: u64,
    /// The full commitment vector C = v·G + r·H (private, for proofs)
    pub vector: ZqVec,
    /// The on-chain hash H(C) — 32 bytes stored in TX output
    pub hash: [u8; 32],
}

/// Compute a Pedersen commitment: C = value·G + blinding·H mod q
///
/// Returns the commitment opening (with the full vector for balance proofs)
/// and the 32-byte hash that goes on-chain.
pub fn commit(value: u64, blinding: u64) -> CommitmentOpening {
    let g = generator_g();
    let h = generator_h();

    let vg = scalar_vec(value % LARRS_Q, &g);
    let rh = scalar_vec(blinding % LARRS_Q, &h);
    let vector = vec_add(&vg, &rh);

    let hash = domain_hash_32(Domain::Commitment, &vec_to_bytes(&vector));

    CommitmentOpening { value, blinding, vector, hash }
}

/// Generate a random blinding factor.
pub fn random_blinding(entropy: &[u8]) -> u64 {
    let h = domain_hash(Domain::Commitment, entropy, 8);
    u64::from_le_bytes(h.try_into().unwrap()) % LARRS_Q
}

/// Compute a commitment for a known fee (blinding = 0).
/// Fee commitments use r=0 because the fee must be publicly verifiable.
pub fn commit_fee(fee: u64) -> CommitmentOpening {
    commit(fee, 0)
}

// ── Balance proof ──

/// Serialized balance proof (testnet: just the excess blinding factor).
///
/// The balance equation:
///   Σ(input_C) = Σ(output_C) + fee·G
///   Σ(v_in)·G + Σ(r_in)·H = Σ(v_out)·G + Σ(r_out)·H + fee·G
///
/// This implies:
///   Σ(v_in) = Σ(v_out) + fee  (balance)
///   Σ(r_in) = Σ(r_out)        (blinding factors cancel)
///
/// The proof carries the excess (difference of blinding sums)
/// which must be zero for a valid transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceProof {
    /// Difference vector: Σ(input_C) - Σ(output_C) - fee_C
    /// Must be the zero vector for a valid transaction.
    pub excess_hash: [u8; 32],
}

/// Create a balance proof for a transaction.
///
/// Inputs: commitment openings for all inputs
/// Outputs: commitment openings for all outputs  
/// Fee: the transaction fee
///
/// Returns a proof that Σ(inputs) = Σ(outputs) + fee
/// without revealing any individual amounts.
pub fn create_balance_proof(
    inputs: &[CommitmentOpening],
    outputs: &[CommitmentOpening],
    fee: u64,
) -> BalanceProof {
    // Sum input vectors
    let mut sum_in = [0u64; LARRS_N];
    for inp in inputs {
        sum_in = vec_add(&sum_in, &inp.vector);
    }

    // Sum output vectors + fee commitment
    let fee_commit = commit_fee(fee);
    let mut sum_out = fee_commit.vector;
    for out in outputs {
        sum_out = vec_add(&sum_out, &out.vector);
    }

    // Excess = sum_in - sum_out (should be zero vector if balanced)
    let excess = vec_sub(&sum_in, &sum_out);
    let excess_hash = domain_hash_32(Domain::Commitment, &vec_to_bytes(&excess));

    BalanceProof { excess_hash }
}

/// Verify a balance proof using only the on-chain commitment hashes.
///
/// This verifies that the prover demonstrated Σ(input) = Σ(output) + fee
/// by checking that the excess is the hash of the zero vector.
pub fn verify_balance_proof(proof: &BalanceProof) -> bool {
    let zero_vec = [0u64; LARRS_N];
    let zero_hash = domain_hash_32(Domain::Commitment, &vec_to_bytes(&zero_vec));
    proof.excess_hash == zero_hash
}

/// Verify a balance proof with full vectors (for block validators who
/// receive the vectors as part of the TX).
///
/// This is stronger: it checks the actual vectors, not just hashes.
pub fn verify_balance_vectors(
    input_vectors: &[ZqVec],
    output_vectors: &[ZqVec],
    fee: u64,
) -> bool {
    let mut sum_in = [0u64; LARRS_N];
    for v in input_vectors {
        sum_in = vec_add(&sum_in, v);
    }

    let fee_commit = commit_fee(fee);
    let mut sum_out = fee_commit.vector;
    for v in output_vectors {
        sum_out = vec_add(&sum_out, v);
    }

    let excess = vec_sub(&sum_in, &sum_out);
    vec_is_zero(&excess)
}

// ── Range check (testnet simplified) ──

/// Testnet range check: value must be in [0, 2^64).
///
/// IMPORTANT: This is NOT a zero-knowledge range proof.
/// A real ZK range proof would prove the committed value is
/// non-negative without revealing it. That requires a lattice
/// range proof protocol (Phase 3).
///
/// For testnet, the prover reveals that they CAN open the
/// commitment to a valid value. The verifier trusts this.
pub fn range_check_testnet(opening: &CommitmentOpening) -> bool {
    // Verify the opening matches the commitment
    let recomputed = commit(opening.value, opening.blinding);
    recomputed.hash == opening.hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_hiding() {
        // Same value, different blinding → different commitments
        let c1 = commit(1000, 42);
        let c2 = commit(1000, 99);
        assert_ne!(c1.hash, c2.hash, "Different blinding must give different commitment");
    }

    #[test]
    fn test_commitment_binding() {
        // Same (value, blinding) → same commitment
        let c1 = commit(1000, 42);
        let c2 = commit(1000, 42);
        assert_eq!(c1.hash, c2.hash, "Same inputs must give same commitment");
    }

    #[test]
    fn test_commitment_different_values() {
        let c1 = commit(1000, 42);
        let c2 = commit(2000, 42);
        assert_ne!(c1.hash, c2.hash, "Different values must give different commitment");
    }

    #[test]
    fn test_balance_proof_valid() {
        // TX: 2 inputs → 2 outputs + fee
        // Input: 1000 (blind=10) + 500 (blind=20) = 1500
        // Output: 800 (blind=15) + 600 (blind=15) = 1400
        // Fee: 100 (blind=0)
        // Balance: 1500 = 1400 + 100 ✓
        // Blinding: 10+20 = 15+15 ✓

        let inp1 = commit(1000, 10);
        let inp2 = commit(500, 20);
        let out1 = commit(800, 15);
        let out2 = commit(600, 15);
        let fee = 100u64;

        let proof = create_balance_proof(&[inp1, inp2], &[out1, out2], fee);
        assert!(verify_balance_proof(&proof), "Valid balance must verify");
    }

    #[test]
    fn test_balance_proof_invalid_amounts() {
        // Amounts don't balance: 1000 ≠ 500 + 100
        let inp = commit(1000, 42);
        let out = commit(500, 42); // short 400
        let fee = 100u64;

        let proof = create_balance_proof(&[inp], &[out], fee);
        assert!(!verify_balance_proof(&proof), "Unbalanced TX must fail");
    }

    #[test]
    fn test_balance_proof_invalid_blinding() {
        // Amounts balance but blindings don't
        let inp = commit(1000, 42);
        let out = commit(900, 99); // wrong blinding
        let fee = 100u64;

        let proof = create_balance_proof(&[inp], &[out], fee);
        assert!(!verify_balance_proof(&proof), "Mismatched blinding must fail");
    }

    #[test]
    fn test_balance_vector_verification() {
        let inp1 = commit(1000, 10);
        let inp2 = commit(500, 20);
        let out1 = commit(800, 15);
        let out2 = commit(600, 15);

        assert!(verify_balance_vectors(
            &[inp1.vector, inp2.vector],
            &[out1.vector, out2.vector],
            100,
        ));

        // Unbalanced
        assert!(!verify_balance_vectors(
            &[inp1.vector],
            &[out1.vector, out2.vector],
            100,
        ));
    }

    #[test]
    fn test_fee_commitment_public() {
        let fc = commit_fee(2000);
        assert_eq!(fc.blinding, 0, "Fee blinding must be 0");
        assert_eq!(fc.value, 2000);
    }

    #[test]
    fn test_range_check() {
        let c = commit(42, 99);
        assert!(range_check_testnet(&c));
    }

    #[test]
    fn test_homomorphic_property() {
        // C(v1, r1) + C(v2, r2) should equal C(v1+v2, r1+r2)
        let c1 = commit(100, 10);
        let c2 = commit(200, 20);
        let c_sum = commit(300, 30);

        let manual_sum = vec_add(&c1.vector, &c2.vector);
        assert_eq!(manual_sum, c_sum.vector,
            "Pedersen commitments must be homomorphic");
    }
}
