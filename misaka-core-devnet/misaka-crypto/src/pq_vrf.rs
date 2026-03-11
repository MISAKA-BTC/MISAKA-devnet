// ============================================================
// MISAKA Network — Post-Quantum VRF (Stub / Future)
// ============================================================
//
// STATUS: NOT USED IN CONSENSUS.
//
// Proposer selection uses deterministic round-robin based on
// fingerprint-sorted validator index:
//   proposer = validators[(height + round) % N]
// See misaka-consensus ValidatorSet::get_proposer().
//
// This module defines the VRF interface for FUTURE use only
// (e.g., randomness beacons, random committee selection).
// TestnetPseudoVrf is provided for experimentation but MUST NOT
// be used for any security-critical path — it is NOT verifiable
// without the secret key.
//
// ③ Future: If VRF is needed, it MUST be PQ-safe.
//
// Candidate constructions:
//   - Lattice-based VRF (Esgin et al., 2019)
//   - LWE-based VRF
//   - Hash-based VRF (conservative but large proofs)
//
// ============================================================

/// VRF output: 32-byte pseudorandom value.
pub type VrfOutput = [u8; 32];

/// VRF proof (size depends on construction).
pub type VrfProof = Vec<u8>;

#[derive(Debug, thiserror::Error)]
pub enum PqVrfError {
    #[error("pqVRF not yet implemented — awaiting mature lattice VRF construction")]
    NotImplemented,
    #[error("VRF verification failed")]
    VerifyFailed,
}

/// pqVRF trait — to be implemented when a construction matures.
///
/// Usage (future):
///   let (output, proof) = vrf.evaluate(sk, input)?;
///   let valid = vrf.verify(pk, input, output, proof)?;
pub trait PqVrf {
    /// Evaluate VRF: (sk, input) → (output, proof)
    fn evaluate(&self, secret_key: &[u8], input: &[u8]) -> Result<(VrfOutput, VrfProof), PqVrfError>;

    /// Verify VRF: (pk, input, output, proof) → bool
    fn verify(&self, public_key: &[u8], input: &[u8], output: &VrfOutput, proof: &VrfProof) -> Result<bool, PqVrfError>;
}

/// Placeholder: returns NotImplemented for all calls.
pub struct StubPqVrf;

impl PqVrf for StubPqVrf {
    fn evaluate(&self, _sk: &[u8], _input: &[u8]) -> Result<(VrfOutput, VrfProof), PqVrfError> {
        Err(PqVrfError::NotImplemented)
    }

    fn verify(&self, _pk: &[u8], _input: &[u8], _output: &VrfOutput, _proof: &VrfProof) -> Result<bool, PqVrfError> {
        Err(PqVrfError::NotImplemented)
    }
}

/// Temporary: SHAKE256-based "VRF" for testnet.
///
/// NOT a real VRF — no verifiability property.
/// ONLY for testnet leader selection until pqVRF matures.
///
/// output = SHAKE256("MISAKA_VRF" || sk[0:32] || input, 32)
///
/// This is deterministic and pseudorandom but NOT verifiable
/// without revealing the secret key. Do NOT use in production.
pub struct TestnetPseudoVrf;

impl PqVrf for TestnetPseudoVrf {
    fn evaluate(&self, secret_key: &[u8], input: &[u8]) -> Result<(VrfOutput, VrfProof), PqVrfError> {
        use crate::hash::{Domain, domain_hash_multi};
        let sk_prefix = if secret_key.len() >= 32 { &secret_key[..32] } else { secret_key };
        let output_vec = domain_hash_multi(Domain::Vrf, &[sk_prefix, input], 32);
        let mut output = [0u8; 32];
        output.copy_from_slice(&output_vec);
        // "proof" is just a hash — not verifiable without sk
        let proof = domain_hash_multi(Domain::Vrf, &[&output, input], 32);
        Ok((output, proof))
    }

    fn verify(&self, _pk: &[u8], _input: &[u8], _output: &VrfOutput, _proof: &VrfProof) -> Result<bool, PqVrfError> {
        // Cannot verify without sk — this is the limitation
        // Production pqVRF will support verification with pk only
        Err(PqVrfError::VerifyFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_returns_not_implemented() {
        let vrf = StubPqVrf;
        assert!(vrf.evaluate(b"sk", b"input").is_err());
        assert!(vrf.verify(b"pk", b"input", &[0; 32], &vec![]).is_err());
    }

    #[test]
    fn test_testnet_pseudo_vrf_deterministic() {
        let vrf = TestnetPseudoVrf;
        let sk = [0x42u8; 64];
        let (out1, _) = vrf.evaluate(&sk, b"block-42").unwrap();
        let (out2, _) = vrf.evaluate(&sk, b"block-42").unwrap();
        assert_eq!(out1, out2, "Same (sk, input) must produce same output");

        let (out3, _) = vrf.evaluate(&sk, b"block-43").unwrap();
        assert_ne!(out1, out3, "Different input must produce different output");
    }
}
