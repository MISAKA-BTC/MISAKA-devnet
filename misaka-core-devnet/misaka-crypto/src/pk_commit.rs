// ============================================================
// MISAKA Network — Public Key Commitment
// ============================================================
//
// AUDIT FIX #8: Plain sha3(pk) is dangerous because:
//   - No algorithm identification → migration confusion
//   - No version tagging → can't distinguish Falcon from future algos
//   - Collision risk if same hash used for different key types
//
// Solution: Structured commitment with multihash-like format:
//
//   commitment = SHAKE256(
//     "MISAKA_PK_COMMIT" ||        ← domain separation (#7)
//     version(1) ||                 ← protocol version
//     algorithm_id(2) ||            ← key algorithm tag
//     key_length(4 LE) ||           ← explicit length
//     public_key_bytes             ← the actual key
//   , 32)
//
// This means:
//   - Falcon-512 PK and Kyber-768 PK produce different commitments
//     even if the bytes were somehow the same
//   - Future algorithm migration (e.g., Falcon → HAWK) won't
//     collide with existing commitments
//   - The commitment is self-describing: you can verify which
//     algorithm was used
//
// Merkle commitment (for multi-key wallets):
//   root = MerkleRoot(commitment_falcon, commitment_kyber, ...)
//
// ============================================================

use crate::hash::{Domain, domain_hash, domain_hash_32, domain_hash_multi, merkle_root};

/// Protocol version for PK commitments
const PK_COMMIT_VERSION: u8 = 1;

/// Algorithm identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KeyAlgorithm {
    /// Falcon-512 (NIST FIPS 206)
    Falcon512 = 0x0001,
    /// ML-KEM-768 / Kyber-768 (NIST FIPS 203)
    Kyber768 = 0x0002,
    /// Future: HAWK, NTRU+, etc.
    Reserved = 0xFFFF,
}

/// A structured public key commitment.
///
/// 32 bytes, includes algorithm identification and version.
/// Stored on-chain where full PK is too large (e.g., Solana 32-byte fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkCommitment {
    /// The 32-byte commitment value
    pub bytes: [u8; 32],
    /// Which algorithm this commitment is for
    pub algorithm: KeyAlgorithm,
}

/// Compute a structured PK commitment.
///
/// commitment = SHAKE256("MISAKA_PK_COMMIT" || version || algo_id || key_len || pk, 32)
///
/// This replaces the naive `sha3(pk)` approach (audit fix #8).
pub fn compute_pk_commitment(algorithm: KeyAlgorithm, public_key: &[u8]) -> PkCommitment {
    let mut input = Vec::with_capacity(1 + 2 + 4 + public_key.len());

    // Version byte
    input.push(PK_COMMIT_VERSION);

    // Algorithm ID (2 bytes LE)
    input.extend_from_slice(&(algorithm as u16).to_le_bytes());

    // Key length (4 bytes LE) — explicit, prevents truncation attacks
    input.extend_from_slice(&(public_key.len() as u32).to_le_bytes());

    // Public key bytes
    input.extend_from_slice(public_key);

    let bytes = domain_hash_32(Domain::PkCommit, &input);

    PkCommitment { bytes, algorithm }
}

/// Verify a PK commitment matches a public key.
pub fn verify_pk_commitment(
    commitment: &PkCommitment,
    algorithm: KeyAlgorithm,
    public_key: &[u8],
) -> bool {
    if commitment.algorithm != algorithm {
        return false;
    }
    let recomputed = compute_pk_commitment(algorithm, public_key);
    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in commitment.bytes.iter().zip(recomputed.bytes.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Compute a Merkle commitment over multiple keys.
///
/// For Jamtis wallets: root = Merkle(falcon_commit, kyber_commit)
/// This binds both keys into a single 32-byte identifier.
pub fn compute_multi_key_commitment(commitments: &[PkCommitment]) -> [u8; 32] {
    let items: Vec<&[u8]> = commitments.iter().map(|c| c.bytes.as_slice()).collect();
    merkle_root(&items)
}

/// Compute the Falcon-512 PK commitment (convenience).
///
/// Replaces: `sha3_256(falcon_pk)` throughout the codebase.
pub fn falcon_pk_commitment(falcon_pk: &[u8]) -> PkCommitment {
    compute_pk_commitment(KeyAlgorithm::Falcon512, falcon_pk)
}

/// Compute the Kyber-768 PK commitment (convenience).
pub fn kyber_pk_commitment(kyber_pk: &[u8]) -> PkCommitment {
    compute_pk_commitment(KeyAlgorithm::Kyber768, kyber_pk)
}

/// Serialization: commitment → 34 bytes (32 hash + 2 algo ID)
pub fn serialize_commitment(c: &PkCommitment) -> [u8; 34] {
    let mut buf = [0u8; 34];
    buf[0..32].copy_from_slice(&c.bytes);
    buf[32..34].copy_from_slice(&(c.algorithm as u16).to_le_bytes());
    buf
}

/// Deserialization: 34 bytes → commitment
pub fn deserialize_commitment(buf: &[u8; 34]) -> PkCommitment {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&buf[0..32]);
    let algo_id = u16::from_le_bytes([buf[32], buf[33]]);
    let algorithm = match algo_id {
        0x0001 => KeyAlgorithm::Falcon512,
        0x0002 => KeyAlgorithm::Kyber768,
        _ => KeyAlgorithm::Reserved,
    };
    PkCommitment { bytes, algorithm }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_different_algos_different_commitments() {
        let fake_key = [0xAAu8; 897]; // Same bytes, different algorithm tag
        let c_falcon = compute_pk_commitment(KeyAlgorithm::Falcon512, &fake_key);
        let c_kyber = compute_pk_commitment(KeyAlgorithm::Kyber768, &fake_key);
        assert_ne!(
            c_falcon.bytes, c_kyber.bytes,
            "Same key bytes with different algo must produce different commitments"
        );
    }

    #[test]
    fn test_commitment_verification() {
        let pk = [0xBBu8; 897];
        let c = falcon_pk_commitment(&pk);
        assert!(verify_pk_commitment(&c, KeyAlgorithm::Falcon512, &pk));
        // Wrong key
        let wrong_pk = [0xCCu8; 897];
        assert!(!verify_pk_commitment(&c, KeyAlgorithm::Falcon512, &wrong_pk));
        // Wrong algorithm
        assert!(!verify_pk_commitment(&c, KeyAlgorithm::Kyber768, &pk));
    }

    #[test]
    fn test_multi_key_commitment() {
        let falcon_c = falcon_pk_commitment(&[0xAA; 897]);
        let kyber_c = kyber_pk_commitment(&[0xBB; 1184]);
        let root = compute_multi_key_commitment(&[falcon_c, kyber_c]);
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let c = falcon_pk_commitment(&[0x42; 897]);
        let bytes = serialize_commitment(&c);
        let c2 = deserialize_commitment(&bytes);
        assert_eq!(c.bytes, c2.bytes);
        assert_eq!(c.algorithm, c2.algorithm);
    }
}
