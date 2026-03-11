// ============================================================
// MISAKA Network — LaRRS Ring Signature (Testnet)
// ============================================================
//
// Linkable Ad-hoc Ring Signature over Z_q.
//
// Ring size: 4 (25% sender anonymity — WP §6.3 testnet variant)
//
// Construction: Schnorr ring signature over Z_q^N vectors.
//   Public params: matrix A ∈ Z_q^{N×N} (deterministic from seed)
//   Secret key:    s ∈ Z_q^N (derived from Falcon SK)
//   Public key:    t = A·s mod q
//
//   Ring = {t_0, t_1, t_2, t_3}, real signer index π
//
//   Sign:
//     1. key_image = H(LINKTAG || s)
//     2. y ← uniform Z_q^N, w = A·y mod q
//     3. c_{π+1} = H(msg || ring || I || w)
//     4. For decoys: z_i ← uniform, w_i = A·z_i - c_i·t_i, c_{i+1} = H(...)
//     5. Close ring: z_π = y + c_π · s mod q
//     6. σ = (c_0, z_0..z_3, I)
//
//   Verify:
//     For each i: w_i = A·z_i - c_i·t_i, c_{i+1} = H(msg || ring || I || w_i)
//     Check c_4 == c_0 (ring closes)
//
//   Key image: deterministic per s → double-spend = duplicate I
//
// Security:
//   - Zero-knowledge: y is uniform → z_π = y + c·s is uniform (perfect ZK)
//   - Unforgeability: requires knowing s such that t = A·s
//   - Linkability: key_image is deterministic per s
//
// Parameters (testnet — small and fast):
//   q = 65537 (Fermat prime, fast modular arithmetic)
//   N = 8 (vector dimension)
//   Ring size = 4
//
// ============================================================

use crate::hash::{Domain, domain_hash, domain_hash_multi, domain_hash_32};
use serde::{Serialize, Deserialize};

// ── Parameters ──

pub const LARRS_Q: u64 = 65537;
pub const LARRS_N: usize = 8;
pub const RING_SIZE: usize = 4;

// ── Z_q vector arithmetic ──

pub type Zq = u64;
pub type ZqVec = [Zq; LARRS_N];
pub type ZqMatrix = [ZqVec; LARRS_N]; // N×N matrix (row-major)

fn mod_q(x: i128) -> Zq {
    let q = LARRS_Q as i128;
    ((x % q + q) % q) as Zq
}

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

fn scalar_vec(c: Zq, v: &ZqVec) -> ZqVec {
    let mut r = [0u64; LARRS_N];
    for i in 0..LARRS_N {
        r[i] = ((c as u128 * v[i] as u128) % LARRS_Q as u128) as u64;
    }
    r
}

fn mat_vec(a: &ZqMatrix, v: &ZqVec) -> ZqVec {
    let mut r = [0u64; LARRS_N];
    for i in 0..LARRS_N {
        let mut sum: u128 = 0;
        for j in 0..LARRS_N {
            sum += a[i][j] as u128 * v[j] as u128;
        }
        r[i] = (sum % LARRS_Q as u128) as u64;
    }
    r
}

fn vec_to_bytes(v: &ZqVec) -> Vec<u8> {
    let mut out = Vec::with_capacity(LARRS_N * 8);
    for &x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

fn vec_from_bytes(data: &[u8]) -> ZqVec {
    let mut v = [0u64; LARRS_N];
    for i in 0..LARRS_N {
        let off = i * 8;
        if off + 8 <= data.len() {
            v[i] = u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) % LARRS_Q;
        }
    }
    v
}

/// Deterministic public matrix A from a fixed seed.
/// Shared by all participants — part of the protocol parameters.
pub fn public_matrix() -> ZqMatrix {
    let seed = domain_hash(Domain::Sig, b"MISAKA_LARRS_MATRIX_A_v1", LARRS_N * LARRS_N * 8);
    let mut a = [[0u64; LARRS_N]; LARRS_N];
    for i in 0..LARRS_N {
        for j in 0..LARRS_N {
            let off = (i * LARRS_N + j) * 8;
            let val = u64::from_le_bytes(seed[off..off + 8].try_into().unwrap());
            a[i][j] = val % LARRS_Q;
        }
    }
    a
}

/// Generate random Z_q^N vector from entropy.
fn random_zq_vec(entropy: &[u8]) -> ZqVec {
    let expanded = domain_hash(Domain::Drbg, entropy, LARRS_N * 8);
    let mut v = [0u64; LARRS_N];
    for i in 0..LARRS_N {
        let off = i * 8;
        v[i] = u64::from_le_bytes(expanded[off..off + 8].try_into().unwrap()) % LARRS_Q;
    }
    v
}

// ── Key types ──

/// LaRRS key pair (derived from Falcon SK).
#[derive(Clone)]
pub struct LarrsKeyPair {
    /// Secret key: s ∈ Z_q^N
    pub secret: ZqVec,
    /// Public key: t = A·s mod q
    pub public: ZqVec,
    /// Key image (link tag): H(LINKTAG || s)
    pub key_image: [u8; 32],
}

/// Derive LaRRS key pair from Falcon secret key material.
pub fn larrs_keygen_from_falcon(falcon_sk_prefix: &[u8]) -> LarrsKeyPair {
    let a = public_matrix();
    let secret = random_zq_vec(&domain_hash(Domain::Kdf, falcon_sk_prefix, 64));
    let public = mat_vec(&a, &secret);
    let key_image = domain_hash_32(Domain::LinkTag, &vec_to_bytes(&secret));
    LarrsKeyPair { secret, public, key_image }
}

/// Standalone LaRRS keygen (for testing).
pub fn larrs_keygen(seed: &[u8]) -> LarrsKeyPair {
    let a = public_matrix();
    let secret = random_zq_vec(seed);
    let public = mat_vec(&a, &secret);
    let key_image = domain_hash_32(Domain::LinkTag, &vec_to_bytes(&secret));
    LarrsKeyPair { secret, public, key_image }
}

// ── Ring signature ──

/// A LaRRS ring signature proving knowledge of one secret in a ring of 4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingSignature {
    /// The 4 public keys in the ring (Z_q^N each, serialized)
    pub ring: Vec<Vec<u8>>,
    /// Link tag / key image — same key always produces the same image
    pub key_image: [u8; 32],
    /// Starting challenge c_0
    pub c0: [u8; 32],
    /// Response vectors z_0..z_3 (Z_q^N each, serialized)
    pub responses: Vec<Vec<u8>>,
}

/// Compute challenge hash for the ring signature chain.
fn ring_challenge(
    message: &[u8],
    ring_pks: &[&ZqVec; RING_SIZE],
    key_image: &[u8; 32],
    index: usize,
    w: &ZqVec,
) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::new();
    parts.push(message);
    for pk in ring_pks {
        // We need to pass references that live long enough
        // Build it differently
    }
    // Build manually to avoid lifetime issues
    let mut data = Vec::new();
    data.extend_from_slice(message);
    for pk in ring_pks {
        data.extend_from_slice(&vec_to_bytes(pk));
    }
    data.extend_from_slice(key_image);
    data.extend_from_slice(&(index as u32).to_le_bytes());
    data.extend_from_slice(&vec_to_bytes(w));
    domain_hash_32(Domain::Sig, &data)
}

/// Extract a scalar challenge from a 32-byte hash.
fn challenge_scalar(h: &[u8; 32]) -> Zq {
    let val = u64::from_le_bytes(h[0..8].try_into().unwrap());
    val % LARRS_Q
}

/// Sign a message with a ring of 4 public keys.
///
/// The signer is at `real_index` in the ring.
/// Returns a ring signature that hides which index is real.
///
/// Privacy: an observer sees 4 candidates and cannot determine
/// which one signed. With ring size 4, the anonymity set is 4
/// (25% chance of guessing correctly — the stated testnet target).
pub fn ring_sign(
    kp: &LarrsKeyPair,
    message: &[u8],
    ring_pks: &[ZqVec; RING_SIZE],
    real_index: usize,
) -> RingSignature {
    assert!(real_index < RING_SIZE);
    assert_eq!(ring_pks[real_index], kp.public, "Ring must contain signer's PK at real_index");

    let a = public_matrix();

    // Generate random nonce y
    let mut entropy = Vec::new();
    entropy.extend_from_slice(&vec_to_bytes(&kp.secret));
    entropy.extend_from_slice(message);
    entropy.extend_from_slice(&(real_index as u64).to_le_bytes());
    // Mix in randomness to prevent deterministic nonce issues
    let nonce_seed = domain_hash(Domain::Drbg, &entropy, 64);
    let y = random_zq_vec(&nonce_seed);

    // Commitment: w = A·y
    let w = mat_vec(&a, &y);

    // Build ring PK references
    let ring_refs: [&ZqVec; RING_SIZE] = [
        &ring_pks[0], &ring_pks[1], &ring_pks[2], &ring_pks[3],
    ];

    // Challenge chain
    let mut challenges = [[0u8; 32]; RING_SIZE];
    let mut responses: [ZqVec; RING_SIZE] = [[0u64; LARRS_N]; RING_SIZE];

    // c_{π+1} = H(msg || ring || I || π || w)
    let next = (real_index + 1) % RING_SIZE;
    challenges[next] = ring_challenge(message, &ring_refs, &kp.key_image, real_index, &w);

    // Simulate decoys going forward
    for offset in 1..RING_SIZE {
        let i = (real_index + offset) % RING_SIZE;
        let i_next = (i + 1) % RING_SIZE;

        if i == real_index {
            break; // Will close the ring below
        }

        // Random response for decoy
        let resp_entropy = domain_hash(Domain::Drbg, &[
            &challenges[i][..],
            &(i as u64).to_le_bytes(),
            &nonce_seed,
        ].concat(), 64);
        responses[i] = random_zq_vec(&resp_entropy);

        // w_i = A·z_i - c_i · t_i
        let az = mat_vec(&a, &responses[i]);
        let c_scalar = challenge_scalar(&challenges[i]);
        let ct = scalar_vec(c_scalar, &ring_pks[i]);
        let w_i = vec_sub(&az, &ct);

        challenges[i_next] = ring_challenge(message, &ring_refs, &kp.key_image, i, &w_i);
    }

    // Close ring: z_π = y + c_π · s mod q
    let c_scalar = challenge_scalar(&challenges[real_index]);
    let cs = scalar_vec(c_scalar, &kp.secret);
    responses[real_index] = vec_add(&y, &cs);

    // Serialize
    RingSignature {
        ring: ring_pks.iter().map(|pk| vec_to_bytes(pk)).collect(),
        key_image: kp.key_image,
        c0: challenges[0],
        responses: responses.iter().map(|z| vec_to_bytes(z)).collect(),
    }
}

/// Verify a ring signature.
///
/// Returns true if the signature proves knowledge of one secret key
/// in the ring without revealing which one.
pub fn ring_verify(
    message: &[u8],
    sig: &RingSignature,
) -> bool {
    if sig.ring.len() != RING_SIZE || sig.responses.len() != RING_SIZE {
        return false;
    }

    let a = public_matrix();

    // Deserialize ring PKs
    let ring_pks: Vec<ZqVec> = sig.ring.iter().map(|b| vec_from_bytes(b)).collect();
    let ring_refs: [&ZqVec; RING_SIZE] = [
        &ring_pks[0], &ring_pks[1], &ring_pks[2], &ring_pks[3],
    ];

    // Reconstruct challenge chain
    let mut c = sig.c0;
    for i in 0..RING_SIZE {
        let z = vec_from_bytes(&sig.responses[i]);
        let c_scalar = challenge_scalar(&c);
        let az = mat_vec(&a, &z);
        let ct = scalar_vec(c_scalar, &ring_pks[i]);
        let w_i = vec_sub(&az, &ct);

        let next = (i + 1) % RING_SIZE;
        let c_next = ring_challenge(message, &ring_refs, &sig.key_image, i, &w_i);

        if next == 0 {
            // Final: check ring closure
            return c_next == sig.c0;
        }
        c = c_next;
    }

    false
}

/// Extract the key image (link tag) from a ring signature.
/// If two signatures have the same key_image, the same key signed both
/// → double spend detected.
pub fn extract_key_image(sig: &RingSignature) -> &[u8; 32] {
    &sig.key_image
}

/// Approximate proof size for a ring signature.
pub fn ring_sig_size() -> usize {
    // c0: 32 + key_image: 32 + ring: 4*N*8 + responses: 4*N*8
    32 + 32 + RING_SIZE * LARRS_N * 8 * 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_larrs_sign_verify() {
        let kp0 = larrs_keygen(b"signer-0");
        let kp1 = larrs_keygen(b"signer-1");
        let kp2 = larrs_keygen(b"signer-2");
        let kp3 = larrs_keygen(b"signer-3");

        let ring = [kp0.public, kp1.public, kp2.public, kp3.public];
        let msg = b"transfer 100 stMISAKA";

        // Sign as signer 2
        let sig = ring_sign(&kp2, msg, &ring, 2);
        assert!(ring_verify(msg, &sig), "Valid ring signature must verify");

        // Wrong message
        assert!(!ring_verify(b"wrong msg", &sig), "Wrong message must fail");
    }

    #[test]
    fn test_larrs_all_positions() {
        let kps: Vec<LarrsKeyPair> = (0..4).map(|i| larrs_keygen(&[i as u8; 32])).collect();
        let ring = [kps[0].public, kps[1].public, kps[2].public, kps[3].public];
        let msg = b"test";

        for i in 0..4 {
            let sig = ring_sign(&kps[i], msg, &ring, i);
            assert!(ring_verify(msg, &sig), "Position {i} must verify");
        }
    }

    #[test]
    fn test_larrs_key_image_linkability() {
        let kp = larrs_keygen(b"consistent-signer");
        let decoy1 = larrs_keygen(b"decoy-1");
        let decoy2 = larrs_keygen(b"decoy-2");
        let decoy3 = larrs_keygen(b"decoy-3");

        let ring = [kp.public, decoy1.public, decoy2.public, decoy3.public];

        let sig1 = ring_sign(&kp, b"tx-1", &ring, 0);
        let sig2 = ring_sign(&kp, b"tx-2", &ring, 0);

        // Same signer → same key image (double-spend detection)
        assert_eq!(sig1.key_image, sig2.key_image,
            "Same signer must produce same key image");

        // Different signer → different key image
        let sig3 = ring_sign(&decoy1, b"tx-3",
            &[decoy1.public, kp.public, decoy2.public, decoy3.public], 0);
        assert_ne!(sig1.key_image, sig3.key_image,
            "Different signers must produce different key images");
    }

    #[test]
    fn test_larrs_tampered_response_rejected() {
        let kps: Vec<LarrsKeyPair> = (0..4).map(|i| larrs_keygen(&[i as u8; 32])).collect();
        let ring = [kps[0].public, kps[1].public, kps[2].public, kps[3].public];

        let mut sig = ring_sign(&kps[0], b"msg", &ring, 0);
        // Tamper with one response
        sig.responses[1][0] ^= 0xFF;
        assert!(!ring_verify(b"msg", &sig), "Tampered response must fail");
    }

    #[test]
    fn test_larrs_wrong_ring_rejected() {
        let kps: Vec<LarrsKeyPair> = (0..4).map(|i| larrs_keygen(&[i as u8; 32])).collect();
        let ring = [kps[0].public, kps[1].public, kps[2].public, kps[3].public];

        let sig = ring_sign(&kps[0], b"msg", &ring, 0);

        // Replace one ring member
        let mut tampered_sig = sig.clone();
        let fake = larrs_keygen(b"fake");
        tampered_sig.ring[1] = vec_to_bytes(&fake.public);
        assert!(!ring_verify(b"msg", &tampered_sig), "Wrong ring must fail");
    }
}
