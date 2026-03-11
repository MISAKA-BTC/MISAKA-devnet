// ============================================================
// MISAKA Network — Unified Hash (SHAKE256 + Domain Separation)
// ============================================================
//
// AUDIT FIX #6: Unify all hashing to SHAKE256 (XOF).
//   - Variable output length
//   - Single primitive for the entire chain
//   - No SHA3-256 / SHAKE256 混在
//
// AUDIT FIX #7: Mandatory domain separation.
//   - Every hash call MUST include a domain tag
//   - Prevents cross-protocol attacks
//   - Domain tags are compile-time constants
//
// Usage:
//   let h = domain_hash(Domain::Tx, &tx_bytes, 32);
//   let h = domain_hash(Domain::Block, &block_bytes, 32);
//   let h = domain_hash(Domain::Sig, &msg, 32);
//   let h = domain_hash(Domain::Address, &pk_bytes, 20);
//   let h = domain_hash_multi(Domain::Merkle, &[&left, &right], 32);
//
// XOF advantage:
//   - 32 bytes for fingerprints/addresses
//   - 48 bytes for DRBG seed material
//   - 64 bytes for key derivation
//   - 20 bytes for short addresses
//   All from the same primitive, domain-separated.
//
// ============================================================

use sha3::Shake256;
use sha3::digest::{Update, ExtendableOutput, XofReader};

/// Domain tags — compile-time constants preventing cross-protocol attacks.
///
/// AUDIT FIX #7: Every hash operation MUST use one of these domains.
/// Adding a new domain requires updating this enum — no ad-hoc strings.
#[derive(Debug, Clone, Copy)]
pub enum Domain {
    /// Transaction hashing: H("MISAKA_TX" || data)
    Tx,
    /// Block header hashing: H("MISAKA_BLOCK" || data)
    Block,
    /// Signature message hashing: H("MISAKA_SIG" || data)
    Sig,
    /// BFT vote hashing: H("MISAKA_VOTE" || data)
    Vote,
    /// Address derivation: H("MISAKA_ADDR" || data)
    Address,
    /// Public key fingerprint: H("MISAKA_FINGERPRINT" || data)
    Fingerprint,
    /// Merkle tree node: H("MISAKA_MERKLE" || data)
    Merkle,
    /// Key derivation (HKDF-like): H("MISAKA_KDF" || data)
    Kdf,
    /// DRBG state update: H("MISAKA_DRBG" || data)
    Drbg,
    /// P2P handshake transcript: H("MISAKA_HANDSHAKE" || data)
    Handshake,
    /// Session key derivation: H("MISAKA_SESSION" || data)
    Session,
    /// Link tag (double-spend prevention): H("MISAKA_LINKTAG" || data)
    LinkTag,
    /// View tag derivation: H("MISAKA_VIEWTAG" || data)
    ViewTag,
    /// Amount encryption key: H("MISAKA_AMOUNT" || data)
    Amount,
    /// Stealth address derivation: H("MISAKA_STEALTH" || data)
    Stealth,
    /// Commitment blinding: H("MISAKA_COMMIT" || data)
    Commitment,
    /// Fee commitment: H("MISAKA_FEE" || data)
    Fee,
    /// PK Merkle commitment: H("MISAKA_PK_COMMIT" || data)
    PkCommit,
    /// VRF evaluation (testnet pseudo-VRF): H("MISAKA_VRF" || data)
    Vrf,
}

impl Domain {
    /// Get the domain separator bytes.
    /// Each is unique and fixed-length-prefixed to prevent collisions.
    fn tag(&self) -> &'static [u8] {
        match self {
            Domain::Tx          => b"MISAKA_TX\x00",
            Domain::Block       => b"MISAKA_BLOCK\x00",
            Domain::Sig         => b"MISAKA_SIG\x00",
            Domain::Vote        => b"MISAKA_VOTE\x00",
            Domain::Address     => b"MISAKA_ADDR\x00",
            Domain::Fingerprint => b"MISAKA_FINGERPRINT\x00",
            Domain::Merkle      => b"MISAKA_MERKLE\x00",
            Domain::Kdf         => b"MISAKA_KDF\x00",
            Domain::Drbg        => b"MISAKA_DRBG\x00",
            Domain::Handshake   => b"MISAKA_HANDSHAKE\x00",
            Domain::Session     => b"MISAKA_SESSION\x00",
            Domain::LinkTag     => b"MISAKA_LINKTAG\x00",
            Domain::ViewTag     => b"MISAKA_VIEWTAG\x00",
            Domain::Amount      => b"MISAKA_AMOUNT\x00",
            Domain::Stealth     => b"MISAKA_STEALTH\x00",
            Domain::Commitment  => b"MISAKA_COMMIT\x00",
            Domain::Fee         => b"MISAKA_FEE\x00",
            Domain::PkCommit    => b"MISAKA_PK_COMMIT\x00",
            Domain::Vrf         => b"MISAKA_VRF\x00",
        }
    }
}

/// Domain-separated SHAKE256 hash.
///
/// H(domain_tag || data) → output of `out_len` bytes.
///
/// This is the ONLY hash function that should be called in the
/// entire MISAKA codebase. All other hash calls are errors.
pub fn domain_hash(domain: Domain, data: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    Update::update(&mut h, domain.tag());
    Update::update(&mut h, data);
    let mut xof = ExtendableOutput::finalize_xof(h);
    let mut result = vec![0u8; out_len];
    XofReader::read(&mut xof, &mut result);
    result
}

/// Domain-separated SHAKE256 hash with multiple inputs.
///
/// H(domain_tag || len(data[0]) || data[0] || len(data[1]) || data[1] || ...)
///
/// Length-prefixing prevents ambiguity between different input splits.
pub fn domain_hash_multi(domain: Domain, parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    Update::update(&mut h, domain.tag());
    for part in parts {
        // 4-byte little-endian length prefix for each part
        let len_bytes = (part.len() as u32).to_le_bytes();
        Update::update(&mut h, &len_bytes);
        Update::update(&mut h, part);
    }
    let mut xof = ExtendableOutput::finalize_xof(h);
    let mut result = vec![0u8; out_len];
    XofReader::read(&mut xof, &mut result);
    result
}

/// Fixed 32-byte domain hash (most common case).
pub fn domain_hash_32(domain: Domain, data: &[u8]) -> [u8; 32] {
    let v = domain_hash(domain, data, 32);
    let mut result = [0u8; 32];
    result.copy_from_slice(&v);
    result
}

/// SHAKE256 XOF for variable-length output (DRBG, KDF).
///
/// H(domain_tag || data) → XOF reader for streaming output.
pub fn domain_xof(domain: Domain, data: &[u8]) -> impl XofReader {
    let mut h = Shake256::default();
    Update::update(&mut h, domain.tag());
    Update::update(&mut h, data);
    ExtendableOutput::finalize_xof(h)
}

// ── Merkle Tree (SHAKE256 domain-separated) ──

/// SHA3-256 Merkle root using domain-separated SHAKE256.
///
/// Leaf: H(MERKLE || 0x00 || item)
/// Node: H(MERKLE || 0x01 || left || right)
///
/// The 0x00/0x01 prefix distinguishes leaf from internal nodes,
/// preventing second-preimage attacks on the tree structure.
pub fn merkle_root(items: &[&[u8]]) -> [u8; 32] {
    if items.is_empty() {
        return domain_hash_32(Domain::Merkle, &[0x00]); // empty tree
    }

    // Leaf hashes
    let mut level: Vec<[u8; 32]> = items.iter().map(|item| {
        let mut input = vec![0x00u8]; // leaf prefix
        input.extend_from_slice(item);
        domain_hash_32(Domain::Merkle, &input)
    }).collect();

    // Build tree bottom-up
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            let mut input = vec![0x01u8]; // internal node prefix
            input.extend_from_slice(&chunk[0]);
            input.extend_from_slice(chunk.get(1).unwrap_or(&chunk[0]));
            next.push(domain_hash_32(Domain::Merkle, &input));
        }
        level = next;
    }

    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separation_produces_different_hashes() {
        let data = b"same input data";
        let h_tx = domain_hash_32(Domain::Tx, data);
        let h_block = domain_hash_32(Domain::Block, data);
        let h_sig = domain_hash_32(Domain::Sig, data);

        assert_ne!(h_tx, h_block, "TX and Block domains must differ");
        assert_ne!(h_tx, h_sig, "TX and Sig domains must differ");
        assert_ne!(h_block, h_sig, "Block and Sig domains must differ");
    }

    #[test]
    fn test_domain_hash_deterministic() {
        let h1 = domain_hash_32(Domain::Tx, b"test");
        let h2 = domain_hash_32(Domain::Tx, b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_variable_output_length() {
        let h20 = domain_hash(Domain::Address, b"pk", 20);
        let h32 = domain_hash(Domain::Address, b"pk", 32);
        let h48 = domain_hash(Domain::Address, b"pk", 48);

        assert_eq!(h20.len(), 20);
        assert_eq!(h32.len(), 32);
        assert_eq!(h48.len(), 48);
        // First 20 bytes should be same prefix
        assert_eq!(&h32[..20], &h20[..]);
    }

    #[test]
    fn test_multi_input_length_prefix() {
        // H(domain || "ab" || "cd") != H(domain || "a" || "bcd")
        let h1 = domain_hash_multi(Domain::Merkle, &[b"ab", b"cd"], 32);
        let h2 = domain_hash_multi(Domain::Merkle, &[b"a", b"bcd"], 32);
        assert_ne!(h1, h2, "Length-prefixed multi-hash must prevent ambiguity");
    }

    #[test]
    fn test_merkle_root() {
        let items: Vec<&[u8]> = vec![b"tx1", b"tx2", b"tx3"];
        let root = merkle_root(&items);
        assert_eq!(root.len(), 32);

        // Empty tree
        let empty_root = merkle_root(&[]);
        assert_ne!(root, empty_root);

        // Single item
        let single_root = merkle_root(&[b"tx1"]);
        assert_ne!(single_root, root);
    }

    #[test]
    fn test_merkle_leaf_vs_internal_node() {
        // Leaf H(0x00 || data) must differ from node H(0x01 || data)
        // This prevents second-preimage attacks
        let leaf = domain_hash_32(Domain::Merkle, &[0x00, 0xAA, 0xBB]);
        let node = domain_hash_32(Domain::Merkle, &[0x01, 0xAA, 0xBB]);
        assert_ne!(leaf, node);
    }
}
