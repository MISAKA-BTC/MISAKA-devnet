// ============================================================
// MISAKA Network — Cryptographic Primitives
// ============================================================
//
// Phase 1 (foundation):
pub mod hash;         // SHAKE256 unified XOF + domain separation
pub mod drbg;         // SHAKE256-DRBG (SP 800-90A style)
pub mod falcon;       // Falcon-512 (PQClean, NIST FIPS 206)
pub mod dilithium;    // Dilithium5 / ML-DSA-87 (PQClean, NIST FIPS 204)
pub mod hybrid_sig;   // Falcon-512 || Dilithium5 (AND verification)
pub mod kyber;        // ML-KEM-768 (PQClean, NIST FIPS 203)
pub mod ed25519;      // Ed25519 (classical, migration bridge only)
pub mod dual_sig;     // Hybrid mandatory + Ed25519 optional TX
pub mod pk_commit;    // Structured PK commitment (algo-tagged)
pub mod address;      // Bech32 address (32-byte payload)
pub mod keys;         // MasterSeed → Jamtis wallet key hierarchy
pub mod session;      // AES-256-GCM session encryption (P2P)
pub mod pq_vrf;       // pqVRF stub (future, NOT in consensus)
//
// Phase 2 (privacy layer):
pub mod ring_sig;     // LaRRS ring signature (Z_q Schnorr ring, size 4)
pub mod signing;      // Falcon signing hardening (domain separation, key roles)
pub mod stealth;      // Jamtis stealth addresses (Kyber-768 KEM)
pub mod commitment;   // Lattice Pedersen commitments + balance proofs
pub mod proof_backend; // Swappable proof backends (testnet / lattice)
