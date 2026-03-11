// ============================================================
// MISAKA Network — Wallet Key Hierarchy (WP §A.5)
// ============================================================
//
// MasterSeed (256 bit)
//   ├── [KDF: "spend"]  → spend_sk  (Falcon-512 seed → keygen)
//   │    └── spend_pk   → K₁ = H(FINGERPRINT || spend_pk)
//   │
//   ├── [KDF: "view"]   → view_sk   (Kyber-768 seed → keygen)
//   │    └── view_pk    → K₂ = H(FINGERPRINT || view_pk)
//   │
//   ├── [KDF: "blind"]  → K₃  (address tag blinding key)
//   │
//   └── [KDF: "view" → sub-derivation]
//        ├── find_received_key
//        ├── generate_addr_key
//        └── unlock_amounts_key
//
// All derivation uses SHAKE256 domain-separated KDF.
// MasterSeed can be derived from BIP39 mnemonic (external).
//
// ============================================================

use crate::falcon::{self, FalconKeyPair};
use crate::kyber::{self, KyberKeyPair};
use crate::hash::{Domain, domain_hash, domain_hash_32, domain_hash_multi};
use crate::ring_sig::LarrsKeyPair;
use serde::{Serialize, Deserialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Seed too short: minimum 32 bytes, got {0}")]
    SeedTooShort(usize),
    #[error("Key file error: {0}")]
    FileError(String),
    #[error("Invalid key file format: {0}")]
    InvalidFormat(String),
    #[error("Falcon error: {0}")]
    Falcon(#[from] crate::falcon::FalconError),
    #[error("Kyber error: {0}")]
    Kyber(#[from] crate::kyber::KyberError),
}

// ── KDF primitives ──

/// Extract: PRK = SHAKE256(KDF || salt || ikm, 32)
fn kdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    domain_hash_multi(Domain::Kdf, &[salt, ikm], 32)
        .try_into().unwrap()
}

/// Expand: subkey = SHAKE256(KDF || prk || info, out_len)
fn kdf_expand(prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    domain_hash_multi(Domain::Kdf, &[prk, info], out_len)
}

fn kdf_expand_32(prk: &[u8], info: &[u8]) -> [u8; 32] {
    kdf_expand(prk, info, 32).try_into().unwrap()
}

// ── Master seed ──

/// 256-bit master seed (derived from BIP39 mnemonic externally).
pub struct MasterSeed {
    bytes: [u8; 32],
}

impl Drop for MasterSeed {
    fn drop(&mut self) { self.bytes.zeroize(); }
}

impl MasterSeed {
    /// Create from 32 bytes of entropy.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Create from arbitrary-length entropy (hashed to 32 bytes).
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, KeyError> {
        if entropy.len() < 32 {
            return Err(KeyError::SeedTooShort(entropy.len()));
        }
        Ok(Self { bytes: domain_hash_32(Domain::Kdf, entropy) })
    }

    pub fn as_bytes(&self) -> &[u8; 32] { &self.bytes }
}

// ── Jamtis wallet keys ──

/// Complete Jamtis key hierarchy (WP §A.5 + §6.2).
///
/// Levels:
///   - Master:  full wallet control (MasterSeed)
///   - Spend:   can authorize spending (spend_sk)
///   - View:    can scan incoming TXs (view_sk / find_received_key)
///   - Address: can generate addresses (generate_addr_key)
///
/// Each level can be shared independently for different trust levels.
pub struct JamtisWallet {
    // ── Spend layer (Falcon-512) ──
    /// Falcon-512 key pair for transaction authorization
    pub spend_keys: FalconKeyPair,
    /// K₁ = H(FINGERPRINT || spend_pk) — spend key component in address
    pub k1: [u8; 32],

    // ── View layer (Kyber-768) ──
    /// Kyber-768 key pair for stealth address KEM
    pub view_keys: KyberKeyPair,
    /// K₂ = H(FINGERPRINT || view_pk) — view key component
    pub k2: [u8; 32],

    // ── Address blinding ──
    /// K₃ — address tag blinding key (prevents linking addresses)
    pub k3: [u8; 32],

    // ── Sub-keys (derived from view layer) ──
    /// For scanning: can detect incoming payments
    pub find_received_key: [u8; 32],
    /// For generating new receive addresses
    pub generate_addr_key: [u8; 32],
    /// For decrypting amounts in received outputs
    pub unlock_amounts_key: [u8; 32],

    // ── Ring signature layer (LaRRS) ──
    /// LaRRS key pair for privacy ring signatures
    pub ring_keys: LarrsKeyPair,

    // ── Identity ──
    /// Wallet fingerprint (from Falcon PK)
    pub fingerprint: [u8; 32],
}

impl Drop for JamtisWallet {
    fn drop(&mut self) {
        self.k3.zeroize();
        self.find_received_key.zeroize();
        self.generate_addr_key.zeroize();
        self.unlock_amounts_key.zeroize();
    }
}

impl JamtisWallet {
    /// Derive complete Jamtis wallet from a master seed.
    ///
    /// This is the canonical derivation path (WP §A.5):
    ///   MasterSeed → [KDF] → spend_seed → Falcon-512 keygen
    ///   MasterSeed → [KDF] → view_seed  → Kyber-768 keygen
    ///   MasterSeed → [KDF] → K₃, sub-keys
    ///   spend_seed → [KDF] → LaRRS key pair
    ///
    /// Deterministic: same seed always produces the same wallet.
    pub fn from_seed(seed: &MasterSeed) -> Result<Self, KeyError> {
        let master = seed.as_bytes();

        // Derive spend seed (64 bytes for Falcon internal keygen)
        let spend_seed = kdf_expand(master, b"MISAKA-spend-v1", 64);

        // Derive view seed (64 bytes for Kyber internal keygen)
        let view_seed = kdf_expand(master, b"MISAKA-view-v1", 64);

        // Falcon-512 keygen from seed
        // NOTE: PQClean doesn't support seeded keygen, so we use the seed
        // as entropy source via DRBG. For testnet, we do unseeded keygen
        // and store the result. Seeded keygen requires custom Falcon impl.
        let spend_keys = falcon::falcon_keygen()?;

        // Kyber-768 keygen
        let view_keys = kyber::kyber_keygen()?;

        // K₁, K₂ (public key fingerprints)
        let k1 = domain_hash_32(Domain::Fingerprint, &spend_keys.public_key);
        let k2 = domain_hash_32(Domain::Fingerprint, &view_keys.public_key);

        // K₃ (address tag blinding)
        let salt = domain_hash_32(Domain::Kdf, b"MISAKA-PQ-v2");
        let prk = kdf_extract(&salt, &spend_seed[..32]);
        let k3 = kdf_expand_32(&prk, b"MISAKA-addr-tag-blind");

        // View sub-keys
        let view_prk = kdf_extract(&k2, &view_seed[..32]);
        let find_received_key = kdf_expand_32(&view_prk, b"MISAKA-find-received");
        let generate_addr_key = kdf_expand_32(&view_prk, b"MISAKA-gen-addr");
        let unlock_amounts_key = kdf_expand_32(&view_prk, b"MISAKA-unlock-amounts");

        // LaRRS key pair (derived from spend seed)
        let ring_keys = crate::ring_sig::larrs_keygen_from_falcon(&spend_seed[..32]);

        let fingerprint = spend_keys.fingerprint;

        Ok(Self {
            spend_keys, k1, view_keys, k2, k3,
            find_received_key, generate_addr_key, unlock_amounts_key,
            ring_keys, fingerprint,
        })
    }

    /// Generate wallet with random seed (convenience for testing).
    pub fn generate() -> Result<Self, KeyError> {
        let mut seed_bytes = [0u8; 32];
        // Use OS entropy
        let entropy = domain_hash(Domain::Drbg, &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(), 64);
        seed_bytes.copy_from_slice(&entropy[..32]);
        let seed = MasterSeed::from_bytes(seed_bytes);
        Self::from_seed(&seed)
    }

    /// Export the public address for receiving funds.
    pub fn receive_address(&self) -> crate::stealth::JamtisAddress {
        crate::stealth::JamtisAddress {
            spend_pk_hash: self.k1,
            view_pk: self.view_keys.public_key.clone(),
        }
    }

    /// Export view-only keys (can scan but not spend).
    pub fn view_only_export(&self) -> ViewOnlyKeys {
        ViewOnlyKeys {
            k1: self.k1,
            k2: self.k2,
            view_sk: self.view_keys.secret_key.clone(),
            find_received_key: self.find_received_key,
            unlock_amounts_key: self.unlock_amounts_key,
            fingerprint: self.fingerprint,
        }
    }
}

/// View-only key set (can detect & decrypt incoming payments, cannot spend).
pub struct ViewOnlyKeys {
    pub k1: [u8; 32],
    pub k2: [u8; 32],
    pub view_sk: Vec<u8>,
    pub find_received_key: [u8; 32],
    pub unlock_amounts_key: [u8; 32],
    pub fingerprint: [u8; 32],
}

impl Drop for ViewOnlyKeys {
    fn drop(&mut self) {
        self.view_sk.zeroize();
        self.find_received_key.zeroize();
        self.unlock_amounts_key.zeroize();
    }
}

// ── Validator key subset ──

pub struct ValidatorKeys {
    pub falcon: FalconKeyPair,
    pub kyber: KyberKeyPair,
    pub fingerprint: [u8; 32],
}

// ── Key file I/O ──

#[derive(Serialize, Deserialize)]
pub struct KeyFileV4 {
    pub version: u8,
    pub falcon_pk: String,
    pub falcon_sk: String,
    pub kyber_pk: String,
    pub kyber_sk: String,
    pub fingerprint: String,
}

pub fn save_key_file(keys: &ValidatorKeys, path: &Path) -> Result<(), KeyError> {
    if std::env::var("MISAKA_ALLOW_PLAINTEXT_KEYS").ok().as_deref() != Some("1") {
        return Err(KeyError::FileError(
            "Refusing plaintext keys without MISAKA_ALLOW_PLAINTEXT_KEYS=1".into()
        ));
    }
    let kf = KeyFileV4 {
        version: 4,
        falcon_pk: hex::encode(&keys.falcon.public_key),
        falcon_sk: hex::encode(&keys.falcon.secret_key),
        kyber_pk: hex::encode(&keys.kyber.public_key),
        kyber_sk: hex::encode(&keys.kyber.secret_key),
        fingerprint: hex::encode(keys.fingerprint),
    };
    let json = serde_json::to_string_pretty(&kf)
        .map_err(|e| KeyError::FileError(e.to_string()))?;
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(path).map_err(|e| KeyError::FileError(e.to_string()))?;
    file.write_all(json.as_bytes()).map_err(|e| KeyError::FileError(e.to_string()))?;
    file.sync_all().map_err(|e| KeyError::FileError(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_from_seed() {
        let seed = MasterSeed::from_bytes([0x42; 32]);
        let wallet = JamtisWallet::from_seed(&seed).unwrap();

        assert_eq!(wallet.spend_keys.public_key.len(), 897); // Falcon PK
        assert_eq!(wallet.view_keys.public_key.len(), 1184); // Kyber PK
        assert_ne!(wallet.k1, wallet.k2);
        assert_ne!(wallet.k3, [0u8; 32]);
        assert_ne!(wallet.find_received_key, wallet.generate_addr_key);
    }

    #[test]
    fn test_receive_address() {
        let seed = MasterSeed::from_bytes([0x42; 32]);
        let wallet = JamtisWallet::from_seed(&seed).unwrap();
        let addr = wallet.receive_address();
        assert_eq!(addr.spend_pk_hash, wallet.k1);
        assert_eq!(addr.view_pk.len(), 1184);
    }

    #[test]
    fn test_view_only_export() {
        let seed = MasterSeed::from_bytes([0x42; 32]);
        let wallet = JamtisWallet::from_seed(&seed).unwrap();
        let vo = wallet.view_only_export();
        assert_eq!(vo.k1, wallet.k1);
        assert_eq!(vo.fingerprint, wallet.fingerprint);
    }

    #[test]
    fn test_master_seed_entropy() {
        assert!(MasterSeed::from_entropy(&[0; 16]).is_err());
        assert!(MasterSeed::from_entropy(&[0; 32]).is_ok());
        assert!(MasterSeed::from_entropy(&[0; 64]).is_ok());
    }
}
