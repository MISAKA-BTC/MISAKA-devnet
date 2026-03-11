// ============================================================
// MISAKA Network — SHAKE256-DRBG (SP 800-90A style)
// ============================================================
//
// WP §7.3: All randomness uses SHAKE256-DRBG.
// No AES-CTR-DRBG (Grover-vulnerable).
//
// State: (V: [u8;48], counter: u64, reseed_counter: u64)
// Generate: output = SHAKE256(DRBG || V || counter, len); counter += 1
// Reseed:   V = SHAKE256(DRBG || V || entropy, 48)
//
// NOTE: PQClean Falcon uses internal deterministic nonce derivation,
// so this DRBG is NOT used for Falcon signing. It IS used for:
//   - Ring member selection (decoy sampling)
//   - Blinding factor generation (Pedersen commitments)
//   - Ephemeral key entropy (Kyber KEM in stealth)
//   - Nonce generation (LaRRS ring signatures)
//
// The DRBG is NOT persisted across process restarts. Each node
// instantiates a fresh DRBG seeded from OS entropy at startup.
//
// ============================================================

use crate::hash::{Domain, domain_hash, domain_hash_multi};
use zeroize::Zeroize;

/// Maximum bytes per generate call (SP 800-90A limit).
const MAX_REQUEST_BYTES: usize = 65536;

/// Reseed interval (number of generate calls before mandatory reseed).
const RESEED_INTERVAL: u64 = 1 << 20; // ~1M calls

#[derive(Debug, thiserror::Error)]
pub enum DrbgError {
    #[error("Seed too short: need >= 32 bytes, got {0}")]
    SeedTooShort(usize),
    #[error("Request too large: max {MAX_REQUEST_BYTES} bytes")]
    RequestTooLarge,
    #[error("Reseed required")]
    ReseedRequired,
}

/// SHAKE256-DRBG instance.
///
/// Usage:
///   let mut drbg = Drbg::new(&os_entropy)?;
///   let random_bytes = drbg.generate(32)?;
///   let blinding = drbg.generate_u64()?;
pub struct Drbg {
    /// Internal state V (48 bytes — 384-bit security margin)
    v: [u8; 48],
    /// Monotonic counter (ensures unique output per call)
    counter: u64,
    /// Calls since last reseed
    reseed_counter: u64,
}

impl Drop for Drbg {
    fn drop(&mut self) {
        self.v.zeroize();
        self.counter = 0;
    }
}

impl Drbg {
    /// Instantiate from seed entropy (>= 32 bytes).
    pub fn new(seed: &[u8]) -> Result<Self, DrbgError> {
        if seed.len() < 32 {
            return Err(DrbgError::SeedTooShort(seed.len()));
        }
        let v_vec = domain_hash(Domain::Drbg, seed, 48);
        let mut v = [0u8; 48];
        v.copy_from_slice(&v_vec);
        Ok(Self { v, counter: 0, reseed_counter: 0 })
    }

    /// Generate `len` pseudorandom bytes.
    pub fn generate(&mut self, len: usize) -> Result<Vec<u8>, DrbgError> {
        if len > MAX_REQUEST_BYTES {
            return Err(DrbgError::RequestTooLarge);
        }
        if self.reseed_counter >= RESEED_INTERVAL {
            return Err(DrbgError::ReseedRequired);
        }

        let output = domain_hash_multi(
            Domain::Drbg,
            &[&self.v[..], &self.counter.to_le_bytes()],
            len,
        );

        // Update state
        let new_v = domain_hash_multi(
            Domain::Drbg,
            &[&self.v[..], &self.counter.to_le_bytes(), b"state_update"],
            48,
        );
        self.v.copy_from_slice(&new_v);
        self.counter += 1;
        self.reseed_counter += 1;

        Ok(output)
    }

    /// Generate a random u64.
    pub fn generate_u64(&mut self) -> Result<u64, DrbgError> {
        let bytes = self.generate(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Generate 32 random bytes.
    pub fn generate_32(&mut self) -> Result<[u8; 32], DrbgError> {
        let bytes = self.generate(32)?;
        Ok(bytes.try_into().unwrap())
    }

    /// Reseed with fresh entropy.
    pub fn reseed(&mut self, entropy: &[u8]) -> Result<(), DrbgError> {
        if entropy.len() < 32 {
            return Err(DrbgError::SeedTooShort(entropy.len()));
        }
        let new_v = domain_hash_multi(
            Domain::Drbg,
            &[&self.v[..], entropy],
            48,
        );
        self.v.copy_from_slice(&new_v);
        self.reseed_counter = 0;
        Ok(())
    }

    /// Current counter value (monotonic).
    pub fn counter(&self) -> u64 { self.counter }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drbg_deterministic() {
        let mut d1 = Drbg::new(b"same seed 32 bytes exactly!!!!!").unwrap();
        let mut d2 = Drbg::new(b"same seed 32 bytes exactly!!!!!").unwrap();
        assert_eq!(d1.generate(32).unwrap(), d2.generate(32).unwrap());
    }

    #[test]
    fn test_drbg_different_seeds() {
        let mut d1 = Drbg::new(&[0xAA; 32]).unwrap();
        let mut d2 = Drbg::new(&[0xBB; 32]).unwrap();
        assert_ne!(d1.generate(32).unwrap(), d2.generate(32).unwrap());
    }

    #[test]
    fn test_drbg_sequential_unique() {
        let mut d = Drbg::new(&[0x42; 32]).unwrap();
        let a = d.generate(32).unwrap();
        let b = d.generate(32).unwrap();
        assert_ne!(a, b, "Sequential calls must produce different output");
    }

    #[test]
    fn test_drbg_reseed() {
        let mut d = Drbg::new(&[0x42; 32]).unwrap();
        let before = d.generate(32).unwrap();
        d.reseed(&[0xFF; 32]).unwrap();
        let after = d.generate(32).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn test_drbg_short_seed_rejected() {
        assert!(Drbg::new(&[0; 16]).is_err());
    }
}
