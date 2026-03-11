// ============================================================
// MISAKA Network — Address Design (Bech32)
// ============================================================
//
// AUDIT FIX #10: Falcon-512 PK is 897 bytes — too large for
// direct use as an address. Solution:
//
//   address = Bech32(hrp, SHAKE256("MISAKA_ADDR" || pk_commitment, 20))
//
// Format:
//   misaka1<bech32-encoded-20-bytes>
//
// Properties:
//   - Human-readable prefix: "misaka" (mainnet), "tmsaka" (testnet)
//   - 32-byte payload (256-bit security, full SHAKE256 output)
//   - Bech32 error detection (BCH code, detects up to 4 errors)
//   - ~38 characters total (compact, QR-friendly)
//   - Derived from structured PK commitment (includes algo ID)
//
// Examples:
//   misaka1qw508d6qejxtdg4y5r3zarvaryvg6gdgs
//   tmsaka1qw508d6qejxtdg4y5r3zarvaryvg6gdgs
//
// ============================================================

use crate::hash::{Domain, domain_hash};
use crate::pk_commit::PkCommitment;

/// Human-readable prefix for mainnet
pub const HRP_MAINNET: &str = "misaka";
/// Human-readable prefix for testnet
pub const HRP_TESTNET: &str = "tmsaka";

/// Address payload size: 32 bytes (256-bit)
pub const ADDRESS_PAYLOAD_SIZE: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("Invalid Bech32 encoding: {0}")]
    InvalidBech32(String),
    #[error("Invalid address payload size: expected {ADDRESS_PAYLOAD_SIZE}, got {0}")]
    InvalidPayloadSize(usize),
    #[error("Unknown network prefix: {0}")]
    UnknownPrefix(String),
}

/// A MISAKA network address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Human-readable prefix ("misaka" or "tmsaka")
    pub hrp: String,
    /// 32-byte address payload
    pub payload: [u8; ADDRESS_PAYLOAD_SIZE],
}

impl Address {
    /// Derive an address from a PK commitment.
    ///
    /// payload = SHAKE256("MISAKA_ADDR" || commitment_bytes, 20)
    pub fn from_commitment(commitment: &PkCommitment, testnet: bool) -> Self {
        let payload_vec = domain_hash(Domain::Address, &commitment.bytes, ADDRESS_PAYLOAD_SIZE);
        let mut payload = [0u8; ADDRESS_PAYLOAD_SIZE];
        payload.copy_from_slice(&payload_vec);

        Self {
            hrp: if testnet { HRP_TESTNET } else { HRP_MAINNET }.into(),
            payload,
        }
    }

    /// Encode as Bech32 string.
    ///
    /// Format: {hrp}1{bech32-data}{checksum}
    pub fn to_bech32(&self) -> String {
        let data = convert_bits_8_to_5(&self.payload);
        let checksum = create_checksum(&self.hrp, &data);
        let mut result = self.hrp.clone();
        result.push('1'); // separator
        for &b in data.iter().chain(checksum.iter()) {
            result.push(BECH32_CHARSET[b as usize]);
        }
        result
    }

    /// Decode from Bech32 string.
    pub fn from_bech32(s: &str) -> Result<Self, AddressError> {
        let s_lower = s.to_lowercase();

        // Find separator
        let sep_pos = s_lower.rfind('1')
            .ok_or_else(|| AddressError::InvalidBech32("no separator '1'".into()))?;

        let hrp = &s_lower[..sep_pos];
        let data_part = &s_lower[sep_pos + 1..];

        // Validate HRP
        if hrp != HRP_MAINNET && hrp != HRP_TESTNET {
            return Err(AddressError::UnknownPrefix(hrp.into()));
        }

        // Decode base32
        let mut values = Vec::with_capacity(data_part.len());
        for c in data_part.chars() {
            let idx = BECH32_CHARSET.iter().position(|&x| x == c)
                .ok_or_else(|| AddressError::InvalidBech32(format!("invalid char '{c}'")))?;
            values.push(idx as u8);
        }

        // Verify checksum (last 6 values)
        if values.len() < 6 {
            return Err(AddressError::InvalidBech32("too short".into()));
        }
        if !verify_checksum(hrp, &values) {
            return Err(AddressError::InvalidBech32("checksum failed".into()));
        }

        // Extract payload (exclude checksum)
        let data_5bit = &values[..values.len() - 6];
        let payload_vec = convert_bits_5_to_8(data_5bit)
            .map_err(|e| AddressError::InvalidBech32(e))?;

        if payload_vec.len() != ADDRESS_PAYLOAD_SIZE {
            return Err(AddressError::InvalidPayloadSize(payload_vec.len()));
        }

        let mut payload = [0u8; ADDRESS_PAYLOAD_SIZE];
        payload.copy_from_slice(&payload_vec);

        Ok(Self { hrp: hrp.into(), payload })
    }

    /// Check if this is a testnet address.
    pub fn is_testnet(&self) -> bool {
        self.hrp == HRP_TESTNET
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

// ── Bech32 Encoding (BIP 173) ──

const BECH32_CHARSET: [char; 32] = [
    'q','p','z','r','y','9','x','8',
    'g','f','2','t','v','d','w','0',
    's','3','j','n','5','4','k','h',
    'c','e','6','m','u','a','7','l',
];

fn polymod(values: &[u8]) -> u32 {
    let gen: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for i in 0..5 {
            if (top >> i) & 1 == 1 {
                chk ^= gen[i];
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.chars() {
        result.push((c as u8) >> 5);
    }
    result.push(0);
    for c in hrp.chars() {
        result.push((c as u8) & 31);
    }
    result
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let polymod_val = polymod(&values) ^ 1;
    let mut checksum = [0u8; 6];
    for i in 0..6 {
        checksum[i] = ((polymod_val >> (5 * (5 - i))) & 31) as u8;
    }
    checksum
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == 1
}

fn convert_bits_8_to_5(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        acc = (acc << 8) | (byte as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        result.push(((acc << (5 - bits)) & 31) as u8);
    }
    result
}

fn convert_bits_5_to_8(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &val in data {
        if val > 31 {
            return Err(format!("invalid 5-bit value: {val}"));
        }
        acc = (acc << 5) | (val as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            result.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    // Reject invalid padding (BIP 173 strict mode):
    //   - Padding must be less than 5 bits
    //   - All padding bits must be zero
    if bits >= 5 {
        return Err("non-zero padding of 5+ bits".into());
    }
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err("non-zero padding bits".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pk_commit::{falcon_pk_commitment, kyber_pk_commitment, compute_multi_key_commitment};

    #[test]
    fn test_address_from_falcon_pk() {
        let fake_pk = [0x42u8; 897]; // 897-byte Falcon PK
        let commitment = falcon_pk_commitment(&fake_pk);
        let addr = Address::from_commitment(&commitment, false);

        let bech32 = addr.to_bech32();
        assert!(bech32.starts_with("misaka1"), "Mainnet address must start with misaka1");
        println!("Address: {bech32}");

        // Roundtrip
        let decoded = Address::from_bech32(&bech32).unwrap();
        assert_eq!(addr.payload, decoded.payload);
    }

    #[test]
    fn test_testnet_address() {
        let fake_pk = [0x42u8; 897];
        let commitment = falcon_pk_commitment(&fake_pk);
        let addr = Address::from_commitment(&commitment, true);

        let bech32 = addr.to_bech32();
        assert!(bech32.starts_with("tmsaka1"), "Testnet address must start with tmsaka1");
        assert!(addr.is_testnet());
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let pk1 = [0xAAu8; 897];
        let pk2 = [0xBBu8; 897];
        let c1 = falcon_pk_commitment(&pk1);
        let c2 = falcon_pk_commitment(&pk2);
        let a1 = Address::from_commitment(&c1, false);
        let a2 = Address::from_commitment(&c2, false);
        assert_ne!(a1.payload, a2.payload);
    }

    #[test]
    fn test_multi_key_address() {
        // Jamtis-style: address from Falcon + Kyber commitment root
        let falcon_c = falcon_pk_commitment(&[0xAA; 897]);
        let kyber_c = kyber_pk_commitment(&[0xBB; 1184]);
        let root = compute_multi_key_commitment(&[falcon_c.clone(), kyber_c]);

        // Create a "virtual" commitment from the Merkle root
        let multi_commit = crate::pk_commit::PkCommitment {
            bytes: root,
            algorithm: crate::pk_commit::KeyAlgorithm::Falcon512, // primary
        };
        let addr = Address::from_commitment(&multi_commit, false);
        let bech32 = addr.to_bech32();
        println!("Multi-key address: {bech32}");
        assert!(bech32.starts_with("misaka1"));
    }

    #[test]
    fn test_bech32_error_detection() {
        let fake_pk = [0x42u8; 897];
        let commitment = falcon_pk_commitment(&fake_pk);
        let addr = Address::from_commitment(&commitment, false);
        let mut bech32 = addr.to_bech32();

        // Tamper with one character
        let chars: Vec<char> = bech32.chars().collect();
        let mut tampered: Vec<char> = chars.clone();
        let idx = tampered.len() - 3;
        tampered[idx] = if tampered[idx] == 'q' { 'p' } else { 'q' };
        let tampered_str: String = tampered.into_iter().collect();

        let result = Address::from_bech32(&tampered_str);
        assert!(result.is_err(), "Tampered Bech32 must fail checksum");
    }
}
