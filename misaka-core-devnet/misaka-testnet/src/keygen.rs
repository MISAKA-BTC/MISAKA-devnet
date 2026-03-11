// ============================================================
// MISAKA Testnet — Validator Key Generation
// ============================================================

use crate::TestnetError;
use misaka_crypto::falcon::{falcon_keygen, FalconKeyPair};
use misaka_verify::ValidatorInfo;

/// Generated validator identity for testnet.
pub struct ValidatorIdentity {
    pub index: usize,
    pub keypair: FalconKeyPair,
    pub info: ValidatorInfo,
}

/// Generate `count` validator key pairs.
///
/// Each call to falcon_keygen() takes ~5ms, so 10 validators ≈ 50ms.
pub fn generate_validator_keys(count: usize) -> Result<Vec<ValidatorIdentity>, TestnetError> {
    let mut identities = Vec::with_capacity(count);
    for i in 0..count {
        let kp = falcon_keygen()
            .map_err(|e| TestnetError::KeygenError(format!("validator {}: {}", i, e)))?;
        let info = ValidatorInfo {
            fingerprint: kp.fingerprint,
            falcon_pk: kp.public_key.clone(),
        };
        identities.push(ValidatorIdentity { index: i, keypair: kp, info });
    }
    Ok(identities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_10_validators() {
        let keys = generate_validator_keys(10).unwrap();
        assert_eq!(keys.len(), 10);
        // All fingerprints unique
        let mut fps: Vec<_> = keys.iter().map(|k| k.keypair.fingerprint).collect();
        fps.sort();
        fps.dedup();
        assert_eq!(fps.len(), 10);
    }
}
