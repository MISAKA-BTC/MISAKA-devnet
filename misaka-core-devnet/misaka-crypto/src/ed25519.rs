use ed25519_compact::{KeyPair, PublicKey, SecretKey, Signature, Seed};
use zeroize::Zeroize;

pub const ED25519_PK_SIZE: usize = 32;
pub const ED25519_SK_SIZE: usize = 32;
pub const ED25519_SIG_SIZE: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum Ed25519Error {
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Signature verification failed")]
    VerifyFailed,
}

pub struct Ed25519KeyPair {
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) { self.secret_key.zeroize(); }
}

pub fn ed25519_keygen(seed_bytes: &[u8; 32]) -> Ed25519KeyPair {
    let seed = Seed::from_slice(seed_bytes).unwrap();
    let kp = KeyPair::from_seed(seed);
    let mut pk = [0u8; 32];
    let mut sk = [0u8; 32];
    pk.copy_from_slice(kp.pk.as_ref());
    sk.copy_from_slice(seed_bytes);
    Ed25519KeyPair { public_key: pk, secret_key: sk }
}

pub fn ed25519_sign(secret_key: &[u8; 32], message: &[u8]) -> Result<[u8; 64], Ed25519Error> {
    let seed = Seed::from_slice(secret_key).map_err(|_| Ed25519Error::InvalidSecretKey)?;
    let kp = KeyPair::from_seed(seed);
    let sig = kp.sk.sign(message, None);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    Ok(out)
}

pub fn ed25519_verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<bool, Ed25519Error> {
    let pk = PublicKey::from_slice(public_key).map_err(|_| Ed25519Error::InvalidPublicKey)?;
    let sig = Signature::from_slice(signature).map_err(|_| Ed25519Error::VerifyFailed)?;
    match pk.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ed25519_sign_verify() {
        let kp = ed25519_keygen(&[0x42; 32]);
        let msg = b"test message";
        let sig = ed25519_sign(&kp.secret_key, msg).unwrap();
        assert!(ed25519_verify(&kp.public_key, msg, &sig).unwrap());
        assert!(!ed25519_verify(&kp.public_key, b"wrong", &sig).unwrap());
    }
}
