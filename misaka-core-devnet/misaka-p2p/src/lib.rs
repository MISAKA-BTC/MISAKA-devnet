// ============================================================
// MISAKA Network — Authenticated PQ Handshake
// ============================================================
//
// Fixed protocol (Noise-XX-like with Kyber-768 + Falcon-512):
//
//   → Initiator:
//     1. ek_i ← Kyber.KeyGen()
//     2. sig_i = Falcon.Sign(static_sk, "MISAKA-handshake-init" || ek_i.pk || fingerprint)
//     3. Send: [ek_i.pk(1184) | fingerprint(32) | sig_i(~690)]
//
//   ← Responder:
//     4. Verify sig_i with initiator's known static Falcon PK
//     5. (ct, ss1) = Kyber.Encaps(ek_i.pk)
//     6. sig_r = Falcon.Sign(static_sk, "MISAKA-handshake-resp" || ct || fingerprint)
//     7. session_key = SHAKE256(SESSION || ss1 || transcript_hash)
//     8. Send: [ct(1088) | fingerprint(32) | sig_r(~690)]
//
//   → Initiator:
//     9. Verify sig_r with responder's known static Falcon PK
//    10. ss1 = Kyber.Decaps(ek_i.sk, ct)
//    11. session_key = SHAKE256(SESSION || ss1 || transcript_hash)
//    12. Send encrypted STATUS
//
// AUDIT FIX: Removed unused responder ephemeral KEM keypair (ek_r).
// The previous version generated ek_r and included it in signatures
// but never used it for key agreement — wasting 1184 bytes of bandwidth.
//
// TODO(mainnet): Consider 3-message double-KEM protocol where
// initiator also encapsulates to responder's ephemeral key,
// providing bilateral forward secrecy against compromised static keys.
//
// ============================================================

use misaka_crypto::falcon;
use misaka_crypto::kyber;

use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("Falcon signature verification failed — possible MITM")]
    SignatureVerificationFailed,
    #[error("Unknown peer: fingerprint {0} not in validator set")]
    UnknownPeer(String),
    #[error("Kyber encaps failed: {0}")]
    KyberError(#[from] misaka_crypto::kyber::KyberError),
    #[error("Falcon error: {0}")]
    FalconError(#[from] misaka_crypto::falcon::FalconError),
    #[error("Handshake protocol error: {0}")]
    ProtocolError(String),
}

const DOMAIN_INIT: &[u8] = b"MISAKA-handshake-init-v2";
const DOMAIN_RESP: &[u8] = b"MISAKA-handshake-resp-v2";

/// Static identity of a peer (loaded from key file).
pub struct PeerIdentity {
    pub fingerprint: [u8; 32],
    pub falcon_pk: Vec<u8>,  // 897 bytes — for verifying their signatures
}

/// Our own static identity (with secret key for signing).
pub struct OwnIdentity {
    pub fingerprint: [u8; 32],
    pub falcon_pk: Vec<u8>,
    pub falcon_sk: Vec<u8>,
}

impl Drop for OwnIdentity {
    fn drop(&mut self) {
        self.falcon_sk.zeroize();
    }
}

/// Result of a successful handshake.
pub struct HandshakeResult {
    /// 32-byte session key for AES-256-GCM
    pub session_key: [u8; 32],
    /// Remote peer's fingerprint (verified via Falcon signature)
    pub remote_fingerprint: [u8; 32],
    /// Transcript hash (for channel binding)
    pub transcript_hash: [u8; 32],
}

impl Drop for HandshakeResult {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

// ── Initiator Side ──

/// Initiator message 1: ephemeral KEM PK + signed identity.
pub struct InitiatorHello {
    /// Ephemeral Kyber-768 public key (1184 bytes)
    pub ephemeral_pk: Vec<u8>,
    /// Our static fingerprint (32 bytes)
    pub fingerprint: [u8; 32],
    /// Falcon-512 signature over (DOMAIN_INIT || ephemeral_pk || fingerprint)
    pub signature: Vec<u8>,
    /// Ephemeral secret key (kept by initiator, not sent)
    ephemeral_sk: Vec<u8>,
}

impl Drop for InitiatorHello {
    fn drop(&mut self) {
        self.ephemeral_sk.zeroize();
    }
}

/// Create the initiator's hello message.
pub fn initiator_hello(own: &OwnIdentity) -> Result<InitiatorHello, HandshakeError> {
    let ek = kyber::kyber_keygen()?;

    let mut sign_data = Vec::with_capacity(DOMAIN_INIT.len() + ek.public_key.len() + 32);
    sign_data.extend_from_slice(DOMAIN_INIT);
    sign_data.extend_from_slice(&ek.public_key);
    sign_data.extend_from_slice(&own.fingerprint);

    let signature = falcon::falcon_sign(&own.falcon_sk, &sign_data)?;

    Ok(InitiatorHello {
        ephemeral_pk: ek.public_key.clone(),
        fingerprint: own.fingerprint,
        signature,
        ephemeral_sk: ek.secret_key.clone(),
    })
}

// ── Responder Side ──

/// Responder's reply: KEM ciphertext + signed identity.
///
/// AUDIT FIX: Removed unused ephemeral_pk field. The previous version
/// generated a responder ephemeral KEM keypair but never used it for
/// key agreement — only ss1 (from initiator's ephemeral key) was used.
pub struct ResponderReply {
    /// KEM ciphertext encapsulated to initiator's ephemeral PK (1088 bytes)
    pub ciphertext: Vec<u8>,
    /// Responder's static fingerprint (32 bytes)
    pub fingerprint: [u8; 32],
    /// Falcon-512 signature over (DOMAIN_RESP || ct || fingerprint)
    pub signature: Vec<u8>,
    /// The session key (kept by responder)
    session_key: [u8; 32],
}

impl Drop for ResponderReply {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

/// Process initiator's hello and generate responder's reply.
pub fn responder_reply(
    own: &OwnIdentity,
    hello: &InitiatorHello,
    known_peers: &[PeerIdentity],
) -> Result<(ResponderReply, HandshakeResult), HandshakeError> {
    // 1. Find the initiator's static Falcon PK from known peers
    let initiator_id = known_peers
        .iter()
        .find(|p| p.fingerprint == hello.fingerprint)
        .ok_or_else(|| HandshakeError::UnknownPeer(hex::encode(hello.fingerprint)))?;

    // 2. Verify the initiator's signature (prevents MITM)
    let mut verify_data = Vec::with_capacity(DOMAIN_INIT.len() + hello.ephemeral_pk.len() + 32);
    verify_data.extend_from_slice(DOMAIN_INIT);
    verify_data.extend_from_slice(&hello.ephemeral_pk);
    verify_data.extend_from_slice(&hello.fingerprint);

    let valid = falcon::falcon_verify(&initiator_id.falcon_pk, &verify_data, &hello.signature)?;
    if !valid {
        return Err(HandshakeError::SignatureVerificationFailed);
    }

    // 3. Encapsulate shared secret to initiator's ephemeral PK
    let (ct, ss1) = kyber::kyber_encaps(&hello.ephemeral_pk)?;

    // 4. Sign our reply (ct + fingerprint, no unused ek_r)
    let mut sign_data = Vec::with_capacity(DOMAIN_RESP.len() + ct.len() + 32);
    sign_data.extend_from_slice(DOMAIN_RESP);
    sign_data.extend_from_slice(&ct);
    sign_data.extend_from_slice(&own.fingerprint);

    let signature = falcon::falcon_sign(&own.falcon_sk, &sign_data)?;

    // 5. Compute transcript hash (binds all messages)
    let transcript_hash = compute_transcript_hash(
        &hello.ephemeral_pk,
        &hello.fingerprint,
        &hello.signature,
        &ct,
        &own.fingerprint,
        &signature,
    );

    // 6. Derive session key
    let session_key = derive_session_key(&ss1, &transcript_hash);

    let result = HandshakeResult {
        session_key,
        remote_fingerprint: hello.fingerprint,
        transcript_hash,
    };

    let reply = ResponderReply {
        ciphertext: ct,
        fingerprint: own.fingerprint,
        signature,
        session_key,
    };

    Ok((reply, result))
}

// ── Initiator Completion ──

/// Complete the handshake on the initiator side.
pub fn initiator_complete(
    hello: &InitiatorHello,
    reply: &ResponderReply,
    known_peers: &[PeerIdentity],
) -> Result<HandshakeResult, HandshakeError> {
    // 1. Find the responder's static Falcon PK
    let responder_id = known_peers
        .iter()
        .find(|p| p.fingerprint == reply.fingerprint)
        .ok_or_else(|| HandshakeError::UnknownPeer(hex::encode(reply.fingerprint)))?;

    // 2. Verify the responder's signature
    let mut verify_data = Vec::with_capacity(
        DOMAIN_RESP.len() + reply.ciphertext.len() + 32
    );
    verify_data.extend_from_slice(DOMAIN_RESP);
    verify_data.extend_from_slice(&reply.ciphertext);
    verify_data.extend_from_slice(&reply.fingerprint);

    let valid = falcon::falcon_verify(&responder_id.falcon_pk, &verify_data, &reply.signature)?;
    if !valid {
        return Err(HandshakeError::SignatureVerificationFailed);
    }

    // 3. Decapsulate shared secret
    let ss1 = kyber::kyber_decaps(&hello.ephemeral_sk, &reply.ciphertext)?;

    // 4. Compute transcript hash
    let transcript_hash = compute_transcript_hash(
        &hello.ephemeral_pk,
        &hello.fingerprint,
        &hello.signature,
        &reply.ciphertext,
        &reply.fingerprint,
        &reply.signature,
    );

    // 5. Derive session key
    let session_key = derive_session_key(&ss1, &transcript_hash);

    Ok(HandshakeResult {
        session_key,
        remote_fingerprint: reply.fingerprint,
        transcript_hash,
    })
}

// ── Helpers ──

fn compute_transcript_hash(
    init_ek: &[u8],
    init_fp: &[u8],
    init_sig: &[u8],
    resp_ct: &[u8],
    resp_fp: &[u8],
    resp_sig: &[u8],
) -> [u8; 32] {
    misaka_crypto::hash::domain_hash_multi(
        misaka_crypto::hash::Domain::Handshake,
        &[init_ek, init_fp, init_sig, resp_ct, resp_fp, resp_sig],
        32,
    ).try_into().unwrap()
}

fn derive_session_key(shared_secret: &[u8], transcript_hash: &[u8]) -> [u8; 32] {
    misaka_crypto::hash::domain_hash_multi(
        misaka_crypto::hash::Domain::Session,
        &[shared_secret, transcript_hash],
        32,
    ).try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::falcon;

    fn make_identity() -> (OwnIdentity, PeerIdentity) {
        let kp = falcon::falcon_keygen().unwrap();
        let own = OwnIdentity {
            fingerprint: kp.fingerprint,
            falcon_pk: kp.public_key.clone(),
            falcon_sk: kp.secret_key.clone(),
        };
        let peer = PeerIdentity {
            fingerprint: kp.fingerprint,
            falcon_pk: kp.public_key.clone(),
        };
        (own, peer)
    }

    #[test]
    fn test_authenticated_handshake() {
        let (alice_own, alice_peer) = make_identity();
        let (bob_own, bob_peer) = make_identity();

        let hello = initiator_hello(&alice_own).unwrap();

        let (reply, bob_result) = responder_reply(
            &bob_own,
            &hello,
            &[alice_peer],
        ).unwrap();

        let alice_result = initiator_complete(
            &hello,
            &reply,
            &[bob_peer],
        ).unwrap();

        assert_eq!(
            alice_result.session_key, bob_result.session_key,
            "Session keys must match"
        );
        assert_eq!(
            alice_result.transcript_hash, bob_result.transcript_hash,
            "Transcript hashes must match"
        );
    }

    #[test]
    fn test_mitm_rejected() {
        let (alice_own, alice_peer) = make_identity();
        let (_bob_own, bob_peer) = make_identity();
        let (eve_own, _eve_peer) = make_identity();

        let hello = initiator_hello(&alice_own).unwrap();

        // Eve tries to respond as Bob
        let result = responder_reply(
            &eve_own,
            &hello,
            &[alice_peer],
        );

        if let Ok((eve_reply, _)) = result {
            let verify_result = initiator_complete(
                &hello,
                &eve_reply,
                &[bob_peer], // Alice only trusts Bob
            );
            assert!(
                verify_result.is_err(),
                "MITM handshake must be rejected"
            );
        }
    }
}
