// ============================================================
// MISAKA Network — Integration Tests
// ============================================================
//
// Tests cover:
//   1. 10-validator BFT consensus round (minimum set)
//   2. 30-validator BFT consensus round (maximum set)
//   3. Duplicate vote detection
//   4. Future timestamp rejection
//   5. State consistency across round advancement
//   6. Proposer rotation correctness
//   7. Fee collect → redistribute → invariant
//   8. P2P handshake end-to-end
//   9. Crypto roundtrips (Falcon, Kyber, Hybrid)
//  10. Quorum edge cases
//
// NOTE: Falcon keygen is ~5ms per key. Tests with 30 validators
// take ~150ms for setup. This is acceptable for CI.
//
// ============================================================

use misaka_crypto::falcon;
use misaka_consensus::*;
use misaka_verify::{ValidatorInfo, BlockHeaderRef, self};
use misaka_admin::{Ledger, AdminConfig, ValidatorEntry, ONE_STMISAKA, sign_admin_op};

// ── Helpers ──

/// Generate N validator keypairs and ValidatorInfo structs.
fn gen_validators(n: usize) -> Vec<(falcon::FalconKeyPair, ValidatorInfo)> {
    (0..n).map(|_| {
        let kp = falcon::falcon_keygen().unwrap();
        let info = ValidatorInfo {
            fingerprint: kp.fingerprint,
            falcon_pk: kp.public_key.clone(),
        };
        (kp, info)
    }).collect()
}

/// Create a ValidatorSet from validator infos.
fn make_validator_set(vals: &[(falcon::FalconKeyPair, ValidatorInfo)]) -> ValidatorSet {
    let infos: Vec<ValidatorInfo> = vals.iter().map(|(_, info)| ValidatorInfo {
        fingerprint: info.fingerprint,
        falcon_pk: info.falcon_pk.clone(),
    }).collect();
    ValidatorSet::new(infos).unwrap()
}

/// Find the keypair for a given fingerprint.
fn find_kp<'a>(vals: &'a [(falcon::FalconKeyPair, ValidatorInfo)], fp: &[u8; 32]) -> &'a falcon::FalconKeyPair {
    vals.iter().find(|(_, info)| &info.fingerprint == fp).map(|(kp, _)| kp).unwrap()
}

// ════════════════════════════════════════════
// Test 1: 10-validator BFT consensus round
// ════════════════════════════════════════════

#[test]
fn test_10_validator_consensus_round() {
    let vals = gen_validators(10);
    let vs = make_validator_set(&vals);

    assert_eq!(vs.len(), 10);
    assert_eq!(vs.quorum(), 7); // ⌊2×10/3⌋ + 1 = 7

    let height = 1u64;
    let round = 0u32;
    let block_hash = [0xABu8; 32];

    let mut state = RoundState::new(height);

    // Get proposer
    let proposer = vs.get_proposer(height, round);
    state.proposal_hash = Some(block_hash);

    // All 10 validators prevote for the block
    for (kp, info) in &vals {
        let vote = create_signed_vote(
            VoteType::Prevote, height, round,
            Some(block_hash), info.fingerprint, &kp.secret_key,
        ).unwrap();
        state.insert_prevote(vote, &vs).unwrap();
    }

    // Check quorum
    let prevote_result = check_prevote_quorum(&state, &vs);
    assert_eq!(prevote_result, Some(Some(block_hash)));

    // All 10 validators precommit
    for (kp, info) in &vals {
        let vote = create_signed_vote(
            VoteType::Precommit, height, round,
            Some(block_hash), info.fingerprint, &kp.secret_key,
        ).unwrap();
        state.insert_precommit(vote, &vs).unwrap();
    }

    let precommit_result = check_precommit_quorum(&state, &vs);
    assert_eq!(precommit_result, Some(Some(block_hash)));

    // Collect BFT signatures
    let bft_sigs = collect_bft_signatures(&state, &block_hash);
    assert_eq!(bft_sigs.len(), 10);
}

// ════════════════════════════════════════════
// Test 2: 30-validator BFT consensus round
// ════════════════════════════════════════════

#[test]
fn test_30_validator_consensus_round() {
    let vals = gen_validators(30);
    let vs = make_validator_set(&vals);

    assert_eq!(vs.len(), 30);
    assert_eq!(vs.quorum(), 21); // ⌊2×30/3⌋ + 1 = 21

    let height = 42u64;
    let round = 0u32;
    let block_hash = [0xCDu8; 32];

    let mut state = RoundState::new(height);

    // Only 21 validators (quorum) prevote
    for (kp, info) in vals.iter().take(21) {
        let vote = create_signed_vote(
            VoteType::Prevote, height, round,
            Some(block_hash), info.fingerprint, &kp.secret_key,
        ).unwrap();
        state.insert_prevote(vote, &vs).unwrap();
    }

    assert_eq!(check_prevote_quorum(&state, &vs), Some(Some(block_hash)));

    // Only 21 validators precommit
    for (kp, info) in vals.iter().take(21) {
        let vote = create_signed_vote(
            VoteType::Precommit, height, round,
            Some(block_hash), info.fingerprint, &kp.secret_key,
        ).unwrap();
        state.insert_precommit(vote, &vs).unwrap();
    }

    assert_eq!(check_precommit_quorum(&state, &vs), Some(Some(block_hash)));
}

// ════════════════════════════════════════════
// Test 3: Quorum NOT met with N/3 votes
// ════════════════════════════════════════════

#[test]
fn test_insufficient_quorum() {
    let vals = gen_validators(10);
    let vs = make_validator_set(&vals);

    let mut state = RoundState::new(1);
    let block_hash = [0x11u8; 32];

    // Only 3 validators prevote (< quorum=7)
    for (kp, info) in vals.iter().take(3) {
        let vote = create_signed_vote(
            VoteType::Prevote, 1, 0,
            Some(block_hash), info.fingerprint, &kp.secret_key,
        ).unwrap();
        state.insert_prevote(vote, &vs).unwrap();
    }

    assert_eq!(check_prevote_quorum(&state, &vs), None);
}

// ════════════════════════════════════════════
// Test 4: Duplicate vote (same voter twice)
// ════════════════════════════════════════════

#[test]
fn test_duplicate_vote_replaced() {
    let vals = gen_validators(10);
    let vs = make_validator_set(&vals);

    let mut state = RoundState::new(1);
    let (kp, info) = &vals[0];

    // Vote for block A
    let vote_a = create_signed_vote(
        VoteType::Prevote, 1, 0,
        Some([0xAAu8; 32]), info.fingerprint, &kp.secret_key,
    ).unwrap();
    state.insert_prevote(vote_a, &vs).unwrap();

    // Same voter votes for block B (equivocation — HashMap replaces)
    let vote_b = create_signed_vote(
        VoteType::Prevote, 1, 0,
        Some([0xBBu8; 32]), info.fingerprint, &kp.secret_key,
    ).unwrap();
    state.insert_prevote(vote_b, &vs).unwrap();

    // Only 1 vote in the map (replaced, not duplicated)
    assert_eq!(state.prevotes.len(), 1);
    // The vote should be for block B (latest)
    assert_eq!(state.prevotes[&info.fingerprint].block_hash, Some([0xBBu8; 32]));
}

// ════════════════════════════════════════════
// Test 5: Future timestamp rejection
// ════════════════════════════════════════════

#[test]
fn test_future_timestamp_rejected() {
    let vals = gen_validators(10);
    let vs = make_validator_set(&vals);
    let proposer = vs.get_proposer(1, 0);
    let proposer_kp = find_kp(&vals, &proposer.fingerprint);

    // Build a block header with timestamp far in the future
    let now = 1_700_000_000u64;
    let future_ts = now + 3600; // 1 hour ahead

    let prev_hash = [0u8; 32];
    let merkle = [0u8; 32];
    let utxo_root = [0u8; 32];
    let link_root = [0u8; 32];

    let header = BlockHeaderRef {
        version: 2,
        height: 1,
        round: 0,
        prev_hash: &prev_hash,
        timestamp: future_ts,
        tx_merkle_root: &merkle,
        utxo_root: &utxo_root,
        link_tag_root: &link_root,
        proposer_id: &proposer.fingerprint,
        proposer_sig: &[0u8; 0], // dummy — will fail before sig check
        bft_sigs: Vec::new(),
    };

    let infos: Vec<ValidatorInfo> = vals.iter().map(|(_, info)| ValidatorInfo {
        fingerprint: info.fingerprint,
        falcon_pk: info.falcon_pk.clone(),
    }).collect();

    let result = misaka_verify::verify_block_header(
        &header, &infos, &prev_hash, 1,
        &proposer.fingerprint, Some(now - 60), now,
    );

    match result {
        Err(misaka_verify::VerifyError::FutureTimestamp { .. }) => { /* expected */ }
        other => panic!("Expected FutureTimestamp, got {:?}", other),
    }
}

// ════════════════════════════════════════════
// Test 6: State consistency across round advancement
// ════════════════════════════════════════════

#[test]
fn test_round_advancement_preserves_lock() {
    let vals = gen_validators(10);
    let vs = make_validator_set(&vals);

    let mut state = RoundState::new(1);
    let block_hash = [0xFFu8; 32];

    // Simulate: 7 prevotes for block → lock
    for (kp, info) in vals.iter().take(7) {
        let vote = create_signed_vote(
            VoteType::Prevote, 1, 0,
            Some(block_hash), info.fingerprint, &kp.secret_key,
        ).unwrap();
        state.insert_prevote(vote, &vs).unwrap();
    }

    // Quorum reached → set lock
    assert!(check_prevote_quorum(&state, &vs).is_some());
    state.set_lock(block_hash, 0);

    // Advance round (e.g., precommit timeout)
    state.advance_round();
    assert_eq!(state.round, 1);
    assert_eq!(state.prevotes.len(), 0); // cleared
    assert_eq!(state.precommits.len(), 0); // cleared

    // Lock MUST persist across rounds
    assert_eq!(state.locked_hash, Some(block_hash));
    assert_eq!(state.locked_round, Some(0));

    // Lock enforcement: can prevote for locked block
    assert!(state.is_valid_prevote(Some(block_hash), None));

    // Lock enforcement: cannot prevote for different block without POL
    assert!(!state.is_valid_prevote(Some([0xEEu8; 32]), None));

    // Lock enforcement: CAN prevote for different block with POL at higher round
    assert!(state.is_valid_prevote(Some([0xEEu8; 32]), Some(1)));

    // Nil prevote always allowed
    assert!(state.is_valid_prevote(None, None));
}

// ════════════════════════════════════════════
// Test 7: Nil precommit → round advancement
// ════════════════════════════════════════════

#[test]
fn test_nil_precommit_enables_round_advance() {
    let vals = gen_validators(10);
    let vs = make_validator_set(&vals);

    let mut state = RoundState::new(1);

    // All 10 validators nil-precommit (timeout)
    for (kp, info) in &vals {
        let vote = create_signed_vote(
            VoteType::Precommit, 1, 0,
            None, // nil
            info.fingerprint, &kp.secret_key,
        ).unwrap();
        state.insert_precommit(vote, &vs).unwrap();
    }

    // Nil quorum reached
    let result = check_precommit_quorum(&state, &vs);
    assert_eq!(result, Some(None), "Nil precommit quorum must be detected");
}

// ════════════════════════════════════════════
// Test 8: Proposer rotation is deterministic
// ════════════════════════════════════════════

#[test]
fn test_proposer_rotation_deterministic() {
    let vals = gen_validators(10);
    let vs = make_validator_set(&vals);

    // Same (height, round) always yields same proposer
    let p1 = vs.get_proposer(42, 0);
    let p2 = vs.get_proposer(42, 0);
    assert_eq!(p1.fingerprint, p2.fingerprint);

    // Different heights yield different proposers (usually)
    let mut proposers = std::collections::HashSet::new();
    for h in 0..10u64 {
        proposers.insert(vs.get_proposer(h, 0).fingerprint);
    }
    assert!(proposers.len() > 1, "Rotation must cycle through validators");

    // Round increment rotates proposer
    let p_r0 = vs.get_proposer(0, 0);
    let p_r1 = vs.get_proposer(0, 1);
    assert_ne!(p_r0.fingerprint, p_r1.fingerprint);
}

// ════════════════════════════════════════════
// Test 9: Fee collect → redistribute → invariant
// ════════════════════════════════════════════

#[test]
fn test_full_fee_lifecycle() {
    let admin_kp = falcon::falcon_keygen().unwrap();
    let cfg = AdminConfig {
        fingerprint: admin_kp.fingerprint,
        falcon_pk: admin_kp.public_key.clone(),
    };
    let mut ledger = Ledger::new(cfg, 10_000_000 * ONE_STMISAKA, true);

    // Register validators
    let v1 = [0x01; 32]; let v2 = [0x02; 32]; let a1 = [0xA1; 32];
    ledger.register_validator(ValidatorEntry { fingerprint: v1, stake: 60_000 * ONE_STMISAKA, is_archive: false });
    ledger.register_validator(ValidatorEntry { fingerprint: v2, stake: 40_000 * ONE_STMISAKA, is_archive: false });
    ledger.register_validator(ValidatorEntry { fingerprint: a1, stake: 0, is_archive: true });

    // Fund a user
    let user = [0xEE; 32];
    let fund_amount = 100_000 * ONE_STMISAKA;
    let hash = ledger.op_hash("distribute", &format!("to={} amount={}", hex::encode(user), fund_amount));
    let sig = sign_admin_op(&admin_kp.secret_key, &hash).unwrap();
    ledger.admin_distribute(&user, fund_amount, &sig).unwrap();

    let supply_before = ledger.total_supply();

    // Simulate 10 blocks of fee collection and redistribution
    for _ in 0..10 {
        let fee = 500 * ONE_STMISAKA;
        ledger.collect_fee(&user, fee).unwrap();
        ledger.distribute_block_fees(fee, &v1).unwrap();
    }

    // Supply must NOT have changed
    assert_eq!(ledger.total_supply(), supply_before);
    assert!(ledger.verify_invariant());

    // User lost 5000 stMISAKA in fees
    assert_eq!(ledger.balance_of(&user), fund_amount - 5_000 * ONE_STMISAKA);

    // Validators and archive received rewards
    assert!(ledger.balance_of(&v1) > 0);
    assert!(ledger.balance_of(&v2) > 0);
    assert!(ledger.balance_of(&a1) > 0);
}

// ════════════════════════════════════════════
// Test 10: P2P handshake end-to-end
// ════════════════════════════════════════════

#[test]
fn test_p2p_handshake_e2e() {
    use misaka_p2p::*;

    let alice_kp = falcon::falcon_keygen().unwrap();
    let bob_kp = falcon::falcon_keygen().unwrap();

    let alice_own = OwnIdentity {
        fingerprint: alice_kp.fingerprint,
        falcon_pk: alice_kp.public_key.clone(),
        falcon_sk: alice_kp.secret_key.clone(),
    };
    let alice_peer = PeerIdentity {
        fingerprint: alice_kp.fingerprint,
        falcon_pk: alice_kp.public_key.clone(),
    };
    let bob_own = OwnIdentity {
        fingerprint: bob_kp.fingerprint,
        falcon_pk: bob_kp.public_key.clone(),
        falcon_sk: bob_kp.secret_key.clone(),
    };
    let bob_peer = PeerIdentity {
        fingerprint: bob_kp.fingerprint,
        falcon_pk: bob_kp.public_key.clone(),
    };

    // Full handshake
    let hello = initiator_hello(&alice_own).unwrap();
    let (reply, bob_result) = responder_reply(&bob_own, &hello, &[alice_peer]).unwrap();
    let alice_result = initiator_complete(&hello, &reply, &[bob_peer]).unwrap();

    assert_eq!(alice_result.session_key, bob_result.session_key);
    assert_eq!(alice_result.transcript_hash, bob_result.transcript_hash);
    assert_eq!(alice_result.remote_fingerprint, bob_kp.fingerprint);
    assert_eq!(bob_result.remote_fingerprint, alice_kp.fingerprint);
}

// ════════════════════════════════════════════
// Test 11: Crypto roundtrip (Falcon + Kyber + Hybrid)
// ════════════════════════════════════════════

#[test]
fn test_crypto_roundtrip_all() {
    // Falcon
    let fkp = falcon::falcon_keygen().unwrap();
    let msg = b"integration test message";
    let sig = falcon::falcon_sign(&fkp.secret_key, msg).unwrap();
    assert!(falcon::falcon_verify(&fkp.public_key, msg, &sig).unwrap());

    // Kyber
    let kkp = misaka_crypto::kyber::kyber_keygen().unwrap();
    let (ct, ss_enc) = misaka_crypto::kyber::kyber_encaps(&kkp.public_key).unwrap();
    let ss_dec = misaka_crypto::kyber::kyber_decaps(&kkp.secret_key, &ct).unwrap();
    assert_eq!(ss_enc, ss_dec);

    // Hybrid (Falcon + Dilithium)
    let hkp = misaka_crypto::hybrid_sig::hybrid_keygen().unwrap();
    let hsig = misaka_crypto::hybrid_sig::hybrid_sign(
        &hkp.falcon.secret_key, &hkp.dilithium.secret_key, msg,
    ).unwrap();
    assert!(misaka_crypto::hybrid_sig::hybrid_verify(
        &hkp.falcon.public_key, &hkp.dilithium.public_key, msg, &hsig,
    ).unwrap());
}

// ════════════════════════════════════════════
// Test 12: Wrong height/round vote rejected
// ════════════════════════════════════════════

#[test]
fn test_wrong_height_vote_rejected() {
    let vals = gen_validators(10);
    let vs = make_validator_set(&vals);

    let mut state = RoundState::new(5); // height=5, round=0
    let (kp, info) = &vals[0];

    // Vote at wrong height
    let vote = create_signed_vote(
        VoteType::Prevote, 999, 0,
        Some([0xAA; 32]), info.fingerprint, &kp.secret_key,
    ).unwrap();
    let result = state.insert_prevote(vote, &vs);
    assert!(result.is_err());
}

#[test]
fn test_wrong_round_vote_rejected() {
    let vals = gen_validators(10);
    let vs = make_validator_set(&vals);

    let mut state = RoundState::new(1); // round=0
    let (kp, info) = &vals[0];

    let vote = create_signed_vote(
        VoteType::Prevote, 1, 5, // wrong round
        Some([0xAA; 32]), info.fingerprint, &kp.secret_key,
    ).unwrap();
    let result = state.insert_prevote(vote, &vs);
    assert!(result.is_err());
}

// ════════════════════════════════════════════
// Test 13: Validator set size boundaries
// ════════════════════════════════════════════

#[test]
fn test_validator_set_too_small() {
    let vals = gen_validators(9); // < MIN_VALIDATORS (10)
    let infos: Vec<ValidatorInfo> = vals.iter().map(|(_, info)| ValidatorInfo {
        fingerprint: info.fingerprint,
        falcon_pk: info.falcon_pk.clone(),
    }).collect();
    let result = ValidatorSet::new(infos);
    assert!(result.is_err());
}

#[test]
fn test_validator_set_too_large() {
    let vals = gen_validators(31); // > MAX_VALIDATORS (30)
    let infos: Vec<ValidatorInfo> = vals.iter().map(|(_, info)| ValidatorInfo {
        fingerprint: info.fingerprint,
        falcon_pk: info.falcon_pk.clone(),
    }).collect();
    let result = ValidatorSet::new(infos);
    assert!(result.is_err());
}

// ════════════════════════════════════════════
// Test 14: Admin replay protection
// ════════════════════════════════════════════

#[test]
fn test_admin_replay_protection() {
    let admin_kp = falcon::falcon_keygen().unwrap();
    let cfg = AdminConfig {
        fingerprint: admin_kp.fingerprint,
        falcon_pk: admin_kp.public_key.clone(),
    };
    let mut ledger = Ledger::new(cfg, 1_000_000 * ONE_STMISAKA, true);

    let recipient = [0xAA; 32];
    let amount = 100 * ONE_STMISAKA;

    // First operation succeeds
    let hash1 = ledger.op_hash("distribute", &format!("to={} amount={}", hex::encode(recipient), amount));
    let sig1 = sign_admin_op(&admin_kp.secret_key, &hash1).unwrap();
    ledger.admin_distribute(&recipient, amount, &sig1).unwrap();

    // Replay with same signature fails (nonce incremented → different op_hash)
    let result = ledger.admin_distribute(&recipient, amount, &sig1);
    assert!(result.is_err());
}

// ════════════════════════════════════════════
// Test 15: Hash consistency between consensus and verify
// ════════════════════════════════════════════

#[test]
fn test_vote_hash_consistency() {
    // A vote hash computed in consensus must match verify's computation
    let vote = misaka_consensus::Vote {
        vote_type: VoteType::Precommit,
        height: 42,
        round: 3,
        block_hash: Some([0xAB; 32]),
        voter_id: [0x01; 32],
        signature: vec![],
    };

    let consensus_hash = misaka_consensus::encode_vote_message(&vote);
    let verify_hash = misaka_verify::compute_vote_hash(
        VoteType::Precommit as u8, 42, 3, &[0xAB; 32],
    );

    assert_eq!(consensus_hash, verify_hash, "Vote hash must be identical between consensus and verify modules");
}

// ════════════════════════════════════════════
// Test 16: WAL crash recovery — votes preserved
// ════════════════════════════════════════════

#[test]
fn test_wal_crash_recovery_votes() {
    use misaka_wal::*;
    use std::fs;

    let dir = std::env::temp_dir().join("misaka_integ_wal");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test_recovery.wal");
    let _ = fs::remove_file(&path);

    // Simulate: validator writes vote to WAL, then "crashes"
    {
        let mut wal = ConsensusWal::open(&path).unwrap();
        wal.truncate_and_start_height(100, [0xAA; 32]).unwrap();

        // Wrote prevote before broadcasting
        wal.write_entry(&WalEntry::Vote {
            height: 100, round: 0, vote_type: 1,
            block_hash: Some([0xBB; 32]),
            signature: vec![1, 2, 3, 4],
        }).unwrap();

        // Locked on this block
        wal.write_entry(&WalEntry::Lock {
            height: 100, round: 0, block_hash: [0xBB; 32],
        }).unwrap();

        // Wrote precommit
        wal.write_entry(&WalEntry::Vote {
            height: 100, round: 0, vote_type: 2,
            block_hash: Some([0xBB; 32]),
            signature: vec![5, 6, 7, 8],
        }).unwrap();

        // "crash" — drop without commit
    }

    // Recovery
    let state = ConsensusWal::recover(&path).unwrap().unwrap();
    assert_eq!(state.height, 100);
    assert_eq!(state.round, 0);
    assert_eq!(state.locked_hash, Some([0xBB; 32]));
    assert!(state.our_prevote.is_some());
    assert!(state.our_precommit.is_some());
    assert!(state.committed.is_none(), "No commit was written — should be None");

    // The recovered vote signatures can be re-broadcast
    match state.our_prevote.unwrap() {
        WalEntry::Vote { signature, .. } => {
            assert_eq!(signature, vec![1, 2, 3, 4]);
        }
        _ => panic!("Expected Vote"),
    }

    let _ = fs::remove_dir_all(&dir);
}

// ════════════════════════════════════════════
// Test 17: WAL crash mid-write recovery
// ════════════════════════════════════════════

#[test]
fn test_wal_partial_write_safe() {
    use misaka_wal::*;
    use std::fs;
    use std::io::Write;

    let dir = std::env::temp_dir().join("misaka_integ_wal2");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test_partial.wal");
    let _ = fs::remove_file(&path);

    // Write valid entries
    {
        let mut wal = ConsensusWal::open(&path).unwrap();
        wal.truncate_and_start_height(50, [0; 32]).unwrap();
        wal.write_entry(&WalEntry::Vote {
            height: 50, round: 0, vote_type: 1,
            block_hash: Some([0xCC; 32]),
            signature: vec![9, 9],
        }).unwrap();
    }

    // Simulate crash: append partial JSON
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"type\":\"Commit\",\"height\":50,\"rou").unwrap();
        // no fsync, no newline — truncated
    }

    // Recovery should get the valid entries, skip the partial
    let state = ConsensusWal::recover(&path).unwrap().unwrap();
    assert_eq!(state.height, 50);
    assert!(state.our_prevote.is_some());
    assert!(state.committed.is_none()); // partial commit not recovered

    let _ = fs::remove_dir_all(&dir);
}

// ════════════════════════════════════════════
// Test 18: WAL height transition truncation
// ════════════════════════════════════════════

#[test]
fn test_wal_height_transition() {
    use misaka_wal::*;
    use std::fs;

    let dir = std::env::temp_dir().join("misaka_integ_wal3");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test_height.wal");
    let _ = fs::remove_file(&path);

    {
        let mut wal = ConsensusWal::open(&path).unwrap();

        // Height 10
        wal.truncate_and_start_height(10, [0xAA; 32]).unwrap();
        wal.write_entry(&WalEntry::Vote {
            height: 10, round: 0, vote_type: 1,
            block_hash: Some([0x10; 32]), signature: vec![],
        }).unwrap();
        wal.write_entry(&WalEntry::Commit {
            height: 10, round: 0, block_hash: [0x10; 32],
        }).unwrap();

        // Height 11 — truncates height 10 data
        wal.truncate_and_start_height(11, [0x10; 32]).unwrap();
        wal.write_entry(&WalEntry::Vote {
            height: 11, round: 0, vote_type: 1,
            block_hash: Some([0x11; 32]), signature: vec![],
        }).unwrap();
    }

    // Recovery should only see height 11
    let state = ConsensusWal::recover(&path).unwrap().unwrap();
    assert_eq!(state.height, 11);
    assert_eq!(state.last_block_hash, [0x10; 32]); // prev hash from height 10
    assert!(state.committed.is_none()); // height 11 not committed yet

    let _ = fs::remove_dir_all(&dir);
}

// ════════════════════════════════════════════
// Test 19: Ledger snapshot save/load
// ════════════════════════════════════════════

#[test]
fn test_ledger_snapshot_integration() {
    use misaka_wal::LedgerSnapshot;
    use std::fs;

    let dir = std::env::temp_dir().join("misaka_integ_snap");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.json");

    let mut balances = std::collections::HashMap::new();
    balances.insert(hex::encode([0xAA; 32]), 5000 * ONE_STMISAKA);
    balances.insert(hex::encode([0xBB; 32]), 3000 * ONE_STMISAKA);

    let snap = LedgerSnapshot {
        height: 100,
        block_hash: [0xFF; 32],
        treasury: 2000 * ONE_STMISAKA,
        total_supply: 10_000 * ONE_STMISAKA,
        total_fee_rewards: 100 * ONE_STMISAKA,
        total_admin_distributed: 8000 * ONE_STMISAKA,
        admin_nonce: 15,
        balances,
    };

    snap.save(&path).unwrap();
    let loaded = LedgerSnapshot::load(&path).unwrap().unwrap();
    assert_eq!(loaded.height, 100);
    assert_eq!(loaded.admin_nonce, 15);
    assert_eq!(loaded.total_supply, 10_000 * ONE_STMISAKA);
    assert_eq!(loaded.balances.len(), 2);

    // Atomic write: verify tmp file doesn't linger
    assert!(!path.with_extension("tmp").exists());

    let _ = fs::remove_dir_all(&dir);
}

// ════════════════════════════════════════════
// Test 20: Mint freeze → distribute still works
// ════════════════════════════════════════════

#[test]
fn test_mint_freeze_distribute_unaffected() {
    let admin_kp = falcon::falcon_keygen().unwrap();
    let cfg = AdminConfig {
        fingerprint: admin_kp.fingerprint,
        falcon_pk: admin_kp.public_key.clone(),
    };
    let mut ledger = Ledger::new(cfg, 10_000_000 * ONE_STMISAKA, true);

    // Freeze mint
    let hash = ledger.op_hash("freeze_mint", "freeze_mint");
    let sig = sign_admin_op(&admin_kp.secret_key, &hash).unwrap();
    ledger.freeze_mint(&sig).unwrap();

    // Mint fails
    let hash2 = ledger.op_hash("mint", "amount=1");
    let sig2 = sign_admin_op(&admin_kp.secret_key, &hash2).unwrap();
    assert!(ledger.admin_mint(1, &sig2).is_err());

    // But distribute still works
    let alice = [0xAA; 32];
    let details = format!("to={} amount={}", hex::encode(alice), 100 * ONE_STMISAKA);
    let hash3 = ledger.op_hash("distribute", &details);
    let sig3 = sign_admin_op(&admin_kp.secret_key, &hash3).unwrap();
    ledger.admin_distribute(&alice, 100 * ONE_STMISAKA, &sig3).unwrap();
    assert_eq!(ledger.balance_of(&alice), 100 * ONE_STMISAKA);
    assert!(ledger.verify_invariant());
}

