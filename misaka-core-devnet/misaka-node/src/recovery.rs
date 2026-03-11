// ============================================================
// MISAKA Node — Startup Recovery Orchestration
// ============================================================
//
// Pipeline:
//   A. Load chain state (tip hash, height)
//   B. Replay WAL → reconstruct ConsensusManager
//   C. Reconcile chain tip vs consensus WAL state
//   D. Initialize mempool (empty)
//   E. Mark node ready for networking
//
// All steps are synchronous with no external side effects.
// Networking and consensus loops must not start until recovery
// completes successfully.
//
// ============================================================

use crate::{
    StartupError, RecoveredNodeState, ReconciliationAction, NodeStartupPhase,
};
use misaka_store::ChainState;
use misaka_mempool::Mempool;
use misaka_consensus_relay::{
    ConsensusManager, ConsensusRelayConfig, ConsensusEvent,
    consensus_wal::ConsensusEventWal,
};
use misaka_wal::event_wal::replay_events;
use std::path::Path;

// ════════════════════════════════════════════
// Startup recovery entrypoint
// ════════════════════════════════════════════

/// Perform full node startup recovery.
///
/// This is the canonical recovery entrypoint. It:
///   1. Reads chain state tip from the provided ChainState
///   2. Replays the consensus WAL to reconstruct ConsensusManager
///   3. Reconciles chain tip with WAL state
///   4. Returns RecoveredNodeState + live ConsensusManager + fresh Mempool
///
/// SAFETY:
///   - No votes/proposals/broadcasts emitted
///   - No chain state mutations (except tip reconciliation if needed)
///   - No mempool cleanup
///   - Caller must not start networking until this returns Ok
///
/// `local_validator_id`: Our Falcon fingerprint, used to restore
/// anti-equivocation flags (our_prevote/our_precommit). Pass None
/// for non-validator nodes.
pub fn startup_recover(
    chain_state: &ChainState,
    wal_path: &Path,
    consensus_config: ConsensusRelayConfig,
    local_validator_id: Option<[u8; 32]>,
) -> Result<(ConsensusManager, Mempool, RecoveredNodeState), StartupError> {
    let mut warnings = Vec::new();

    // ── A. Read chain state tip ──
    let chain_tip_hash = *chain_state.tip_hash();
    let chain_height = chain_state.tip_height();
    let is_genesis = chain_tip_hash == [0u8; 32] && chain_height == 0;

    // ── B. Replay WAL ──
    let events: Vec<ConsensusEvent> = replay_events(wal_path)
        .map_err(|e| StartupError::WalReplayFailed(e.to_string()))?;

    let events_replayed = events.len();
    if events_replayed == 0 {
        // No WAL — fresh start
        let next_height = if is_genesis { 0 } else { chain_height + 1 };
        let cm = ConsensusManager::new(consensus_config, next_height);
        let mempool = Mempool::with_defaults();

        return Ok((cm, mempool, RecoveredNodeState {
            chain_tip_hash,
            chain_height,
            consensus_height: next_height,
            wal_committed: false,
            wal_height_advanced: false,
            events_replayed: 0,
            our_prevote_restored: false,
            our_precommit_restored: false,
            warnings,
            reconciliation: ReconciliationAction::FreshStart,
        }));
    }

    // Determine WAL state
    let mut wal_height: u64 = 0;
    let mut wal_committed = false;
    let mut wal_height_advanced = false;
    let mut wal_committed_height: Option<u64> = None;

    for event in &events {
        match event {
            ConsensusEvent::HeightAdvanced { new_height } => {
                wal_height = *new_height;
                wal_committed = false;
                wal_height_advanced = true;
            }
            ConsensusEvent::BlockCommitted { height, .. } => {
                wal_height = *height;
                wal_committed = true;
                wal_height_advanced = false;
                wal_committed_height = Some(*height);
            }
            _ => {
                wal_height_advanced = false;
            }
        }
    }

    // Reconstruct ConsensusManager via canonical recovery path
    let cm = ConsensusManager::recover_from_wal(
        consensus_config.clone(), wal_path, local_validator_id,
    ).map_err(|e| StartupError::WalReplayFailed(e))?
     .unwrap_or_else(|| {
         let next_height = if is_genesis { 0 } else { chain_height + 1 };
         ConsensusManager::new(consensus_config.clone(), next_height)
     });

    let our_prevote_restored = cm.has_our_prevote();
    let our_precommit_restored = cm.has_our_precommit();

    // ── C. Reconcile chain tip vs WAL state ──
    let reconciliation;
    let consensus_height = cm.current_height();

    // Case A: WAL committed at height H, but chain store tip < H
    // This means the WAL recorded BlockCommitted but the block was never
    // applied to the store (crash between WAL write and store apply).
    if let Some(committed_h) = wal_committed_height {
        let expected_chain_height = if is_genesis { 0 } else { committed_h };
        if wal_committed && !wal_height_advanced {
            // WAL says committed but height not advanced
            if chain_height < committed_h && !is_genesis {
                // Critical: WAL committed but store didn't apply
                return Err(StartupError::CommittedButNotApplied(committed_h));
            }
            reconciliation = ReconciliationAction::CommittedNeedAdvance;
        } else if wal_height_advanced {
            // Clean: committed and advanced
            reconciliation = ReconciliationAction::Normal;
        } else {
            reconciliation = ReconciliationAction::PendingConsensus;
        }
    } else if wal_height < chain_height && !is_genesis {
        // Case C: WAL is behind chain (stale WAL from earlier height)
        warnings.push(format!(
            "WAL height {} is behind chain height {}; rebuilding consensus",
            wal_height, chain_height,
        ));
        reconciliation = ReconciliationAction::WalBehindChain;
    } else {
        // Case D: WAL has partial consensus state, no commit yet
        reconciliation = ReconciliationAction::PendingConsensus;
    }

    // ── D. Initialize mempool (empty — safe default) ──
    // Future: mempool persistence could be added here.
    let mempool = Mempool::with_defaults();

    Ok((cm, mempool, RecoveredNodeState {
        chain_tip_hash,
        chain_height,
        consensus_height,
        wal_committed,
        wal_height_advanced,
        events_replayed,
        our_prevote_restored,
        our_precommit_restored,
        warnings,
        reconciliation,
    }))
}

/// Check if it's safe to start networking given the current recovery state.
///
/// Returns Ok(()) if recovery completed normally.
/// Returns Err if the recovery state indicates an unsafe condition.
pub fn check_ready_for_networking(
    state: &RecoveredNodeState,
) -> Result<(), StartupError> {
    match state.reconciliation {
        ReconciliationAction::Normal
        | ReconciliationAction::PendingConsensus
        | ReconciliationAction::FreshStart
        | ReconciliationAction::WalBehindChain => Ok(()),
        ReconciliationAction::CommittedNeedAdvance => {
            // Node should advance height before starting networking.
            // The caller should call cm.advance_height() first.
            Err(StartupError::RecoveryNotReady(NodeStartupPhase::Recovering))
        }
    }
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_tx::*;
    use misaka_crypto::falcon::{falcon_keygen, FalconKeyPair};
    use misaka_verify::ValidatorInfo;
    use misaka_consensus::{ValidatorSet, VoteType, create_signed_vote};
    use misaka_consensus_relay::{
        ConsensusManager, ConsensusRelayConfig,
        consensus_wal::ConsensusEventWal,
    };
    use misaka_store::{Block, BlockHeader, ChainState};
    use misaka_block::apply_block_atomically_trusted;
    use misaka_mempool::Mempool;
    use std::path::PathBuf;
    use std::fs;

    // ── Helpers ──

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("misaka_node_test");
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn gen_validators(n: usize) -> Vec<(FalconKeyPair, ValidatorInfo)> {
        (0..n).map(|_| {
            let kp = falcon_keygen().unwrap();
            let info = ValidatorInfo {
                fingerprint: kp.fingerprint,
                falcon_pk: kp.public_key.clone(),
            };
            (kp, info)
        }).collect()
    }

    fn make_validator_set(vals: &[(FalconKeyPair, ValidatorInfo)]) -> ValidatorSet {
        let infos: Vec<ValidatorInfo> = vals.iter().map(|(_, i)| ValidatorInfo {
            fingerprint: i.fingerprint,
            falcon_pk: i.falcon_pk.clone(),
        }).collect();
        ValidatorSet::new(infos).unwrap()
    }

    fn seeded_chain_state() -> ChainState {
        let mut state = ChainState::genesis();
        for id_byte in [1u8, 2, 3, 4] {
            let eid = EnoteId([id_byte; 32]);
            let enote = StoredEnote {
                enote_id: eid,
                one_time_address: [id_byte; 32],
                amount_commitment: AmountCommitment([0xCC; 32]),
                note_commitment: NoteCommitment([0; 32]),
                view_tag: 0,
                asset_id: ASSET_NATIVE,
                enote_version: ENOTE_VERSION,
                created_at: 0,
            };
            state.insert_enote(&enote).unwrap();
        }
        state
    }

    fn make_block_simple(height: u64, prev_hash: [u8; 32]) -> Block {
        Block {
            header: BlockHeader {
                version: 2, height, round: 0, prev_hash, timestamp: 1000,
                tx_merkle_root: [0u8; 32], utxo_root: [0; 32], link_tag_root: [0; 32],
                proposer_id: [0xAA; 32], proposer_sig: vec![], bft_sigs: vec![],
            },
            transactions: vec![],
        }
    }

    fn default_config() -> ConsensusRelayConfig {
        ConsensusRelayConfig::default()
    }

    // ════════════════════════════════════════════
    // A. Restart after prevote — anti-equivocation
    // ════════════════════════════════════════════

    #[test]
    fn test_restart_after_prevote_prevents_conflicting_vote() {
        let wal_path = tmp_path("restart_prevote.wal");
        let _ = fs::remove_file(&wal_path);

        let vals = gen_validators(10);
        let our_id = vals[0].0.fingerprint;
        let our_sk = &vals[0].0.secret_key;

        // Phase 1: Create a consensus manager with WAL, cast prevote
        {
            let wal = misaka_wal::event_wal::EventWal::open(&wal_path).unwrap();
            let mut cm = ConsensusManager::new_with_wal(default_config(), 0, wal);

            // Cast prevote for block_hash [0xAA; 32]
            let result = cm.create_prevote(Some([0xAA; 32]), our_id, our_sk).unwrap();
            assert!(result.is_some());
            assert!(cm.has_our_prevote());
        }
        // cm + wal dropped — simulates crash

        // Phase 2: Recover from WAL
        let state = seeded_chain_state();
        let (cm, _mempool, recovered) = startup_recover(
            &state, &wal_path, default_config(), Some(our_id),
        ).unwrap();

        // Anti-equivocation: our_prevote must be restored
        assert!(cm.has_our_prevote(), "our_prevote must be restored after crash");
        assert!(recovered.our_prevote_restored);

        // Attempting a conflicting prevote must be rejected
        let conflict = cm.create_prevote(Some([0xBB; 32]), our_id, our_sk).unwrap();
        assert!(conflict.is_none(), "conflicting prevote must be rejected after recovery");

        let _ = fs::remove_file(&wal_path);
    }

    // ════════════════════════════════════════════
    // B. Restart after precommit — anti-equivocation
    // ════════════════════════════════════════════

    #[test]
    fn test_restart_after_precommit_prevents_conflicting_vote() {
        let wal_path = tmp_path("restart_precommit.wal");
        let _ = fs::remove_file(&wal_path);

        let vals = gen_validators(10);
        let our_id = vals[0].0.fingerprint;
        let our_sk = &vals[0].0.secret_key;

        // Phase 1: Cast precommit
        {
            let wal = misaka_wal::event_wal::EventWal::open(&wal_path).unwrap();
            let mut cm = ConsensusManager::new_with_wal(default_config(), 0, wal);
            let result = cm.create_precommit(Some([0xBB; 32]), our_id, our_sk).unwrap();
            assert!(result.is_some());
            assert!(cm.has_our_precommit());
        }

        // Phase 2: Recover
        let state = seeded_chain_state();
        let (cm, _, recovered) = startup_recover(
            &state, &wal_path, default_config(), Some(our_id),
        ).unwrap();

        assert!(cm.has_our_precommit(), "our_precommit must be restored");
        assert!(recovered.our_precommit_restored);

        let conflict = cm.create_precommit(Some([0xCC; 32]), our_id, our_sk).unwrap();
        assert!(conflict.is_none(), "conflicting precommit must be rejected");

        let _ = fs::remove_file(&wal_path);
    }

    // ════════════════════════════════════════════
    // C. Restart with pending proposal + votes
    // ════════════════════════════════════════════

    #[test]
    fn test_restart_with_pending_proposal_and_votes() {
        let wal_path = tmp_path("restart_pending.wal");
        let _ = fs::remove_file(&wal_path);

        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);

        // Phase 1: Receive proposal + some prevotes, then crash
        {
            let wal = misaka_wal::event_wal::EventWal::open(&wal_path).unwrap();
            let mut cm = ConsensusManager::new_with_wal(default_config(), 0, wal);

            // Proposer creates proposal
            let proposer = vs.get_proposer(0, 0);
            let proposer_kp = vals.iter()
                .find(|(_, i)| i.fingerprint == proposer.fingerprint).unwrap();
            let block = make_block_simple(0, [0u8; 32]);
            cm.create_proposal(block, proposer.fingerprint, &proposer_kp.0.secret_key).unwrap();

            // 3 validators prevote
            let bh = cm.proposal_block_hash().unwrap();
            for i in 0..3 {
                let vote = create_signed_vote(
                    VoteType::Prevote, 0, 0, Some(bh),
                    vals[i].0.fingerprint, &vals[i].0.secret_key,
                ).unwrap();
                cm.handle_prevote((i + 1) as u64, vote, &vs);
            }
            assert_eq!(cm.prevote_count(), 3);
        }
        // crash

        // Phase 2: Recover
        let state = seeded_chain_state();
        let (cm, _, recovered) = startup_recover(
            &state, &wal_path, default_config(), None,
        ).unwrap();

        // Proposal and votes should be restored
        assert_eq!(cm.prevote_count(), 3);
        assert!(cm.has_proposal());
        assert!(!cm.is_committed());
        assert_eq!(recovered.reconciliation, ReconciliationAction::PendingConsensus);
        assert!(recovered.events_replayed > 0);

        let _ = fs::remove_file(&wal_path);
    }

    // ════════════════════════════════════════════
    // D. Restart after committed block
    // ════════════════════════════════════════════

    #[test]
    fn test_restart_after_committed_block() {
        let wal_path = tmp_path("restart_committed.wal");
        let _ = fs::remove_file(&wal_path);

        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let mut chain_state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();

        let block = make_block_simple(0, [0u8; 32]);
        let block_hash = block.hash();

        // Phase 1: Full consensus round → commit → advance
        {
            let wal = misaka_wal::event_wal::EventWal::open(&wal_path).unwrap();
            let mut cm = ConsensusManager::new_with_wal(default_config(), 0, wal);

            // Store block candidate
            let proposer = vs.get_proposer(0, 0);
            let proposer_kp = vals.iter()
                .find(|(_, i)| i.fingerprint == proposer.fingerprint).unwrap();
            cm.create_proposal(block.clone(), proposer.fingerprint, &proposer_kp.0.secret_key).unwrap();

            // Quorum prevotes + precommits
            let quorum = vs.quorum();
            for i in 0..quorum {
                let vote = create_signed_vote(
                    VoteType::Prevote, 0, 0, Some(block_hash),
                    vals[i].0.fingerprint, &vals[i].0.secret_key,
                ).unwrap();
                cm.handle_prevote((i + 1) as u64, vote, &vs);
            }
            for i in 0..quorum {
                let vote = create_signed_vote(
                    VoteType::Precommit, 0, 0, Some(block_hash),
                    vals[i].0.fingerprint, &vals[i].0.secret_key,
                ).unwrap();
                cm.handle_precommit((i + 1) as u64, vote, &vs);
            }

            // Commit
            let (committed, _) = cm.try_commit(&mut chain_state, &mut mempool);
            assert!(committed);

            // Advance height
            cm.advance_height();
            assert_eq!(cm.current_height(), 1);
        }
        // crash after clean commit + advance

        // Phase 2: Recover
        let (cm, _, recovered) = startup_recover(
            &chain_state, &wal_path, default_config(), None,
        ).unwrap();

        assert_eq!(cm.current_height(), 1);
        assert!(!cm.is_committed());
        assert_eq!(chain_state.tip_height(), 0);
        assert_eq!(recovered.chain_height, 0);
        assert_eq!(recovered.consensus_height, 1);
        assert_eq!(recovered.reconciliation, ReconciliationAction::Normal);

        let _ = fs::remove_file(&wal_path);
    }

    // ════════════════════════════════════════════
    // E. Crash during partial WAL tail
    // ════════════════════════════════════════════

    #[test]
    fn test_crash_partial_wal_tail() {
        let wal_path = tmp_path("restart_partial_tail.wal");
        let _ = fs::remove_file(&wal_path);

        // Write valid events
        {
            let mut wal = ConsensusEventWal::open(&wal_path).unwrap();
            wal.start_height(0).unwrap();
            wal.append(&ConsensusEvent::ProposalReceived {
                height: 0, round: 0, block_hash: [0xAA; 32],
            }).unwrap();
            wal.append(&ConsensusEvent::PrevoteRecorded {
                height: 0, round: 0, voter: [0x01; 32],
                block_hash: Some([0xAA; 32]),
            }).unwrap();
        }

        // Append truncated garbage (simulate crash mid-write)
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new().append(true).open(&wal_path).unwrap();
            f.write_all(&500u32.to_le_bytes()).unwrap(); // header claiming 500 bytes
            f.write_all(&0u32.to_le_bytes()).unwrap();   // bogus checksum
            f.write_all(b"partial").unwrap();             // only 7 of 500 bytes
        }

        // Recover — should get the 3 valid events (HeightAdvanced + Proposal + Prevote)
        let state = seeded_chain_state();
        let (cm, _, recovered) = startup_recover(
            &state, &wal_path, default_config(), None,
        ).unwrap();

        assert_eq!(recovered.events_replayed, 3); // HeightAdvanced + Proposal + Prevote
        assert_eq!(cm.current_height(), 0);
        assert_eq!(cm.prevote_count(), 1);

        let _ = fs::remove_file(&wal_path);
    }

    // ════════════════════════════════════════════
    // F. Startup gating
    // ════════════════════════════════════════════

    #[test]
    fn test_startup_gating_committed_need_advance() {
        let wal_path = tmp_path("restart_gating.wal");
        let _ = fs::remove_file(&wal_path);

        // Write committed but NOT advanced
        {
            let mut wal = ConsensusEventWal::open(&wal_path).unwrap();
            wal.start_height(0).unwrap();
            wal.append(&ConsensusEvent::BlockCommitted {
                height: 0, block_hash: [0xDD; 32],
            }).unwrap();
            // No HeightAdvanced — crash between commit WAL write and advance
        }

        // Chain state has height 0 applied (committed)
        let mut state = seeded_chain_state();
        let block = make_block_simple(0, [0u8; 32]);
        let result = apply_block_atomically_trusted(&block, &mut state);
        assert!(result.is_applied());

        let (mut cm, _, recovered) = startup_recover(
            &state, &wal_path, default_config(), None,
        ).unwrap();

        assert_eq!(recovered.reconciliation, ReconciliationAction::CommittedNeedAdvance);

        // Networking should be blocked until advance
        let gate = check_ready_for_networking(&recovered);
        assert!(gate.is_err());

        // Advance height manually
        cm.advance_height();
        assert_eq!(cm.current_height(), 1);

        let _ = fs::remove_file(&wal_path);
    }

    // ════════════════════════════════════════════
    // G. Inconsistency detection
    // ════════════════════════════════════════════

    #[test]
    fn test_inconsistency_wal_committed_but_chain_not_applied() {
        let wal_path = tmp_path("restart_inconsistency.wal");
        let _ = fs::remove_file(&wal_path);

        // WAL says committed at height 5
        {
            let mut wal = ConsensusEventWal::open(&wal_path).unwrap();
            wal.start_height(5).unwrap();
            wal.append(&ConsensusEvent::BlockCommitted {
                height: 5, block_hash: [0xFF; 32],
            }).unwrap();
        }

        // But chain state is still at genesis (height 0)
        let state = seeded_chain_state();
        assert_eq!(state.tip_height(), 0);

        let result = startup_recover(
            &state, &wal_path, default_config(), None,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            StartupError::CommittedButNotApplied(h) => assert_eq!(h, 5),
            other => panic!("expected CommittedButNotApplied, got {:?}", other),
        }

        let _ = fs::remove_file(&wal_path);
    }

    // ════════════════════════════════════════════
    // Fresh start (no WAL)
    // ════════════════════════════════════════════

    #[test]
    fn test_fresh_start_no_wal() {
        let wal_path = tmp_path("restart_fresh.wal");
        let _ = fs::remove_file(&wal_path);

        let state = seeded_chain_state();
        let (cm, _, recovered) = startup_recover(
            &state, &wal_path, default_config(), None,
        ).unwrap();

        assert_eq!(cm.current_height(), 0);
        assert!(!cm.is_committed());
        assert_eq!(recovered.events_replayed, 0);
        assert_eq!(recovered.reconciliation, ReconciliationAction::FreshStart);
    }

    // ════════════════════════════════════════════
    // WAL behind chain tip
    // ════════════════════════════════════════════

    #[test]
    fn test_wal_behind_chain_tip() {
        let wal_path = tmp_path("restart_wal_behind.wal");
        let _ = fs::remove_file(&wal_path);

        // WAL at height 0 (old)
        {
            let mut wal = ConsensusEventWal::open(&wal_path).unwrap();
            wal.start_height(0).unwrap();
        }

        // Chain already at height 5
        let mut state = seeded_chain_state();
        for h in 0..5 {
            let prev = if h == 0 { [0u8; 32] } else { *state.tip_hash() };
            let block = make_block_simple(h, prev);
            let _ = apply_block_atomically_trusted(&block, &mut state);
        }
        assert_eq!(state.tip_height(), 4);

        let (cm, _, recovered) = startup_recover(
            &state, &wal_path, default_config(), None,
        ).unwrap();

        assert!(recovered.warnings.len() > 0);
        assert_eq!(recovered.reconciliation, ReconciliationAction::WalBehindChain);

        let _ = fs::remove_file(&wal_path);
    }

    // ════════════════════════════════════════════
    // Full integration: propose → vote → commit → crash → recover
    // ════════════════════════════════════════════

    #[test]
    fn test_full_consensus_round_crash_recover() {
        let wal_path = tmp_path("restart_full_round.wal");
        let _ = fs::remove_file(&wal_path);

        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let our_id = vals[0].0.fingerprint;
        let our_sk = &vals[0].0.secret_key;
        let mut chain_state = seeded_chain_state();
        let mut mempool = Mempool::with_defaults();

        let block = make_block_simple(0, [0u8; 32]);
        let block_hash = block.hash();

        // Phase 1: Full round
        {
            let wal = misaka_wal::event_wal::EventWal::open(&wal_path).unwrap();
            let mut cm = ConsensusManager::new_with_wal(default_config(), 0, wal);

            // Proposal
            let proposer = vs.get_proposer(0, 0);
            let proposer_kp = vals.iter()
                .find(|(_, i)| i.fingerprint == proposer.fingerprint).unwrap();
            cm.create_proposal(block.clone(), proposer.fingerprint, &proposer_kp.0.secret_key).unwrap();

            // Our prevote
            cm.create_prevote(Some(block_hash), our_id, our_sk).unwrap();

            // Other prevotes to reach quorum
            let quorum = vs.quorum();
            for i in 1..quorum {
                let vote = create_signed_vote(
                    VoteType::Prevote, 0, 0, Some(block_hash),
                    vals[i].0.fingerprint, &vals[i].0.secret_key,
                ).unwrap();
                cm.handle_prevote((i + 1) as u64, vote, &vs);
            }

            // Our precommit
            cm.create_precommit(Some(block_hash), our_id, our_sk).unwrap();

            // Other precommits to reach quorum
            for i in 1..quorum {
                let vote = create_signed_vote(
                    VoteType::Precommit, 0, 0, Some(block_hash),
                    vals[i].0.fingerprint, &vals[i].0.secret_key,
                ).unwrap();
                cm.handle_precommit((i + 1) as u64, vote, &vs);
            }

            // Commit
            let (committed, _) = cm.try_commit(&mut chain_state, &mut mempool);
            assert!(committed);
            cm.advance_height();
        }
        // crash

        // Phase 2: Recover
        let (cm, _, recovered) = startup_recover(
            &chain_state, &wal_path, default_config(), Some(our_id),
        ).unwrap();

        // Should be at height 1, ready to continue
        assert_eq!(cm.current_height(), 1);
        assert!(!cm.is_committed());
        assert!(!cm.has_our_prevote()); // new height, flags reset
        assert!(!cm.has_our_precommit());

        // Chain state should be at height 0
        assert_eq!(chain_state.tip_height(), 0);
        assert_eq!(recovered.chain_height, 0);
        assert_eq!(recovered.consensus_height, 1);

        // Networking check should pass
        assert!(check_ready_for_networking(&recovered).is_ok());

        let _ = fs::remove_file(&wal_path);
    }

    // ════════════════════════════════════════════
    // Pending precommit quorum, no commit
    // ════════════════════════════════════════════

    #[test]
    fn test_restart_pending_precommit_quorum() {
        let wal_path = tmp_path("restart_pending_quorum.wal");
        let _ = fs::remove_file(&wal_path);

        let vals = gen_validators(10);
        let vs = make_validator_set(&vals);
        let our_id = vals[0].0.fingerprint;
        let our_sk = &vals[0].0.secret_key;

        let block = make_block_simple(0, [0u8; 32]);
        let block_hash = block.hash();

        // Phase 1: Reach precommit quorum but crash before try_commit
        {
            let wal = misaka_wal::event_wal::EventWal::open(&wal_path).unwrap();
            let mut cm = ConsensusManager::new_with_wal(default_config(), 0, wal);

            let proposer = vs.get_proposer(0, 0);
            let proposer_kp = vals.iter()
                .find(|(_, i)| i.fingerprint == proposer.fingerprint).unwrap();
            cm.create_proposal(block, proposer.fingerprint, &proposer_kp.0.secret_key).unwrap();

            // Prevotes
            cm.create_prevote(Some(block_hash), our_id, our_sk).unwrap();
            let quorum = vs.quorum();
            for i in 1..quorum {
                let vote = create_signed_vote(
                    VoteType::Prevote, 0, 0, Some(block_hash),
                    vals[i].0.fingerprint, &vals[i].0.secret_key,
                ).unwrap();
                cm.handle_prevote((i + 1) as u64, vote, &vs);
            }

            // Precommits
            cm.create_precommit(Some(block_hash), our_id, our_sk).unwrap();
            for i in 1..quorum {
                let vote = create_signed_vote(
                    VoteType::Precommit, 0, 0, Some(block_hash),
                    vals[i].0.fingerprint, &vals[i].0.secret_key,
                ).unwrap();
                cm.handle_precommit((i + 1) as u64, vote, &vs);
            }

            assert!(cm.precommit_quorum_hash().is_some());
            // CRASH before try_commit
        }

        // Phase 2: Recover
        let state = seeded_chain_state();
        let (cm, _, recovered) = startup_recover(
            &state, &wal_path, default_config(), Some(our_id),
        ).unwrap();

        // Quorum should be restored
        assert!(cm.precommit_quorum_hash().is_some());
        assert!(cm.has_our_prevote());
        assert!(cm.has_our_precommit());
        assert!(!cm.is_committed()); // commit never happened

        // Node can now call try_commit with the block body
        // (In production, the block would need to be re-fetched from peers)
        assert_eq!(recovered.reconciliation, ReconciliationAction::PendingConsensus);

        let _ = fs::remove_file(&wal_path);
    }

    // ════════════════════════════════════════════
    // Phase lifecycle
    // ════════════════════════════════════════════

    #[test]
    fn test_node_startup_phase_lifecycle() {
        let phase = NodeStartupPhase::Recovering;
        assert_eq!(phase, NodeStartupPhase::Recovering);

        // Transition
        let phase = NodeStartupPhase::Recovered;
        assert_eq!(phase, NodeStartupPhase::Recovered);

        let phase = NodeStartupPhase::NetworkingStarted;
        assert_eq!(phase, NodeStartupPhase::NetworkingStarted);
    }
}
