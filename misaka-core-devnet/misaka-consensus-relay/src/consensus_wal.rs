// ============================================================
// MISAKA Consensus — WAL Integration
// ============================================================
//
// Wraps misaka_wal::event_wal::EventWal for ConsensusEvent persistence.
//
// WAL lifecycle per consensus height:
//
//   1. On height start: truncate WAL, write HeightAdvanced
//   2. Before any state mutation: append ConsensusEvent + fsync
//   3. On commit: write BlockCommitted + fsync
//   4. After commit: write HeightAdvanced + fsync
//   5. On recovery: replay events to reconstruct ConsensusManager state
//
// Safety invariant:
//   Events are written to WAL BEFORE they affect in-memory state.
//   If the process crashes:
//     - before WAL write: event never happened (safe)
//     - after WAL write but before state mutation: replay will restore it
//     - after state mutation: no issue
//
// ============================================================

use crate::{ConsensusEvent, ConsensusManager, ConsensusRelayConfig};
use misaka_wal::event_wal::{EventWal, replay_events};
use misaka_wal::WalError;
use std::path::Path;

// ════════════════════════════════════════════
// ConsensusEventWal
// ════════════════════════════════════════════

/// WAL handle for consensus events.
///
/// Wraps the generic EventWal with ConsensusEvent-specific methods.
/// All writes are followed by fsync (handled by EventWal internally).
pub struct ConsensusEventWal {
    inner: EventWal,
}

impl ConsensusEventWal {
    /// Open or create a consensus WAL file.
    pub fn open(path: &Path) -> Result<Self, WalError> {
        let inner = EventWal::open(path)?;
        Ok(Self { inner })
    }

    /// Append a consensus event to the WAL.
    ///
    /// CRITICAL: Call this BEFORE the corresponding state mutation
    /// in ConsensusManager. The fsync ensures the event is durable.
    pub fn append(&mut self, event: &ConsensusEvent) -> Result<(), WalError> {
        self.inner.append_event(event)
    }

    /// Truncate WAL and write an initial HeightAdvanced event.
    ///
    /// Called at the start of a new consensus height to discard
    /// events from the previous height.
    pub fn start_height(&mut self, new_height: u64) -> Result<(), WalError> {
        self.inner.truncate_and_write(&ConsensusEvent::HeightAdvanced {
            new_height,
        })
    }

    /// Truncate WAL completely (fresh start).
    pub fn truncate(&mut self) -> Result<(), WalError> {
        self.inner.truncate()
    }

    /// Get the WAL file path.
    pub fn path(&self) -> &Path {
        self.inner.path()
    }
}

// ════════════════════════════════════════════
// Recovery
// ════════════════════════════════════════════

/// Recovered consensus state from WAL replay.
#[derive(Debug)]
pub struct RecoveredConsensusState {
    /// Events replayed from WAL, in order.
    pub events: Vec<ConsensusEvent>,
    /// The height the node was at when it stopped.
    pub recovered_height: u64,
    /// Whether a block was committed at the recovered height.
    pub committed: bool,
    /// Whether height was advanced after commit (clean shutdown).
    pub height_advanced: bool,
}

/// Replay a consensus WAL and reconstruct the ConsensusManager state.
///
/// Recovery procedure:
///   1. Read all valid events from WAL
///   2. Replay into a fresh ConsensusManager
///   3. Return the recovered state for the caller to inspect
///
/// The caller should then:
///   - If committed but height not advanced: advance height manually
///   - Resume normal consensus operation
///   - Do NOT rebroadcast recovered votes (replay is silent)
pub fn recover_from_wal(
    wal_path: &Path,
    config: ConsensusRelayConfig,
    _start_height: u64,
    local_validator_id: Option<[u8; 32]>,
) -> Result<(ConsensusManager, RecoveredConsensusState), WalError> {
    let events: Vec<ConsensusEvent> = replay_events(wal_path)?;

    // Determine recovered state from events
    let mut recovered_height = 0u64;
    let mut committed = false;
    let mut height_advanced = false;

    for event in &events {
        match event {
            ConsensusEvent::HeightAdvanced { new_height } => {
                recovered_height = *new_height;
                committed = false;
                height_advanced = true;
            }
            ConsensusEvent::BlockCommitted { height, .. } => {
                recovered_height = *height;
                committed = true;
                height_advanced = false;
            }
            _ => {
                height_advanced = false;
            }
        }
    }

    // Use ConsensusManager::recover_from_wal which handles local_validator_id
    let cm = ConsensusManager::recover_from_wal(config.clone(), wal_path, local_validator_id)
        .map_err(|e| WalError::Corrupted { line: 0, reason: e })?
        .unwrap_or_else(|| ConsensusManager::new(config, recovered_height));

    let state = RecoveredConsensusState {
        events,
        recovered_height,
        committed,
        height_advanced,
    };

    Ok((cm, state))
}

/// Write the commit sequence to WAL atomically.
///
/// This is the critical path: BlockCommitted must be persisted
/// before the block is applied to the state store.
///
/// Sequence:
///   1. Append BlockCommitted → fsync
///   2. (caller applies block to state)
///   3. Append HeightAdvanced → fsync
///   4. (caller truncates WAL for next height)
pub fn write_commit_sequence(
    wal: &mut ConsensusEventWal,
    height: u64,
    block_hash: [u8; 32],
) -> Result<(), WalError> {
    wal.append(&ConsensusEvent::BlockCommitted { height, block_hash })?;
    Ok(())
}

/// Write height advancement after successful commit.
pub fn write_height_advance(
    wal: &mut ConsensusEventWal,
    new_height: u64,
) -> Result<(), WalError> {
    wal.append(&ConsensusEvent::HeightAdvanced { new_height })?;
    Ok(())
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_relay::BlockHash;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("misaka_consensus_wal_test");
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn default_config() -> ConsensusRelayConfig {
        ConsensusRelayConfig::default()
    }

    // ════════════════════════════════════════════
    // WAL write/read tests
    // ════════════════════════════════════════════

    #[test]
    fn test_append_and_replay_events() {
        let path = tmp_path("test_append_replay.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 0 }).unwrap();
            wal.append(&ConsensusEvent::ProposalReceived {
                height: 0, round: 0, block_hash: [0xAA; 32],
            }).unwrap();
            wal.append(&ConsensusEvent::PrevoteRecorded {
                height: 0, round: 0, voter: [0x01; 32],
                block_hash: Some([0xAA; 32]),
            }).unwrap();
            wal.append(&ConsensusEvent::PrecommitRecorded {
                height: 0, round: 0, voter: [0x01; 32],
                block_hash: Some([0xAA; 32]),
            }).unwrap();
        }

        let events: Vec<ConsensusEvent> = replay_events(&path).unwrap();
        assert_eq!(events.len(), 4);
        assert!(matches!(events[0], ConsensusEvent::HeightAdvanced { new_height: 0 }));
        assert!(matches!(events[1], ConsensusEvent::ProposalReceived { .. }));
        assert!(matches!(events[2], ConsensusEvent::PrevoteRecorded { .. }));
        assert!(matches!(events[3], ConsensusEvent::PrecommitRecorded { .. }));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_replay_correct_order() {
        let path = tmp_path("test_order.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            for i in 0..5u64 {
                wal.append(&ConsensusEvent::PrevoteRecorded {
                    height: 0, round: 0,
                    voter: [i as u8; 32],
                    block_hash: Some([0xBB; 32]),
                }).unwrap();
            }
        }

        let events: Vec<ConsensusEvent> = replay_events(&path).unwrap();
        assert_eq!(events.len(), 5);
        for (i, e) in events.iter().enumerate() {
            if let ConsensusEvent::PrevoteRecorded { voter, .. } = e {
                assert_eq!(voter[0], i as u8);
            } else {
                panic!("wrong event type");
            }
        }

        let _ = fs::remove_file(&path);
    }

    // ════════════════════════════════════════════
    // Crash safety tests
    // ════════════════════════════════════════════

    #[test]
    fn test_crash_mid_write_recovery() {
        let path = tmp_path("test_crash_mid.wal");
        let _ = fs::remove_file(&path);

        // Write two valid events
        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 5 }).unwrap();
            wal.append(&ConsensusEvent::ProposalReceived {
                height: 5, round: 0, block_hash: [0xCC; 32],
            }).unwrap();
        }

        // Append partial garbage (simulate crash mid-write)
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            // Write a header claiming 200 bytes but only write 3
            f.write_all(&200u32.to_le_bytes()).unwrap();
            f.write_all(&0u32.to_le_bytes()).unwrap();
            f.write_all(b"abc").unwrap();
        }

        // Replay should recover the two valid events only
        let events: Vec<ConsensusEvent> = replay_events(&path).unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], ConsensusEvent::HeightAdvanced { new_height: 5 }));
        assert!(matches!(events[1], ConsensusEvent::ProposalReceived { .. }));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_empty_wal_recovery() {
        let path = tmp_path("test_empty_wal.wal");
        let _ = fs::remove_file(&path);

        let events: Vec<ConsensusEvent> = replay_events(&path).unwrap();
        assert!(events.is_empty());
    }

    // ════════════════════════════════════════════
    // Consensus recovery tests
    // ════════════════════════════════════════════

    #[test]
    fn test_recover_proposal_and_votes() {
        let path = tmp_path("test_recover_pv.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 0 }).unwrap();
            wal.append(&ConsensusEvent::ProposalReceived {
                height: 0, round: 0, block_hash: [0xAA; 32],
            }).unwrap();
            for i in 0..3u8 {
                wal.append(&ConsensusEvent::PrevoteRecorded {
                    height: 0, round: 0,
                    voter: [i; 32],
                    block_hash: Some([0xAA; 32]),
                }).unwrap();
            }
        }

        let (cm, state) = recover_from_wal(&path, default_config(), 0, None).unwrap();
        assert_eq!(cm.current_height(), 0);
        assert_eq!(cm.prevote_count(), 3);
        assert_eq!(state.recovered_height, 0);
        assert!(!state.committed);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_recover_quorum_events() {
        let path = tmp_path("test_recover_quorum.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 0 }).unwrap();
            wal.append(&ConsensusEvent::PrevoteQuorum {
                height: 0, round: 0, block_hash: Some([0xAA; 32]),
            }).unwrap();
            wal.append(&ConsensusEvent::PrecommitQuorum {
                height: 0, round: 0, block_hash: [0xAA; 32],
            }).unwrap();
        }

        let (cm, _) = recover_from_wal(&path, default_config(), 0, None).unwrap();
        assert_eq!(cm.prevote_quorum_hash(), Some(Some([0xAA; 32])));
        assert_eq!(cm.precommit_quorum_hash(), Some([0xAA; 32]));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_recover_commit() {
        let path = tmp_path("test_recover_commit.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 10 }).unwrap();
            wal.append(&ConsensusEvent::BlockCommitted {
                height: 10, block_hash: [0xDD; 32],
            }).unwrap();
        }

        let (cm, state) = recover_from_wal(&path, default_config(), 10, None).unwrap();
        assert!(cm.is_committed());
        assert_eq!(state.recovered_height, 10);
        assert!(state.committed);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_recover_commit_then_height_advance() {
        let path = tmp_path("test_recover_advance.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 5 }).unwrap();
            wal.append(&ConsensusEvent::BlockCommitted {
                height: 5, block_hash: [0xEE; 32],
            }).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 6 }).unwrap();
        }

        let (cm, state) = recover_from_wal(&path, default_config(), 5, None).unwrap();
        assert_eq!(cm.current_height(), 6);
        assert!(!cm.is_committed()); // new height, not yet committed
        assert_eq!(state.recovered_height, 6);
        assert!(!state.committed);
        assert!(state.height_advanced);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_recover_correct_height() {
        let path = tmp_path("test_recover_height.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            // Simulate a sequence of heights
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 0 }).unwrap();
            wal.append(&ConsensusEvent::BlockCommitted {
                height: 0, block_hash: [0x01; 32],
            }).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 1 }).unwrap();
            wal.append(&ConsensusEvent::BlockCommitted {
                height: 1, block_hash: [0x02; 32],
            }).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 2 }).unwrap();
            // Crash here — height 2 not committed
        }

        let (cm, state) = recover_from_wal(&path, default_config(), 0, None).unwrap();
        assert_eq!(cm.current_height(), 2);
        assert!(!cm.is_committed());
        assert_eq!(state.recovered_height, 2);
        assert!(!state.committed);

        let _ = fs::remove_file(&path);
    }

    // ════════════════════════════════════════════
    // Integration: full round with WAL
    // ════════════════════════════════════════════

    #[test]
    fn test_full_round_with_wal_persist_and_recover() {
        let path = tmp_path("test_full_round.wal");
        let _ = fs::remove_file(&path);

        let bh: BlockHash = [0xAA; 32];

        // Simulate a full consensus round with WAL persistence
        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();

            // Height 0 start
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 0 }).unwrap();

            // Proposal
            wal.append(&ConsensusEvent::ProposalReceived {
                height: 0, round: 0, block_hash: bh,
            }).unwrap();

            // 7 prevotes (quorum for 10 validators)
            for i in 0..7u8 {
                wal.append(&ConsensusEvent::PrevoteRecorded {
                    height: 0, round: 0,
                    voter: [i; 32],
                    block_hash: Some(bh),
                }).unwrap();
            }

            // Prevote quorum
            wal.append(&ConsensusEvent::PrevoteQuorum {
                height: 0, round: 0, block_hash: Some(bh),
            }).unwrap();

            // 7 precommits
            for i in 0..7u8 {
                wal.append(&ConsensusEvent::PrecommitRecorded {
                    height: 0, round: 0,
                    voter: [i; 32],
                    block_hash: Some(bh),
                }).unwrap();
            }

            // Precommit quorum
            wal.append(&ConsensusEvent::PrecommitQuorum {
                height: 0, round: 0, block_hash: bh,
            }).unwrap();

            // Commit
            write_commit_sequence(&mut wal, 0, bh).unwrap();

            // Height advance
            write_height_advance(&mut wal, 1).unwrap();
        }

        // Recovery: node restarts
        let (cm, state) = recover_from_wal(&path, default_config(), 0, None).unwrap();

        // Should be at height 1, not committed
        assert_eq!(cm.current_height(), 1);
        assert!(!cm.is_committed());
        assert_eq!(state.recovered_height, 1);
        assert!(!state.committed);
        assert!(state.height_advanced);

        // Events should all be present
        assert_eq!(state.events.len(), 19); // 1 + 1 + 7 + 1 + 7 + 1 + 1 + 1 = 20... let me count
        // HeightAdvanced(0) + ProposalReceived + 7*Prevote + PrevoteQuorum +
        // 7*Precommit + PrecommitQuorum + BlockCommitted + HeightAdvanced(1) = 20
        assert_eq!(state.events.len(), 20);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_crash_before_commit_no_double_commit() {
        let path = tmp_path("test_no_double_commit.wal");
        let _ = fs::remove_file(&path);

        let bh: BlockHash = [0xBB; 32];

        // Simulate crash BEFORE BlockCommitted is written
        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 0 }).unwrap();
            wal.append(&ConsensusEvent::PrecommitQuorum {
                height: 0, round: 0, block_hash: bh,
            }).unwrap();
            // CRASH — no BlockCommitted written
        }

        let (cm, state) = recover_from_wal(&path, default_config(), 0, None).unwrap();
        assert_eq!(cm.current_height(), 0);
        assert!(!cm.is_committed()); // NOT committed — safe
        assert!(cm.precommit_quorum_hash().is_some()); // quorum was restored
        assert!(!state.committed);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_crash_after_commit_before_advance() {
        let path = tmp_path("test_crash_after_commit.wal");
        let _ = fs::remove_file(&path);

        let bh: BlockHash = [0xCC; 32];

        // Crash AFTER BlockCommitted but BEFORE HeightAdvanced
        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 3 }).unwrap();
            write_commit_sequence(&mut wal, 3, bh).unwrap();
            // CRASH — no HeightAdvanced written
        }

        let (cm, state) = recover_from_wal(&path, default_config(), 3, None).unwrap();
        assert_eq!(cm.current_height(), 3);
        assert!(cm.is_committed()); // committed is restored
        assert!(state.committed);
        assert!(!state.height_advanced);

        // Caller should advance height manually
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_start_height_truncates_wal() {
        let path = tmp_path("test_start_height.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusEventWal::open(&path).unwrap();
            // Old events
            wal.append(&ConsensusEvent::HeightAdvanced { new_height: 0 }).unwrap();
            wal.append(&ConsensusEvent::ProposalReceived {
                height: 0, round: 0, block_hash: [0xAA; 32],
            }).unwrap();

            // Start new height — should truncate
            wal.start_height(1).unwrap();
        }

        let events: Vec<ConsensusEvent> = replay_events(&path).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], ConsensusEvent::HeightAdvanced { new_height: 1 });

        let _ = fs::remove_file(&path);
    }
}
