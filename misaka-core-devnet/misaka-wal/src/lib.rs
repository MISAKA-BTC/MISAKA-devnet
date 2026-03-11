// ============================================================
// MISAKA Network — Write-Ahead Log (WAL)
// ============================================================
//
// Purpose:
//   Prevent equivocation and enable crash recovery for BFT consensus.
//
// Invariant:
//   A validator MUST write its intended vote to the WAL and fsync
//   BEFORE broadcasting the vote to the network. This ensures that
//   after a crash, the validator can recover what it already voted
//   for and will not sign a conflicting vote (equivocation).
//
// WAL lifecycle per height:
//   1. On entering a new height: truncate WAL, write NewHeight entry
//   2. Before each vote: write Vote entry + fsync
//   3. On lock change: write Lock entry + fsync
//   4. On commit: write Commit entry + fsync
//   5. On next height: goto 1
//
// Recovery:
//   On startup, read the WAL file. The last NewHeight entry determines
//   the current height. Replay all subsequent entries to reconstruct
//   the RoundState (which round, what we voted for, lock state).
//
// File format:
//   One JSON object per line (newline-delimited JSON / NDJSON).
//   Each line is self-contained and parseable independently.
//   Partial writes (crash mid-line) produce invalid JSON on the
//   last line, which is safely skipped during recovery.
//
// ============================================================

use serde::{Serialize, Deserialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub mod event_wal;

#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("WAL I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("WAL corrupted at line {line}: {reason}")]
    Corrupted { line: usize, reason: String },
}

/// A single WAL entry. Each variant represents a state transition
/// that must be persisted before the corresponding network action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum WalEntry {
    /// Start of a new consensus height. Implies WAL truncation.
    NewHeight {
        height: u64,
        /// Hash of the last committed block (prev_hash for this height)
        last_block_hash: [u8; 32],
    },

    /// Round advancement (timeout or +2/3 nil).
    NewRound {
        height: u64,
        round: u32,
    },

    /// Our own vote. Written BEFORE broadcasting.
    /// This is the critical equivocation-prevention entry.
    Vote {
        height: u64,
        round: u32,
        vote_type: u8,  // 1=Prevote, 2=Precommit
        /// None for nil vote
        block_hash: Option<[u8; 32]>,
        /// The serialized signature (so we can re-broadcast on recovery)
        signature: Vec<u8>,
    },

    /// Lock state change.
    Lock {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
    },

    /// Lock cleared (after +2/3 nil prevotes at higher round).
    Unlock {
        height: u64,
        round: u32,
    },

    /// Block committed at this height. After this, the next
    /// NewHeight will truncate the WAL.
    Commit {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
    },
}

/// Recovery state reconstructed from WAL replay.
#[derive(Debug, Clone)]
pub struct RecoveredState {
    pub height: u64,
    pub last_block_hash: [u8; 32],
    pub round: u32,
    /// Votes we already cast (must not re-sign different ones)
    pub our_prevote: Option<WalEntry>,
    pub our_precommit: Option<WalEntry>,
    /// Lock state
    pub locked_hash: Option<[u8; 32]>,
    pub locked_round: Option<u32>,
    /// Whether a commit was already written for this height
    pub committed: Option<[u8; 32]>,
}

/// The WAL file handle.
pub struct ConsensusWal {
    path: PathBuf,
    file: File,
}

impl ConsensusWal {
    /// Open or create a WAL file at the given path.
    pub fn open(path: &Path) -> Result<Self, WalError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Write an entry to the WAL and fsync.
    ///
    /// CRITICAL: This MUST complete before the corresponding network
    /// action (e.g., broadcasting a vote). If the process crashes
    /// after fsync but before broadcast, recovery will find the vote
    /// and can re-broadcast it. If the process crashes before fsync,
    /// the vote was never persisted and never broadcast — safe.
    pub fn write_entry(&mut self, entry: &WalEntry) -> Result<(), WalError> {
        let json = serde_json::to_string(entry)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.file.write_all(json.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Truncate the WAL (called at the start of a new height).
    ///
    /// After truncation, writes a NewHeight entry as the first line.
    pub fn truncate_and_start_height(
        &mut self,
        height: u64,
        last_block_hash: [u8; 32],
    ) -> Result<(), WalError> {
        // Truncate by re-opening with truncate
        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;

        self.write_entry(&WalEntry::NewHeight {
            height,
            last_block_hash,
        })
    }

    /// Recover state from the WAL file.
    ///
    /// Returns None if the WAL is empty or contains no valid NewHeight.
    /// Partial/corrupted last lines are silently skipped (crash tolerance).
    pub fn recover(path: &Path) -> Result<Option<RecoveredState>, WalError> {
        if !path.exists() {
            return Ok(None);
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut entries = Vec::new();
        for (line_num, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(l) => l,
                Err(_) => break, // Partial read at EOF — stop
            };

            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<WalEntry>(&line) {
                Ok(entry) => entries.push(entry),
                Err(_) => {
                    // Last line may be partial (crash mid-write) — skip it.
                    // If it's NOT the last line, this is real corruption.
                    // We can't know yet, so we collect what we can and
                    // validate below.
                    break;
                }
            }
        }

        if entries.is_empty() {
            return Ok(None);
        }

        // Find the last NewHeight — that's our recovery point.
        let nh_idx = entries.iter().rposition(|e| matches!(e, WalEntry::NewHeight { .. }));
        let nh_idx = match nh_idx {
            Some(i) => i,
            None => return Ok(None),
        };

        let (height, last_block_hash) = match &entries[nh_idx] {
            WalEntry::NewHeight { height, last_block_hash } => (*height, *last_block_hash),
            _ => unreachable!(),
        };

        let mut state = RecoveredState {
            height,
            last_block_hash,
            round: 0,
            our_prevote: None,
            our_precommit: None,
            locked_hash: None,
            locked_round: None,
            committed: None,
        };

        // Replay entries after NewHeight
        for entry in &entries[nh_idx + 1..] {
            match entry {
                WalEntry::NewRound { round, height: h } if *h == height => {
                    state.round = *round;
                    // Votes reset on new round
                    state.our_prevote = None;
                    state.our_precommit = None;
                }
                WalEntry::Vote { vote_type, height: h, round, .. } if *h == height && *round == state.round => {
                    match vote_type {
                        1 => state.our_prevote = Some(entry.clone()),
                        2 => state.our_precommit = Some(entry.clone()),
                        _ => {}
                    }
                }
                WalEntry::Lock { height: h, round, block_hash } if *h == height => {
                    state.locked_hash = Some(*block_hash);
                    state.locked_round = Some(*round);
                }
                WalEntry::Unlock { height: h, .. } if *h == height => {
                    state.locked_hash = None;
                    state.locked_round = None;
                }
                WalEntry::Commit { height: h, block_hash, .. } if *h == height => {
                    state.committed = Some(*block_hash);
                }
                _ => {} // Ignore entries for other heights (shouldn't exist after truncation)
            }
        }

        Ok(Some(state))
    }
}

/// Ledger state snapshot for persistence.
///
/// The Ledger (admin module) should serialize this after each committed
/// block and write it to a state file. On recovery, reload from the
/// snapshot + replay any WAL-committed blocks not yet in the snapshot.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LedgerSnapshot {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub treasury: u64,
    pub total_supply: u64,
    pub total_fee_rewards: u64,
    pub total_admin_distributed: u64,
    pub admin_nonce: u64,
    /// Balances as hex(fingerprint) → amount
    pub balances: std::collections::HashMap<String, u64>,
}

impl LedgerSnapshot {
    /// Save snapshot to a file with atomic rename.
    ///
    /// Write to tmp file, fsync, rename over target. This ensures
    /// that the target file is always complete and valid — a crash
    /// during write leaves the old snapshot intact.
    pub fn save(&self, path: &Path) -> Result<(), WalError> {
        let tmp_path = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut f = File::create(&tmp_path)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load snapshot from a file.
    pub fn load(path: &Path) -> Result<Option<Self>, WalError> {
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(path)?;
        let snap: Self = serde_json::from_str(&data)
            .map_err(|e| WalError::Corrupted {
                line: 0,
                reason: format!("snapshot parse error: {}", e),
            })?;
        Ok(Some(snap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("misaka_wal_test");
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn test_wal_write_and_recover() {
        let path = tmp_path("test_basic.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusWal::open(&path).unwrap();
            wal.truncate_and_start_height(10, [0xAA; 32]).unwrap();

            wal.write_entry(&WalEntry::Vote {
                height: 10, round: 0, vote_type: 1,
                block_hash: Some([0xBB; 32]),
                signature: vec![1, 2, 3],
            }).unwrap();

            wal.write_entry(&WalEntry::Lock {
                height: 10, round: 0, block_hash: [0xBB; 32],
            }).unwrap();

            wal.write_entry(&WalEntry::Vote {
                height: 10, round: 0, vote_type: 2,
                block_hash: Some([0xBB; 32]),
                signature: vec![4, 5, 6],
            }).unwrap();
        }

        let state = ConsensusWal::recover(&path).unwrap().unwrap();
        assert_eq!(state.height, 10);
        assert_eq!(state.last_block_hash, [0xAA; 32]);
        assert_eq!(state.round, 0);
        assert!(state.our_prevote.is_some());
        assert!(state.our_precommit.is_some());
        assert_eq!(state.locked_hash, Some([0xBB; 32]));
        assert_eq!(state.locked_round, Some(0));
        assert!(state.committed.is_none());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_round_advancement() {
        let path = tmp_path("test_round.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusWal::open(&path).unwrap();
            wal.truncate_and_start_height(5, [0; 32]).unwrap();

            // Round 0: vote for A
            wal.write_entry(&WalEntry::Vote {
                height: 5, round: 0, vote_type: 1,
                block_hash: Some([0xAA; 32]),
                signature: vec![],
            }).unwrap();

            // Advance to round 1
            wal.write_entry(&WalEntry::NewRound { height: 5, round: 1 }).unwrap();

            // Round 1: vote for B
            wal.write_entry(&WalEntry::Vote {
                height: 5, round: 1, vote_type: 1,
                block_hash: Some([0xBB; 32]),
                signature: vec![],
            }).unwrap();
        }

        let state = ConsensusWal::recover(&path).unwrap().unwrap();
        assert_eq!(state.round, 1);
        // Should have round 1's vote, not round 0's
        match &state.our_prevote {
            Some(WalEntry::Vote { block_hash, round, .. }) => {
                assert_eq!(*round, 1);
                assert_eq!(*block_hash, Some([0xBB; 32]));
            }
            other => panic!("Expected Vote, got {:?}", other),
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_truncated_line_recovery() {
        let path = tmp_path("test_trunc.wal");
        let _ = fs::remove_file(&path);

        // Write valid entry + partial garbage (simulating crash mid-write)
        {
            let mut wal = ConsensusWal::open(&path).unwrap();
            wal.truncate_and_start_height(1, [0; 32]).unwrap();
            wal.write_entry(&WalEntry::Vote {
                height: 1, round: 0, vote_type: 1,
                block_hash: Some([0xCC; 32]),
                signature: vec![],
            }).unwrap();
        }

        // Append partial garbage (crash simulation)
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{\"type\":\"Vote\",\"hei").unwrap(); // truncated JSON
        }

        // Recovery should work, ignoring the partial line
        let state = ConsensusWal::recover(&path).unwrap().unwrap();
        assert_eq!(state.height, 1);
        assert!(state.our_prevote.is_some());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_wal_commit_recovery() {
        let path = tmp_path("test_commit.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = ConsensusWal::open(&path).unwrap();
            wal.truncate_and_start_height(20, [0; 32]).unwrap();
            wal.write_entry(&WalEntry::Commit {
                height: 20, round: 0, block_hash: [0xDD; 32],
            }).unwrap();
        }

        let state = ConsensusWal::recover(&path).unwrap().unwrap();
        assert_eq!(state.committed, Some([0xDD; 32]));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_empty_wal_recovery() {
        let path = tmp_path("test_empty.wal");
        let _ = fs::remove_file(&path);

        // Non-existent file
        let state = ConsensusWal::recover(&path).unwrap();
        assert!(state.is_none());

        // Empty file
        File::create(&path).unwrap();
        let state = ConsensusWal::recover(&path).unwrap();
        assert!(state.is_none());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_ledger_snapshot_roundtrip() {
        let path = tmp_path("test_snap.json");
        let _ = fs::remove_file(&path);

        let mut balances = std::collections::HashMap::new();
        balances.insert("aa".repeat(32), 1000);
        balances.insert("bb".repeat(32), 2000);

        let snap = LedgerSnapshot {
            height: 42,
            block_hash: [0xFF; 32],
            treasury: 999_000,
            total_supply: 1_000_000,
            total_fee_rewards: 500,
            total_admin_distributed: 500,
            admin_nonce: 7,
            balances,
        };

        snap.save(&path).unwrap();
        let loaded = LedgerSnapshot::load(&path).unwrap().unwrap();

        assert_eq!(loaded.height, 42);
        assert_eq!(loaded.treasury, 999_000);
        assert_eq!(loaded.admin_nonce, 7);
        assert_eq!(loaded.balances.len(), 2);

        let _ = fs::remove_file(&path);
    }
}
