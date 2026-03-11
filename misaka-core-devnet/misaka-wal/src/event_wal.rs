// ============================================================
// MISAKA WAL — Generic Binary-Framed Event WAL
// ============================================================
//
// Append-only log for any Serialize + DeserializeOwned type.
//
// Entry format:
//   | length (u32 LE) | crc32 (u32 LE) | json_bytes |
//
// Properties:
//   - Deterministic encoding (serde_json)
//   - CRC32 corruption detection per entry
//   - fsync after each append
//   - Truncated/corrupted entries detected and skipped on replay
//   - Append-only (no in-place edits)
//
// ============================================================

use crate::WalError;
use serde::{Serialize, de::DeserializeOwned};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};

// ════════════════════════════════════════════
// CRC32 (IEEE 802.3)
// ════════════════════════════════════════════

/// CRC32 lookup table (IEEE polynomial 0xEDB88320).
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

/// Compute CRC32 checksum of a byte slice.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        let idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    crc ^ 0xFFFFFFFF
}

// ════════════════════════════════════════════
// EventWal writer
// ════════════════════════════════════════════

/// Generic binary-framed WAL writer.
///
/// Each entry: `| length: u32 LE | crc32: u32 LE | json_bytes |`
///
/// Written atomically (length+checksum+body), then fsync'd.
pub struct EventWal {
    file: File,
    path: PathBuf,
}

impl EventWal {
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

    /// Append a serializable event to the WAL and fsync.
    ///
    /// CRITICAL: Must complete BEFORE the corresponding state mutation.
    pub fn append_event<T: Serialize>(&mut self, event: &T) -> Result<(), WalError> {
        let json = serde_json::to_vec(event)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let len = json.len() as u32;
        let checksum = crc32(&json);

        // Write atomically: header + body
        let mut buf = Vec::with_capacity(8 + json.len());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&checksum.to_le_bytes());
        buf.extend_from_slice(&json);

        self.file.write_all(&buf)?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Truncate the WAL and optionally write a first event.
    ///
    /// Used at the start of a new height to discard old entries.
    pub fn truncate_and_write<T: Serialize>(&mut self, first_event: &T) -> Result<(), WalError> {
        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        self.append_event(first_event)
    }

    /// Truncate the WAL completely (no initial event).
    pub fn truncate(&mut self) -> Result<(), WalError> {
        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Get the file path.
    pub fn path(&self) -> &Path { &self.path }
}

// ════════════════════════════════════════════
// EventWal reader / replay
// ════════════════════════════════════════════

/// Replay all valid events from a WAL file.
///
/// Reads sequentially, verifies CRC32 per entry.
/// Stops at first corrupted or truncated entry (crash tolerance).
///
/// Returns events in order of insertion.
pub fn replay_events<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>, WalError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut events = Vec::new();
    let mut pos: u64 = 0;

    loop {
        // Need at least 8 bytes for header
        if pos + 8 > file_len {
            break;
        }

        // Read header
        let mut header = [0u8; 8];
        file.seek(SeekFrom::Start(pos))?;
        if file.read_exact(&mut header).is_err() {
            break;
        }

        let len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let expected_crc = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

        // Sanity: reject absurdly large entries
        if len > 10 * 1024 * 1024 {
            break;
        }

        // Need len more bytes for body
        if pos + 8 + (len as u64) > file_len {
            break; // Truncated entry — crash mid-write
        }

        // Read body
        let mut body = vec![0u8; len];
        if file.read_exact(&mut body).is_err() {
            break;
        }

        // Verify checksum
        let actual_crc = crc32(&body);
        if actual_crc != expected_crc {
            break; // Corrupted entry
        }

        // Deserialize
        match serde_json::from_slice::<T>(&body) {
            Ok(event) => events.push(event),
            Err(_) => break, // Corrupted data
        }

        pos += 8 + (len as u64);
    }

    Ok(events)
}

/// Truncate a WAL file to the last valid entry offset.
///
/// Useful after detecting corruption: truncate to the end of the
/// last valid entry so new appends start clean.
pub fn truncate_to_valid(path: &Path, valid_bytes: u64) -> Result<(), WalError> {
    let file = OpenOptions::new()
        .write(true)
        .open(path)?;
    file.set_len(valid_bytes)?;
    file.sync_all()?;
    Ok(())
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Serialize, Deserialize};
    use std::fs;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "type")]
    enum TestEvent {
        Alpha { value: u32 },
        Beta { name: String },
        Gamma { data: Vec<u8> },
    }

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("misaka_event_wal_test");
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn test_append_and_replay() {
        let path = tmp_path("test_basic.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = EventWal::open(&path).unwrap();
            wal.append_event(&TestEvent::Alpha { value: 42 }).unwrap();
            wal.append_event(&TestEvent::Beta { name: "hello".into() }).unwrap();
            wal.append_event(&TestEvent::Gamma { data: vec![1, 2, 3] }).unwrap();
        }

        let events: Vec<TestEvent> = replay_events(&path).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], TestEvent::Alpha { value: 42 });
        assert_eq!(events[1], TestEvent::Beta { name: "hello".into() });
        assert_eq!(events[2], TestEvent::Gamma { data: vec![1, 2, 3] });

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_replay_correct_order() {
        let path = tmp_path("test_order.wal");
        let _ = fs::remove_file(&path);

        {
            let mut wal = EventWal::open(&path).unwrap();
            for i in 0..10 {
                wal.append_event(&TestEvent::Alpha { value: i }).unwrap();
            }
        }

        let events: Vec<TestEvent> = replay_events(&path).unwrap();
        assert_eq!(events.len(), 10);
        for (i, e) in events.iter().enumerate() {
            assert_eq!(*e, TestEvent::Alpha { value: i as u32 });
        }

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_crash_mid_write_recovery() {
        let path = tmp_path("test_crash.wal");
        let _ = fs::remove_file(&path);

        // Write two valid events
        {
            let mut wal = EventWal::open(&path).unwrap();
            wal.append_event(&TestEvent::Alpha { value: 1 }).unwrap();
            wal.append_event(&TestEvent::Alpha { value: 2 }).unwrap();
        }

        // Append partial garbage (simulate crash mid-write)
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            // Write a header claiming 100 bytes but only write 5
            f.write_all(&100u32.to_le_bytes()).unwrap();
            f.write_all(&0u32.to_le_bytes()).unwrap();
            f.write_all(b"parti").unwrap(); // only 5 of 100 bytes
        }

        // Replay should recover the two valid events
        let events: Vec<TestEvent> = replay_events(&path).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], TestEvent::Alpha { value: 1 });
        assert_eq!(events[1], TestEvent::Alpha { value: 2 });

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_corrupted_checksum_stops_replay() {
        let path = tmp_path("test_corrupt.wal");
        let _ = fs::remove_file(&path);

        // Write valid event
        {
            let mut wal = EventWal::open(&path).unwrap();
            wal.append_event(&TestEvent::Alpha { value: 1 }).unwrap();
        }

        // Corrupt: write entry with wrong checksum
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            let json = serde_json::to_vec(&TestEvent::Alpha { value: 99 }).unwrap();
            f.write_all(&(json.len() as u32).to_le_bytes()).unwrap();
            f.write_all(&0xDEADBEEFu32.to_le_bytes()).unwrap(); // bad checksum
            f.write_all(&json).unwrap();
        }

        // Write another valid event after the corrupt one
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            let json = serde_json::to_vec(&TestEvent::Alpha { value: 3 }).unwrap();
            let crc = crc32(&json);
            f.write_all(&(json.len() as u32).to_le_bytes()).unwrap();
            f.write_all(&crc.to_le_bytes()).unwrap();
            f.write_all(&json).unwrap();
        }

        // Replay stops at the corrupt entry — event 3 is NOT recovered
        let events: Vec<TestEvent> = replay_events(&path).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], TestEvent::Alpha { value: 1 });

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_empty_file_replay() {
        let path = tmp_path("test_empty.wal");
        let _ = fs::remove_file(&path);

        // Non-existent
        let events: Vec<TestEvent> = replay_events(&path).unwrap();
        assert!(events.is_empty());

        // Empty file
        File::create(&path).unwrap();
        let events: Vec<TestEvent> = replay_events(&path).unwrap();
        assert!(events.is_empty());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_truncate_and_write() {
        let path = tmp_path("test_trunc_write.wal");
        let _ = fs::remove_file(&path);

        let mut wal = EventWal::open(&path).unwrap();
        wal.append_event(&TestEvent::Alpha { value: 1 }).unwrap();
        wal.append_event(&TestEvent::Alpha { value: 2 }).unwrap();

        // Truncate and write new first event
        wal.truncate_and_write(&TestEvent::Beta { name: "fresh".into() }).unwrap();

        let events: Vec<TestEvent> = replay_events(&path).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], TestEvent::Beta { name: "fresh".into() });

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_crc32_known_vectors() {
        // "123456789" → 0xCBF43926 (standard CRC32 test vector)
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b""), 0x00000000);
        assert_eq!(crc32(b"a"), 0xE8B7BE43);
    }
}
