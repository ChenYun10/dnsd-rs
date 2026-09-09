//! L2 cache: a self-built, embedded, persistent key-value store.
//!
//! Design: Bitcask-style append-only log + in-memory hash index, with
//! compaction. This is the "自建 Rust 高性能数据库" — a durable on-disk cache
//! that is much larger than L1 (RAM) and independent of Redis (L3).
//!
//! Record layout (little-endian):
//!   magic:u8(0xA5) key_len:u32 val_len:u32 expire_at_ms:i64 crc:u32 key val
//!
//! A single `Mutex<Inner>` guards index + file handles. L1 absorbs the hot
//! path, so L2 is only hit on L1 miss — single-lock contention is negligible,
//! and it removes all lock-ordering/deadlock risk.
//!
//! Writes are one `write_all` syscall (OS page-cache absorbed, no fsync); a
//! torn tail after a crash is detected by checksum and dropped on replay. A
//! background thread compacts when dead bytes exceed a threshold.

use crate::error::{Error, Result};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: u8 = 0xA5;
const HEADER_LEN: usize = 1 + 4 + 4 + 8 + 4; // 21 bytes

#[derive(Clone, Copy)]
struct IndexEntry {
    offset: u64,
    val_len: u32,
    expire_at_ms: i64,
}

struct Inner {
    index: HashMap<String, IndexEntry>,
    write_file: File,
    read_file: File,
    size: u64,
    dead_bytes: u64,
}

pub struct L2Store {
    dir: PathBuf,
    inner: Mutex<Inner>,
    max_file_bytes: u64,
}

impl L2Store {
    pub fn open(dir: &Path, max_file_bytes: u64) -> Result<Arc<L2Store>> {
        fs::create_dir_all(dir).map_err(Error::Io)?;
        let path = dir.join("data.log");

        let mut index = HashMap::new();
        if path.exists() {
            replay(&path, &mut index)?;
        }

        let write_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(Error::Io)?;
        let size = write_file.metadata().map(|m| m.len()).unwrap_or(0);
        let read_file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(Error::Io)?;

        let store = Arc::new(L2Store {
            dir: dir.to_path_buf(),
            inner: Mutex::new(Inner {
                index,
                write_file,
                read_file,
                size,
                dead_bytes: 0,
            }),
            max_file_bytes: max_file_bytes.max(16 * 1024 * 1024),
        });

        let s2 = Arc::clone(&store);
        std::thread::spawn(move || compaction_loop(s2));

        Ok(store)
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock().unwrap();
        let ent = *inner.index.get(key)?;
        let now = now_ms();
        if ent.expire_at_ms != 0 && now >= ent.expire_at_ms {
            return None; // expired; dropped on next compaction
        }
        if inner.read_file.seek(SeekFrom::Start(ent.offset)).is_err() {
            return None;
        }
        let mut hdr = [0u8; HEADER_LEN];
        if inner.read_file.read_exact(&mut hdr).is_err() {
            return None;
        }
        if hdr[0] != MAGIC {
            return None;
        }
        let key_len = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        let val_len = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
        let mut body = vec![0u8; key_len + val_len];
        if inner.read_file.read_exact(&mut body).is_err() {
            return None;
        }
        Some(body[key_len..].to_vec())
    }

    pub fn put(&self, key: &str, val: &[u8], ttl_secs: i64) -> Result<()> {
        if ttl_secs <= 0 {
            return Ok(());
        }
        let expire_at_ms = now_ms() + ttl_secs * 1000;

        let mut rec = Vec::with_capacity(HEADER_LEN + key.len() + val.len());
        rec.push(MAGIC);
        rec.extend_from_slice(&(key.len() as u32).to_le_bytes());
        rec.extend_from_slice(&(val.len() as u32).to_le_bytes());
        rec.extend_from_slice(&expire_at_ms.to_le_bytes());
        let expire_bytes = expire_at_ms.to_le_bytes();
        let mut crc_input = Vec::with_capacity(key.len() + val.len() + 8);
        crc_input.extend_from_slice(key.as_bytes());
        crc_input.extend_from_slice(val);
        crc_input.extend_from_slice(&expire_bytes);
        let crc = fnv64(&crc_input);
        rec.extend_from_slice(&(crc as u32).to_le_bytes());
        rec.extend_from_slice(key.as_bytes());
        rec.extend_from_slice(val);

        let mut inner = self.inner.lock().unwrap();
        let off = inner.size;
        inner.write_file.write_all(&rec).map_err(Error::Io)?;
        inner.size += rec.len() as u64;

        if let Some(old) = inner.index.insert(
            key.to_string(),
            IndexEntry {
                offset: off,
                val_len: val.len() as u32,
                expire_at_ms,
            },
        ) {
            inner.dead_bytes += HEADER_LEN as u64 + key.len() as u64 + old.val_len as u64;
        }
        Ok(())
    }

    pub fn delete(&self, key: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(old) = inner.index.remove(key) {
            inner.dead_bytes += HEADER_LEN as u64 + key.len() as u64 + old.val_len as u64;
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().index.len()
    }

    pub fn file_size(&self) -> u64 {
        self.inner.lock().unwrap().size
    }

    fn compact(&self) -> Result<()> {
        let tmp = self.dir.join("data.log.tmp");
        let data_path = self.dir.join("data.log");

        // Collect live offsets, then write compacted file with a fresh handle.
        let live_offsets: HashSet<u64> = {
            let inner = self.inner.lock().unwrap();
            let now = now_ms();
            inner
                .index
                .iter()
                .filter(|(_, e)| e.expire_at_ms == 0 || now < e.expire_at_ms)
                .map(|(_, e)| e.offset)
                .collect()
        };

        let mut new_index: HashMap<String, IndexEntry> = HashMap::new();
        let new_size: u64 = {
            let tmp_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .map_err(Error::Io)?;
            let mut w = tmp_file;
            let src = File::open(&data_path).map_err(Error::Io)?;
            let mut r = BufReader::new(src);
            let mut read_offset: u64 = 0;
            let mut offset: u64 = 0;
            while let Some(rec) = read_record(&mut r, &mut read_offset)? {
                if !live_offsets.contains(&rec.offset) {
                    continue;
                }
                w.write_all(&rec.raw).map_err(Error::Io)?;
                new_index.insert(
                    rec.key.clone(),
                    IndexEntry {
                        offset,
                        val_len: rec.val_len,
                        expire_at_ms: rec.expire_at_ms,
                    },
                );
                offset += rec.raw.len() as u64;
            }
            w.flush().map_err(Error::Io)?;
            drop(w);
            offset
        };

        // Swap: close old handles, rename, reopen, replace index.
        {
            let mut inner = self.inner.lock().unwrap();
            // Drop handles so Windows allows the rename.
            inner.write_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&tmp)
                .map_err(Error::Io)?;
            inner.read_file = OpenOptions::new()
                .read(true)
                .open(&tmp)
                .map_err(Error::Io)?;
            // Rename tmp -> data. If it fails, we still hold tmp handles.
            fs::rename(&tmp, &data_path).map_err(Error::Io)?;
            inner.write_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&data_path)
                .map_err(Error::Io)?;
            inner.read_file = OpenOptions::new()
                .read(true)
                .open(&data_path)
                .map_err(Error::Io)?;
            inner.size = new_size;
            inner.dead_bytes = 0;
            inner.index = new_index;
        }
        Ok(())
    }
}

struct RawRecord {
    offset: u64,
    key: String,
    val_len: u32,
    expire_at_ms: i64,
    raw: Vec<u8>,
}

fn read_record(r: &mut BufReader<File>, read_offset: &mut u64) -> Result<Option<RawRecord>> {
    let mut hdr = [0u8; HEADER_LEN];
    let n = r.read(&mut hdr).map_err(Error::Io)?;
    if n == 0 {
        return Ok(None); // EOF
    }
    if n < HEADER_LEN || hdr[0] != MAGIC {
        return Ok(None); // truncated/corrupt tail
    }
    let key_len = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let val_len = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
    let expire_at_ms = i64::from_le_bytes(hdr[9..17].try_into().unwrap());
    let crc = u32::from_le_bytes([hdr[17], hdr[18], hdr[19], hdr[20]]);

    let body_len = key_len + val_len;
    let mut body = vec![0u8; body_len];
    if r.read_exact(&mut body).is_err() {
        return Ok(None); // torn write
    }
    let rec_off = *read_offset;
    *read_offset += HEADER_LEN as u64 + body_len as u64;

    let expire_bytes = expire_at_ms.to_le_bytes();
    let mut crc_input = Vec::with_capacity(body.len() + 8);
    crc_input.extend_from_slice(&body);
    crc_input.extend_from_slice(&expire_bytes);
    let computed = fnv64(&crc_input);
    if (computed as u32) != crc {
        return Ok(None); // corrupt record — stop replay
    }

    let mut raw = Vec::with_capacity(HEADER_LEN + body_len);
    raw.extend_from_slice(&hdr);
    raw.extend_from_slice(&body);

    Ok(Some(RawRecord {
        offset: rec_off,
        key: String::from_utf8_lossy(&body[..key_len]).to_string(),
        val_len: val_len as u32,
        expire_at_ms,
        raw,
    }))
}

fn replay(path: &Path, index: &mut HashMap<String, IndexEntry>) -> Result<()> {
    let f = File::open(path).map_err(Error::Io)?;
    let mut r = BufReader::new(f);
    let mut off: u64 = 0;
    while let Some(rec) = read_record(&mut r, &mut off)? {
        index.insert(
            rec.key,
            IndexEntry {
                offset: rec.offset,
                val_len: rec.val_len,
                expire_at_ms: rec.expire_at_ms,
            },
        );
    }
    Ok(())
}

fn compaction_loop(store: Arc<L2Store>) {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        let (dead, size) = {
            let inner = store.inner.lock().unwrap();
            (inner.dead_bytes, inner.size)
        };
        let should = size > store.max_file_bytes || (dead > size / 2 && dead > 64 * 1024 * 1024);
        if should {
            if let Err(e) = store.compact() {
                tracing::warn!("l2 compaction failed: {}", e);
            }
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get() {
        let dir = std::env::temp_dir().join(format!("l2test-{}", uuid::Uuid::new_v4()));
        let s = L2Store::open(&dir, 1024 * 1024).unwrap();
        s.put("k", b"hello", 60).unwrap();
        assert_eq!(s.get("k").unwrap(), b"hello");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("l2test-{}", uuid::Uuid::new_v4()));
        {
            let s = L2Store::open(&dir, 1024 * 1024).unwrap();
            s.put("k", b"persist", 60).unwrap();
        }
        {
            let s = L2Store::open(&dir, 1024 * 1024).unwrap();
            assert_eq!(s.get("k").unwrap(), b"persist");
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
