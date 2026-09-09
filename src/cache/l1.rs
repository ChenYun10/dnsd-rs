//! L1 cache: process-local, sharded in-memory store of raw DNS response bytes.
//!
//! 64 shards so there is no single global lock. Entries store the packed wire
//! bytes (not parsed messages) so a cache hit is a cheap clone + ID patch.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const SHARDS: usize = 64;

struct Entry {
    raw: Vec<u8>,
    stored_secs: i64,
    ttl_secs: i64, // capped at max_ttl
}

struct Shard {
    m: Mutex<Vec<(String, Entry)>>,
}

impl Shard {
    fn new() -> Self {
        Shard {
            m: Mutex::new(Vec::new()),
        }
    }
}

pub struct L1Cache {
    shards: Vec<Shard>,
    max_per_shard: usize,
    max_ttl_secs: i64,
}

impl L1Cache {
    pub fn new(max_entries: usize, max_ttl_secs: i64) -> Self {
        let max_entries = if max_entries == 0 {
            131072
        } else {
            max_entries
        };
        let max_ttl_secs = if max_ttl_secs <= 0 { 60 } else { max_ttl_secs };
        let max_per_shard = (max_entries / SHARDS).max(64);
        L1Cache {
            shards: (0..SHARDS).map(|_| Shard::new()).collect(),
            max_per_shard,
            max_ttl_secs,
        }
    }

    #[inline]
    fn shard(&self, key: &str) -> &Shard {
        &self.shards[fnv32(key.as_bytes()) as usize % SHARDS]
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let s = self.shard(key);
        let now = now_secs();
        let mut m = s.m.lock().unwrap();
        // linear scan; entries are small in count per shard and we evict inline
        for i in 0..m.len() {
            let (k, e) = &m[i];
            if k == key {
                if now - e.stored_secs < e.ttl_secs && now - e.stored_secs < self.max_ttl_secs {
                    let raw = e.raw.clone();
                    return Some(raw);
                }
                // expired — remove
                m.swap_remove(i);
                return None;
            }
        }
        None
    }

    pub fn put(&self, key: &str, raw: Vec<u8>, ttl_secs: i64) {
        if ttl_secs <= 0 {
            return;
        }
        let ttl = ttl_secs.min(self.max_ttl_secs);
        let s = self.shard(key);
        let now = now_secs();
        let mut m = s.m.lock().unwrap();

        // evict expired first if full
        if m.len() >= self.max_per_shard {
            m.retain(|(_, e)| {
                now - e.stored_secs < e.ttl_secs && now - e.stored_secs < self.max_ttl_secs
            });
        }
        // if still full, drop one arbitrary entry
        if m.len() >= self.max_per_shard {
            m.swap_remove(0);
        }

        let entry = Entry {
            raw,
            stored_secs: now,
            ttl_secs: ttl,
        };
        // replace existing key in place if present
        for (k, e) in m.iter_mut() {
            if k == key {
                *e = entry;
                return;
            }
        }
        m.push((key.to_string(), entry));
    }

    pub fn del(&self, key: &str) {
        let s = self.shard(key);
        let mut m = s.m.lock().unwrap();
        m.retain(|(k, _)| k != key);
    }

    pub fn purge_prefix(&self, prefix: &str) -> usize {
        let mut n = 0;
        for s in &self.shards {
            let mut m = s.m.lock().unwrap();
            let before = m.len();
            m.retain(|(k, _)| !k.starts_with(prefix));
            n += before - m.len();
        }
        n
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.m.lock().unwrap().len()).sum()
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn fnv32(data: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_hit() {
        let c = L1Cache::new(1024, 60);
        c.put("k", b"v".to_vec(), 30);
        assert_eq!(c.get("k").unwrap(), b"v");
    }

    #[test]
    fn expired_miss() {
        let c = L1Cache::new(1024, 60);
        c.put("k", b"v".to_vec(), 0);
        assert!(c.get("k").is_none());
    }
}
