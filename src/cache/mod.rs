//! Tiered cache: L1 (process RAM) → L2 (self-built embedded KV) → L3 (Redis).

pub mod l1;
pub mod l2;
pub mod redis;

use crate::config::Config;
use l1::L1Cache;
use l2::L2Store;
use redis::Redis;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;

pub struct TieredCache {
    l1: L1Cache,
    l2: Arc<L2Store>,
    l3: Option<Arc<Redis>>,
    l3_tx: Option<Sender<(String, Vec<u8>, i64)>>,
}

impl TieredCache {
    pub fn new(cfg: &Config) -> Arc<TieredCache> {
        let l1 = L1Cache::new(cfg.l1_max_entries, cfg.l1_ttl_secs as i64);
        let l2 = L2Store::open(&cfg.l2_path, cfg.l2_max_bytes).unwrap_or_else(|e| {
            tracing::warn!("L2 store open failed (cache disabled): {}", e);
            // fall back to an in-memory-only throwaway store under temp
            L2Store::open(
                &std::env::temp_dir().join("dnsd-l2-fallback"),
                cfg.l2_max_bytes,
            )
            .unwrap()
        });

        // L3 (Redis): optional. Failures are non-fatal — it is the backup tier.
        let mut l3 = None;
        let mut l3_tx = None;
        if !cfg.redis_addr.is_empty() {
            match Redis::connect(&cfg.redis_addr) {
                Ok(c) => {
                    let c = Arc::new(c);
                    let (tx, rx) = channel::<(String, Vec<u8>, i64)>();
                    let writer = Arc::clone(&c);
                    std::thread::spawn(move || {
                        while let Ok((k, v, ttl)) = rx.recv() {
                            if let Err(e) = writer.set(&k, &v, ttl) {
                                tracing::debug!("L3 redis set failed: {}", e);
                            }
                        }
                    });
                    l3_tx = Some(tx);
                    l3 = Some(c);
                }
                Err(e) => tracing::warn!("L3 redis unavailable ({}): continuing without L3", e),
            }
        }

        Arc::new(TieredCache { l1, l2, l3, l3_tx })
    }

    /// Look up a key, promoting hits toward L1. Returns raw response bytes.
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        if let Some(v) = self.l1.get(key) {
            return Some(v);
        }
        if let Some(v) = self.l2.get(key) {
            // promote to L1 (best-effort TTL: store with a short cap)
            self.l1.put(key, v.clone(), 60);
            return Some(v);
        }
        if let Some(l3) = &self.l3 {
            if let Ok(Some(v)) = l3.get(key) {
                self.l2.put(key, &v, 60).ok();
                self.l1.put(key, v.clone(), 60);
                return Some(v);
            }
        }
        None
    }

    /// Store an entry in all tiers. `ttl_secs` is the DNS-derived TTL.
    pub fn put(&self, key: &str, raw: Vec<u8>, ttl_secs: i64) {
        if ttl_secs <= 0 {
            return;
        }
        self.l1.put(key, raw.clone(), ttl_secs);
        let _ = self.l2.put(key, &raw, ttl_secs);
        if let Some(tx) = &self.l3_tx {
            // fire-and-forget (unbounded channel: send never blocks)
            let _ = tx.send((key.to_string(), raw, ttl_secs));
        }
    }

    pub fn del(&self, key: &str) {
        self.l1.del(key);
        self.l2.delete(key);
        if let Some(l3) = &self.l3 {
            let _ = l3.del(key);
        }
    }

    pub fn purge_prefix(&self, prefix: &str) -> usize {
        let n = self.l1.purge_prefix(prefix);
        tracing::info!("cache purge prefix {:?}: {} L1 entries evicted", prefix, n);
        n
    }

    pub fn stats(&self) -> (usize, usize) {
        (self.l1.len(), self.l2.len())
    }
}
