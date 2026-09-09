//! Query log (等保) and tamper-evident audit log writers.
//!
//! - QueryLogWriter: asynchronous, batched, non-blocking insert into MySQL.
//! - AuditWriter: append-only with a SHA-256 hash chain (prev_hash chaining)
//!   so the audit trail is tamper-evident, as required by 等保 compliance.

use super::Store;
use crate::error::{Error, Result};
use crate::model::{AuditRow, QueryLogRow};
use mysql::prelude::Queryable;
use sha2::{Digest, Sha256};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ---- query log -------------------------------------------------------------

#[derive(Clone)]
pub struct QueryLogWriter {
    tx: Option<Sender<QueryLogRow>>,
}

impl QueryLogWriter {
    pub fn new(store: Store, batch_size: usize, flush_interval: Duration) -> QueryLogWriter {
        if !store.available() {
            tracing::warn!("query logging disabled (no MySQL)");
            return QueryLogWriter { tx: None };
        }
        let (tx, rx) = channel::<QueryLogRow>();
        let writer = QueryLogWriter { tx: Some(tx) };
        let store = Arc::new(store);
        std::thread::spawn(move || flush_loop(store, rx, batch_size, flush_interval));
        writer
    }

    /// Non-blocking enqueue (unbounded channel: send never blocks).
    pub fn write(&self, row: QueryLogRow) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(row);
        }
    }
}

fn flush_loop(store: Arc<Store>, rx: Receiver<QueryLogRow>, batch_size: usize, interval: Duration) {
    let mut buf: Vec<QueryLogRow> = Vec::with_capacity(batch_size);
    let mut last_flush = std::time::Instant::now();

    loop {
        let deadline = interval.saturating_sub(last_flush.elapsed());
        match rx.recv_timeout(if deadline.is_zero() {
            Duration::from_millis(1)
        } else {
            deadline
        }) {
            Ok(row) => {
                buf.push(row);
                if buf.len() >= batch_size {
                    flush_batch(&store, &mut buf);
                    last_flush = std::time::Instant::now();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if !buf.is_empty() {
                    flush_batch(&store, &mut buf);
                }
                last_flush = std::time::Instant::now();
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if !buf.is_empty() {
                    flush_batch(&store, &mut buf);
                }
                return;
            }
        }
    }
}

fn flush_batch(store: &Store, buf: &mut Vec<QueryLogRow>) {
    if buf.is_empty() {
        return;
    }
    let rows: Vec<QueryLogRow> = std::mem::take(buf);
    if let Err(e) = insert_query_batch(store, &rows) {
        tracing::warn!(
            "query log batch insert failed ({} rows dropped): {}",
            rows.len(),
            e
        );
    }
}

fn insert_query_batch(store: &Store, rows: &[QueryLogRow]) -> Result<()> {
    let mut c = store.conn()?;
    let stmt = "INSERT INTO query_logs \
                (ts_ms, client_ip, ecs, qname, qtype, rcode, cache_hit, upstream, rtt_ms, blocked, via) \
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    c.exec_batch(
        stmt,
        rows.iter().map(|r| {
            (
                r.ts_ms,
                r.client_ip.clone(),
                r.ecs.clone(),
                r.qname.clone(),
                r.qtype.clone(),
                r.rcode.clone(),
                r.cache_hit,
                r.upstream.clone(),
                r.rtt_ms,
                r.blocked,
                r.via.clone(),
            )
        }),
    )
    .map_err(Error::from)?;
    Ok(())
}

// ---- audit log (hash chain) -------------------------------------------------

pub struct AuditWriter {
    store: Arc<Store>,
    prev_hash: Mutex<String>,
    verifier: String,
}

impl AuditWriter {
    pub fn new(store: Store, verifier: &str) -> Arc<AuditWriter> {
        let prev_hash = last_entry_hash(&store).unwrap_or_else(|_| GENESIS.to_string());
        Arc::new(AuditWriter {
            store: Arc::new(store),
            prev_hash: Mutex::new(prev_hash),
            verifier: verifier.to_string(),
        })
    }

    pub fn record(&self, actor: &str, action: &str, target: &str, detail: &str, client_ip: &str) {
        if !self.store.available() {
            return;
        }
        let ts_ms = now_ms();
        let mut prev = self.prev_hash.lock().unwrap();
        let entry_hash = compute_hash(&prev, ts_ms, actor, action, target, detail, client_ip);

        let result: Result<()> = (|| {
            let mut c = self.store.conn()?;
            c.exec_drop(
                "INSERT INTO audit_logs \
                 (ts_ms, actor, action, target, detail, client_ip, prev_hash, entry_hash, verifier) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ts_ms,
                    actor,
                    action,
                    target,
                    detail,
                    client_ip,
                    prev.as_str(),
                    entry_hash.clone(),
                    self.verifier.clone(),
                ),
            )
            .map_err(Error::from)?;
            Ok(())
        })();

        match result {
            Ok(()) => *prev = entry_hash,
            Err(e) => tracing::warn!("audit log write failed: {}", e),
        }
    }
}

fn last_entry_hash(store: &Store) -> Result<String> {
    let mut c = store.conn()?;
    let row: Option<String> = c
        .exec_first(
            "SELECT entry_hash FROM audit_logs WHERE entry_hash IS NOT NULL \
             ORDER BY id DESC LIMIT 1",
            (),
        )
        .map_err(Error::from)?;
    Ok(row.unwrap_or_else(|| GENESIS.to_string()))
}

pub fn compute_hash(
    prev: &str,
    ts_ms: i64,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
    client_ip: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"|");
    h.update(ts_ms.to_string().as_bytes());
    h.update(b"|");
    h.update(actor.as_bytes());
    h.update(b"|");
    h.update(action.as_bytes());
    h.update(b"|");
    h.update(target.as_bytes());
    h.update(b"|");
    h.update(detail.as_bytes());
    h.update(b"|");
    h.update(client_ip.as_bytes());
    hex_encode(&h.finalize())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Build an AuditRow without writing (used by tests / verification).
pub fn make_audit_row(
    prev: &str,
    ts_ms: i64,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
    client_ip: &str,
) -> AuditRow {
    let entry_hash = compute_hash(prev, ts_ms, actor, action, target, detail, client_ip);
    AuditRow {
        ts_ms,
        actor: actor.to_string(),
        action: action.to_string(),
        target: target.to_string(),
        detail: detail.to_string(),
        client_ip: client_ip.to_string(),
        prev_hash: prev.to_string(),
        entry_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_is_deterministic_and_links() {
        let a = make_audit_row(GENESIS, 1000, "admin", "login", "self", "{}", "1.2.3.4");
        let b = make_audit_row(
            &a.entry_hash,
            1001,
            "admin",
            "logout",
            "self",
            "{}",
            "1.2.3.4",
        );
        assert_ne!(a.entry_hash, b.entry_hash);
        assert_eq!(b.prev_hash, a.entry_hash);
        assert_eq!(a.entry_hash.len(), 64);
    }
}
