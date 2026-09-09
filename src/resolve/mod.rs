//! The DNS request pipeline: parse → validate → rate limit → ECS → block →
//! custom zone → cache(L1→L2→L3) → recursive resolve → ECS echo → log.

pub mod block;
pub mod custom;
pub mod dualstack;
pub mod qqwry;
pub mod recurse;

use crate::cache::TieredCache;
use crate::config::Config;
use crate::error::Result;
use crate::model::{BlockMode, DualstackBinding, QueryLogRow, Zone, ZoneRecord};
use crate::proto::{self, canonical_name, Message, RData};
use crate::proto::{RCODE_REFUSED, RCODE_SERVFAIL};
use crate::store::QueryLogWriter;
use block::BlockList;
use custom::ZoneIndex;
use dualstack::Dualstack;
use recurse::Resolver;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

pub struct Pipeline {
    cfg: Arc<Config>,
    resolver: Resolver,
    cache: Arc<TieredCache>,
    logger: QueryLogWriter,
    dualstack: Dualstack,
    // hot-reloadable policy state
    policy: RwLock<Policy>,
    limiter: Limiter,
}

struct Policy {
    block: BlockList,
    zones: ZoneIndex,
}

pub struct RespMeta {
    pub rcode: String,
    pub cache_hit: bool,
    pub upstream: String,
    pub rtt_ms: i64,
    pub blocked: bool,
    pub qname: String,
    pub qtype: String,
    pub ecs: String,
}

impl Pipeline {
    pub fn new(
        cfg: Arc<Config>,
        cache: Arc<TieredCache>,
        resolver: Resolver,
        logger: QueryLogWriter,
        dualstack: Dualstack,
    ) -> Pipeline {
        Pipeline {
            cfg: cfg.clone(),
            resolver,
            cache,
            logger,
            dualstack,
            policy: RwLock::new(Policy {
                block: BlockList::empty(),
                zones: ZoneIndex::empty(),
            }),
            limiter: Limiter::new(cfg.rate_limit_qps),
        }
    }

    /// Reload policy tables (blocklist + zones) from MySQL.
    pub fn reload(
        &self,
        zones: Vec<Zone>,
        records: Vec<ZoneRecord>,
        blocked: Vec<crate::model::BlockedDomain>,
    ) {
        let mut p = self.policy.write().unwrap();
        p.block = BlockList::new(blocked);
        p.zones = ZoneIndex::new(zones, records);
    }

    /// Reload dualstack bindings.
    pub fn reload_bindings(&self, bindings: &[DualstackBinding]) {
        self.dualstack.reload(bindings);
    }

    /// Cache stats (L1 entries, L2 entries) for the management API.
    pub fn cache_stats(&self) -> (usize, usize) {
        self.cache.stats()
    }

    /// Handle a raw DNS query, returning the raw response bytes.
    pub fn handle(&self, raw: &[u8], client_ip: IpAddr, via: &str) -> Vec<u8> {
        let start = Instant::now();
        let mut meta = RespMeta {
            rcode: "SERVFAIL".into(),
            cache_hit: false,
            upstream: String::new(),
            rtt_ms: 0,
            blocked: false,
            qname: String::new(),
            qtype: String::new(),
            ecs: String::new(),
        };

        let resp = self.process(raw, client_ip, via, &mut meta);
        meta.rtt_ms = start.elapsed().as_millis() as i64;

        self.logger.write(QueryLogRow {
            ts_ms: crate::store::logs::now_ms(),
            client_ip: client_ip.to_string(),
            ecs: meta.ecs.clone(),
            qname: meta.qname.clone(),
            qtype: meta.qtype.clone(),
            rcode: meta.rcode.clone(),
            cache_hit: meta.cache_hit,
            upstream: meta.upstream.clone(),
            rtt_ms: meta.rtt_ms,
            blocked: meta.blocked,
            via: via.to_string(),
        });

        resp
    }

    fn process(&self, raw: &[u8], client_ip: IpAddr, _via: &str, meta: &mut RespMeta) -> Vec<u8> {
        // 1. parse
        let req = match Message::parse(raw) {
            Ok(m) => m,
            Err(_) => return self.refuse(raw, meta),
        };
        if req.header.qr {
            return Vec::new(); // not a query
        }
        let Some(q) = req.question().cloned() else {
            return self.refuse(raw, meta);
        };
        meta.qname = canonical_name(&q.name);
        meta.qtype = proto::type_to_string(q.qtype);

        // 2. protocol hygiene
        if q.name.len() > 253 {
            return self.refuse(raw, meta);
        }
        if let Some(opt) = req.edns() {
            if let RData::Opt { version, .. } = &opt.data {
                if *version != 0 {
                    return self.badvers(&req, meta);
                }
            }
        }

        // 3. rate limit
        if !self.limiter.allow(client_ip) {
            meta.rcode = "REFUSED".into();
            return encode_rcode(&req, RCODE_REFUSED, meta);
        }

        // 4. ECS extract + clamp + dualstack derive
        let mut ecs = req.ecs();
        if let Some(e) = ecs.as_mut() {
            e.clamp_scope(self.cfg.ecs_scope_max);
        }
        // derive client IPv4 from an internal IPv6 client
        if self.cfg.dualstack_enabled && client_ip.is_ipv6() && ecs.is_none() {
            if let Ok(v6) = ipv6_of(&client_ip) {
                if let Some(derived) = self.dualstack.derive_ecs(v6) {
                    ecs = Some(derived);
                }
            }
        }
        let ecs_token = ecs.as_ref().map(|e| e.cache_token()).unwrap_or_default();
        meta.ecs = ecs_token.clone();

        // 5. block check
        let block_mode = self.policy.read().unwrap().block.mode_for(&q.name);
        if let Some(mode) = block_mode {
            let mut resp = {
                let p = self.policy.read().unwrap();
                p.block.respond(&q, &client_ip, mode)
            };
            resp.header.id = req.header.id;
            meta.blocked = true;
            meta.rcode = "NOERROR".into();
            meta.upstream = if mode == BlockMode::Loopback {
                "block-loopback"
            } else {
                "block-random"
            }
            .into();
            return encode(&resp, meta);
        }

        // 6. custom zone
        if let Some(resp) = {
            let p = self.policy.read().unwrap();
            p.zones.respond(&q)
        } {
            let mut resp = resp;
            resp.header.id = req.header.id;
            meta.rcode = proto::rcode_to_string(resp.header.rcode);
            meta.upstream = "zone".into();
            return encode(&resp, meta);
        }

        // 7. cache lookup
        let cache_key = cache_key(&q.name, q.qtype, &ecs_token);
        if let Some(hit) = self.cache.get(&cache_key) {
            let mut bytes = hit;
            patch_id(&mut bytes, req.header.id);
            meta.cache_hit = true;
            meta.rcode = "NOERROR".into(); // refined below if parseable
            if let Ok(m) = Message::parse(&bytes) {
                meta.rcode = proto::rcode_to_string(m.header.rcode);
            }
            meta.upstream = "cache".into();
            return bytes;
        }

        // 8. recursive resolve
        match self.resolver.resolve(&q.name, q.qtype, ecs.as_ref()) {
            Ok(bytes) => {
                let mut msg = Message::parse(&bytes).unwrap_or_else(|_| Message::default());
                // ECS echo + set client ID
                if let Some(e) = &ecs {
                    proto::echo_ecs(&mut msg, e);
                }
                msg.header.id = req.header.id;
                msg.header.ra = true; // we are a recursive resolver

                let ttl = msg_ttl(&msg, &self.cfg);
                let out = msg.encode().unwrap_or_else(|_| bytes);
                if ttl > 0 {
                    self.cache.put(&cache_key, out.clone(), ttl);
                }
                meta.rcode = proto::rcode_to_string(msg.header.rcode);
                meta.upstream = "recursive".into();
                out
            }
            Err(e) => {
                tracing::debug!("resolve failed for {}: {}", q.name, e);
                let mut resp = Message::default();
                resp.header.id = req.header.id;
                resp.header.qr = true;
                resp.header.rd = true;
                resp.header.ra = true;
                resp.header.rcode = RCODE_SERVFAIL;
                resp.questions = vec![q.clone()];
                meta.rcode = "SERVFAIL".into();
                encode(&resp, meta)
            }
        }
    }

    fn refuse(&self, raw: &[u8], meta: &mut RespMeta) -> Vec<u8> {
        if let Ok(m) = Message::parse(raw) {
            let mut resp = Message::default();
            resp.header.id = m.header.id;
            resp.header.qr = true;
            resp.header.rcode = RCODE_REFUSED;
            resp.questions = m.questions;
            meta.rcode = "REFUSED".into();
            return encode(&resp, meta);
        }
        meta.rcode = "FORMERR".into();
        Vec::new()
    }

    fn badvers(&self, req: &Message, meta: &mut RespMeta) -> Vec<u8> {
        let mut resp = Message::default();
        resp.header.id = req.header.id;
        resp.header.qr = true;
        resp.header.rcode = 16; // BADVERS
        resp.questions = req.questions.clone();
        meta.rcode = "BADVERS".into();
        encode(&resp, meta)
    }
}

fn cache_key(qname: &str, qtype: u16, ecs: &str) -> String {
    format!("{}|{}|{}", canonical_name(qname), qtype, ecs)
}

fn patch_id(bytes: &mut [u8], id: u16) {
    if bytes.len() >= 2 {
        bytes[0] = (id >> 8) as u8;
        bytes[1] = (id & 0xFF) as u8;
    }
}

fn encode(msg: &Message, _meta: &mut RespMeta) -> Vec<u8> {
    msg.encode().unwrap_or_default()
}

fn encode_rcode(req: &Message, rcode: u8, _meta: &mut RespMeta) -> Vec<u8> {
    let mut resp = Message::default();
    resp.header.id = req.header.id;
    resp.header.qr = true;
    resp.header.rd = req.header.rd;
    resp.header.ra = true;
    resp.header.rcode = rcode;
    resp.questions = req.questions.clone();
    resp.encode().unwrap_or_default()
}

fn msg_ttl(msg: &Message, cfg: &Config) -> i64 {
    if !msg.answers.is_empty() {
        let min = msg.answers.iter().map(|r| r.ttl).min().unwrap_or(0);
        return min.min(cfg.cache_max_ttl.as_secs() as u32) as i64;
    }
    // negative caching: use SOA minimum if present, else neg_cache_ttl
    for r in &msg.authority {
        if let RData::Soa { minimum, .. } = &r.data {
            return (*minimum as i64).min(cfg.neg_cache_ttl.as_secs() as i64);
        }
    }
    if msg.header.rcode == proto::RCODE_NXDOMAIN {
        return cfg.neg_cache_ttl.as_secs() as i64;
    }
    0
}

fn ipv6_of(ip: &IpAddr) -> Result<std::net::Ipv6Addr> {
    match ip {
        IpAddr::V6(v6) => Ok(*v6),
        _ => Err(crate::error::Error::Config("not ipv6".into())),
    }
}

// ---- simple in-memory token-bucket rate limiter -----------------------------

struct Limiter {
    qps: f64,
    buckets: RwLock<std::collections::HashMap<IpAddr, (f64, Instant)>>,
}

impl Limiter {
    fn new(qps: u32) -> Limiter {
        Limiter {
            qps: qps.max(1) as f64,
            buckets: RwLock::new(std::collections::HashMap::new()),
        }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        if self.qps <= 0.0 {
            return true;
        }
        let mut b = self.buckets.write().unwrap();
        // opportunistic cleanup
        if b.len() > 65536 {
            b.retain(|_, (_, last)| last.elapsed().as_secs() < 300);
        }
        let now = Instant::now();
        let e = b.entry(ip).or_insert((self.qps, now));
        let (tokens, last) = *e;
        let elapsed = now.duration_since(last).as_secs_f64();
        let tokens = (tokens + elapsed * self.qps).min(self.qps);
        if tokens < 1.0 {
            *e = (tokens, now);
            return false;
        }
        *e = (tokens - 1.0, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::TYPE_A;

    #[test]
    fn cache_key_stability() {
        assert_eq!(
            cache_key("Example.COM", TYPE_A, ""),
            cache_key("example.com.", TYPE_A, "")
        );
    }

    #[test]
    fn limiter_allows_then_blocks() {
        let l = Limiter::new(2);
        let ip = "1.2.3.4".parse().unwrap();
        assert!(l.allow(ip));
        assert!(l.allow(ip));
        assert!(!l.allow(ip));
    }
}
