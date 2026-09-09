//! Iterative (recursive) DNS resolver: walks from the root servers down to the
//! authoritative nameservers for the queried name.
//!
//! Key behaviours:
//!   - built-in root hints (13 roots, IPv4)
//!   - UDP exchange with timeout, TCP fallback on truncation (RFC 7766)
//!   - NS reachability: try every nameserver in turn; a dead NS is skipped and
//!     the next is used — this is what "确保到目标域名 NS 通联正常" requires.
//!   - glue records from the additional section; out-of-bailiwick NS hostnames
//!     are resolved recursively (bounded).
//!   - CNAME chasing with a bounded chain length.
//!   - in-flight dedup (singleflight) against cache stampedes.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::proto::{
    self, canonical_name, EcsInfo, Message, RData, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_NS,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const ROOT_HINTS: &[&str] = &[
    "198.41.0.4:53",     // a.root-servers.net
    "170.247.170.2:53",  // b.root-servers.net
    "192.33.4.12:53",    // c.root-servers.net
    "199.7.91.13:53",    // d.root-servers.net
    "192.203.230.10:53", // e.root-servers.net
    "192.5.5.241:53",    // f.root-servers.net
    "192.112.36.4:53",   // g.root-servers.net
    "198.97.190.53:53",  // h.root-servers.net
    "192.36.148.17:53",  // i.root-servers.net
    "192.58.128.30:53",  // j.root-servers.net
    "193.0.14.129:53",   // k.root-servers.net
    "199.7.83.42:53",    // l.root-servers.net
    "202.12.27.33:53",   // m.root-servers.net
];

pub struct Resolver {
    cfg: Arc<Config>,
    roots: Vec<SocketAddr>,
    inflight: Mutex<HashMap<String, Arc<Flight>>>,
}

struct Flight {
    state: Mutex<Option<Arc<Resolved>>>,
    started: AtomicBool,
    cond: Condvar,
}

type Resolved = std::result::Result<Vec<u8>, String>;

impl Resolver {
    pub fn new(cfg: Arc<Config>) -> Resolver {
        let mut roots: Vec<SocketAddr> = ROOT_HINTS.iter().filter_map(|s| s.parse().ok()).collect();
        if !cfg.root_hints.is_empty() {
            let parsed: Vec<SocketAddr> = cfg
                .root_hints
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !parsed.is_empty() {
                roots = parsed;
            }
        }
        Resolver {
            cfg,
            roots,
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve a name to a packed response, honouring singleflight.
    pub fn resolve(&self, qname: &str, qtype: u16, ecs: Option<&EcsInfo>) -> Result<Vec<u8>> {
        let key = format!(
            "{}|{}|{}",
            canonical_name(qname),
            qtype,
            ecs.map(|e| e.cache_token()).unwrap_or_default()
        );
        let flight = {
            let mut map = self.inflight.lock().unwrap();
            map.entry(key.clone())
                .or_insert_with(|| {
                    Arc::new(Flight {
                        state: Mutex::new(None),
                        started: AtomicBool::new(false),
                        cond: Condvar::new(),
                    })
                })
                .clone()
        };

        // Become leader if no one has started; otherwise wait for the result.
        if !flight.started.swap(true, Ordering::SeqCst) {
            let result: std::result::Result<Vec<u8>, String> = self
                .do_resolve(qname, qtype, ecs)
                .and_then(|m| m.encode())
                .map_err(|e| e.to_string());
            let arc: Arc<Resolved> = Arc::new(result);
            {
                let mut state = flight.state.lock().unwrap();
                *state = Some(arc.clone());
                flight.cond.notify_all();
            }
            self.inflight.lock().unwrap().remove(&key);
            return arc.as_ref().clone().map_err(|e| Error::Resolver(e));
        }

        // Follower: block until the leader publishes the result.
        let mut state = flight.state.lock().unwrap();
        while state.is_none() {
            state = flight.cond.wait(state).unwrap();
        }
        let arc = state.as_ref().expect("flight state populated").clone();
        drop(state);
        arc.as_ref().clone().map_err(|e| Error::Resolver(e))
    }

    fn do_resolve(&self, qname: &str, qtype: u16, ecs: Option<&EcsInfo>) -> Result<Message> {
        let deadline = Instant::now() + self.cfg.recurse_timeout;
        let mut name = canonical_name(qname);
        let mut chain = 0usize;

        loop {
            let resp = self.iterative(&name, qtype, ecs, deadline)?;

            if resp.header.rcode != 0 || !resp.answers.is_empty() {
                return Ok(resp);
            }
            if resp.answers.is_empty() {
                return Ok(resp); // NODATA
            }
            // CNAME chase: last answer is a CNAME with no A/AAAA following.
            let cname = resp
                .answers
                .iter()
                .rev()
                .find(|r| r.rtype == TYPE_CNAME)
                .and_then(|r| match &r.data {
                    RData::Name(n) => Some(n.clone()),
                    _ => None,
                });
            if let Some(target) = cname {
                chain += 1;
                if chain > self.cfg.recurse_max_depth as usize {
                    return Err(Error::Resolver("CNAME chain too long".into()));
                }
                name = target;
                continue;
            }
            return Ok(resp);
        }
    }

    /// Walk from the roots to the authoritative servers for `name`.
    fn iterative(
        &self,
        name: &str,
        qtype: u16,
        ecs: Option<&EcsInfo>,
        deadline: Instant,
    ) -> Result<Message> {
        let mut servers = self.roots.clone();

        for depth in 0..self.cfg.recurse_max_depth {
            if Instant::now() >= deadline {
                return Err(Error::Resolver("recursion deadline exceeded".into()));
            }

            let resp = self.query_servers(&servers, name, qtype, ecs, deadline)?;

            if !resp.answers.is_empty() || resp.header.rcode == proto::RCODE_NXDOMAIN {
                return Ok(resp);
            }
            if resp.header.rcode != 0 {
                return Ok(resp);
            }

            let referral = extract_referral(&resp);
            if referral.ns_names.is_empty() {
                return Ok(resp); // NODATA or lame delegation
            }

            let bailiwick = bailiwick_of(name);
            let mut next = Vec::new();
            for ns in &referral.ns_names {
                if let Some(addr) = referral.glue.get(ns) {
                    next.push(*addr);
                    continue;
                }
                // No glue: resolve the NS hostname (in- or out-of-bailiwick).
                let a = self.iterative(ns, TYPE_A, None, deadline).ok();
                let mut found = false;
                if let Some(sub) = &a {
                    for addr in a_records(sub) {
                        next.push(addr);
                        found = true;
                    }
                }
                if !found {
                    if let Ok(sub) = self.iterative(ns, TYPE_AAAA, None, deadline) {
                        for addr in aaaa_records(&sub) {
                            next.push(addr);
                        }
                    }
                }
                let _ = &bailiwick;
            }
            if next.is_empty() {
                return Err(Error::Resolver(format!(
                    "no reachable nameservers for {} (depth {})",
                    name, depth
                )));
            }
            servers = next;
        }
        Err(Error::Resolver(format!(
            "max recursion depth exceeded for {}",
            name
        )))
    }

    /// Send the query to each server in turn until one answers; returns the
    /// first valid response. This is the NS reachability / failover path.
    fn query_servers(
        &self,
        servers: &[SocketAddr],
        qname: &str,
        qtype: u16,
        ecs: Option<&EcsInfo>,
        deadline: Instant,
    ) -> Result<Message> {
        let query = proto::build_query(qname, qtype, 0x1d5e, ecs);
        let mut last_err = "no nameservers".to_string();

        for server in servers {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let timeout = remaining.min(self.cfg.ns_probe_timeout);
            match exchange(*server, &query, timeout) {
                Ok(resp) if resp.header.qr => return Ok(resp),
                Ok(_) => last_err = "non-response".into(),
                Err(e) => {
                    last_err = e.to_string();
                    tracing::debug!("NS {} unreachable for {}: {}", server, qname, last_err);
                }
            }
        }
        Err(Error::Resolver(format!(
            "{} unreachable: {}",
            qname, last_err
        )))
    }
}

/// A referral: NS names plus glue addresses.
struct Referral {
    ns_names: Vec<String>,
    glue: HashMap<String, SocketAddr>,
}

fn extract_referral(resp: &Message) -> Referral {
    let mut ns_names = Vec::new();
    for r in &resp.authority {
        if r.rtype == TYPE_NS {
            if let RData::Name(n) = &r.data {
                ns_names.push(n.clone());
            }
        }
    }
    let mut glue = HashMap::new();
    for r in &resp.additional {
        let addr = match &r.data {
            RData::A(ip) => SocketAddr::new(IpAddr::V4(*ip), 53),
            RData::Aaaa(ip) => SocketAddr::new(IpAddr::V6(*ip), 53),
            _ => continue,
        };
        glue.insert(r.name.clone(), addr);
    }
    Referral { ns_names, glue }
}

fn a_records(resp: &Message) -> Vec<SocketAddr> {
    resp.answers
        .iter()
        .chain(resp.additional.iter())
        .filter(|r| r.rtype == TYPE_A)
        .filter_map(|r| match &r.data {
            RData::A(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), 53)),
            _ => None,
        })
        .collect()
}

fn aaaa_records(resp: &Message) -> Vec<SocketAddr> {
    resp.answers
        .iter()
        .chain(resp.additional.iter())
        .filter(|r| r.rtype == TYPE_AAAA)
        .filter_map(|r| match &r.data {
            RData::Aaaa(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), 53)),
            _ => None,
        })
        .collect()
}

fn bailiwick_of(name: &str) -> String {
    let name = name.trim_end_matches('.');
    match name.find('.') {
        Some(i) => format!("{}.", &name[i + 1..]),
        None => ".".to_string(),
    }
}

#[allow(dead_code)]
fn ns_in_bailiwick(ns: &str, bailiwick: &str) -> bool {
    ns.trim_end_matches('.')
        .ends_with(bailiwick.trim_end_matches('.'))
}

/// Perform a single DNS exchange (UDP, TCP on truncation) with a timeout.
pub fn exchange(server: SocketAddr, query: &Message, timeout: Duration) -> Result<Message> {
    let bytes = query.encode()?;

    let udp = UdpSocket::bind(match server {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    })
    .map_err(Error::Io)?;
    udp.set_read_timeout(Some(timeout)).map_err(Error::Io)?;
    udp.set_write_timeout(Some(timeout)).map_err(Error::Io)?;
    udp.connect(server).map_err(Error::Io)?;
    udp.send(&bytes).map_err(Error::Io)?;

    let mut buf = [0u8; 4096];
    let n = udp.recv(&mut buf).map_err(Error::Io)?;
    let msg = Message::parse(&buf[..n])?;
    if msg.header.tc {
        return exchange_tcp(server, query, timeout);
    }
    Ok(msg)
}

fn exchange_tcp(server: SocketAddr, query: &Message, timeout: Duration) -> Result<Message> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let bytes = query.encode()?;
    let mut stream = TcpStream::connect_timeout(&server, timeout).map_err(Error::Io)?;
    stream.set_read_timeout(Some(timeout)).map_err(Error::Io)?;
    stream.set_write_timeout(Some(timeout)).map_err(Error::Io)?;
    let len = (bytes.len() as u16).to_be_bytes();
    stream.write_all(&len).map_err(Error::Io)?;
    stream.write_all(&bytes).map_err(Error::Io)?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).map_err(Error::Io)?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).map_err(Error::Io)?;
    Message::parse(&resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bailiwick_logic() {
        assert_eq!(bailiwick_of("www.example.com."), "example.com.");
        assert!(ns_in_bailiwick("ns1.example.com.", "example.com."));
        assert!(!ns_in_bailiwick("ns1.other.net.", "example.com."));
    }
}
