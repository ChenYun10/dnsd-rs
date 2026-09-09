//! Domain blocking: blocked qnames resolve to 127.0.0.1/::1 (loopback) or to a
//! deterministic pseudo-random IP (stable per qname+client, in the 10/8 sinkhole
//! range). Supports exact and `*.example.com` wildcard entries.

use crate::model::{BlockMode, BlockedDomain};
use crate::proto::{canonical_name, Message, Question, RData, Record};
use crate::proto::{Header, CLASS_IN, RCODE_NOERROR, TYPE_A, TYPE_AAAA};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct BlockList {
    exact: HashMap<String, BlockMode>,
    wildcard: Vec<(String, BlockMode)>, // suffix, e.g. ".example.com"
}

impl BlockList {
    pub fn new(entries: Vec<BlockedDomain>) -> BlockList {
        let mut exact = HashMap::new();
        let mut wildcard = Vec::new();
        for e in entries {
            let d = canonical_name(&e.domain);
            let d = d.trim_end_matches('.').to_string();
            if let Some(rest) = d.strip_prefix("*.") {
                wildcard.push((format!(".{}", rest), e.mode));
            } else {
                exact.insert(d, e.mode);
            }
        }
        BlockList { exact, wildcard }
    }

    pub fn empty() -> BlockList {
        BlockList {
            exact: HashMap::new(),
            wildcard: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }

    pub fn mode_for(&self, qname: &str) -> Option<BlockMode> {
        let n = canonical_name(qname);
        let n = n.trim_end_matches('.');
        if let Some(m) = self.exact.get(n) {
            return Some(*m);
        }
        for (suffix, mode) in &self.wildcard {
            if n.ends_with(suffix) && n.len() > suffix.len() {
                return Some(*mode);
            }
        }
        None
    }

    /// Build a blocking response for the given query.
    pub fn respond(&self, q: &Question, client_ip: &IpAddr, mode: BlockMode) -> Message {
        let mut m = Message {
            header: Header {
                id: 0,
                qr: true,
                opcode: 0,
                aa: false,
                rd: true,
                ra: true,
                rcode: RCODE_NOERROR,
                ..Default::default()
            },
            questions: vec![q.clone()],
            ..Default::default()
        };

        let (a, aaaa) = match mode {
            BlockMode::Loopback => (Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST),
            BlockMode::Random => (random_v4(q.name.as_str(), client_ip), Ipv6Addr::LOCALHOST),
        };

        match q.qtype {
            TYPE_A => m.answers.push(Record {
                name: q.name.clone(),
                rtype: TYPE_A,
                class: CLASS_IN,
                ttl: 60,
                data: RData::A(a),
            }),
            TYPE_AAAA => m.answers.push(Record {
                name: q.name.clone(),
                rtype: TYPE_AAAA,
                class: CLASS_IN,
                ttl: 60,
                data: RData::Aaaa(aaaa),
            }),
            _ => { /* NODATA: NOERROR with empty answer */ }
        }
        m
    }
}

/// Deterministic pseudo-random IPv4 in 10/8, stable for a given qname+client.
fn random_v4(qname: &str, client_ip: &IpAddr) -> Ipv4Addr {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in qname.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    for b in client_ip.to_string().as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    let third = ((h >> 16) & 0xFF) as u8;
    let fourth = (h & 0xFF) as u8;
    Ipv4Addr::new(10, 7, third.max(1), fourth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::BlockedDomain;

    fn dom(domain: &str, mode: BlockMode) -> BlockedDomain {
        BlockedDomain {
            id: "x".into(),
            domain: domain.into(),
            mode,
            enabled: true,
        }
    }

    #[test]
    fn exact_and_wildcard_match() {
        let bl = BlockList::new(vec![
            dom("evil.com", BlockMode::Loopback),
            dom("*.ads.example.com", BlockMode::Random),
        ]);
        assert_eq!(bl.mode_for("evil.com"), Some(BlockMode::Loopback));
        assert_eq!(bl.mode_for("www.evil.com"), None); // exact only
        assert_eq!(bl.mode_for("a.ads.example.com"), Some(BlockMode::Random));
        assert_eq!(bl.mode_for("ads.example.com"), None); // wildcard excludes apex
    }

    #[test]
    fn block_responds_loopback() {
        let bl = BlockList::new(vec![dom("evil.com", BlockMode::Loopback)]);
        let q = crate::proto::Question {
            name: "evil.com.".into(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        let client: IpAddr = "1.2.3.4".parse().unwrap();
        let resp = bl.respond(&q, &client, BlockMode::Loopback);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::LOCALHOST),
            other => panic!("expected A, got {:?}", other),
        }
    }

    #[test]
    fn block_random_is_stable_per_client() {
        let bl = BlockList::new(vec![dom("ads.example.com", BlockMode::Random)]);
        let q = crate::proto::Question {
            name: "ads.example.com.".into(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        let c1: IpAddr = "1.2.3.4".parse().unwrap();
        let a = bl.respond(&q, &c1, BlockMode::Random);
        let b = bl.respond(&q, &c1, BlockMode::Random);
        match (&a.answers[0].data, &b.answers[0].data) {
            (RData::A(x), RData::A(y)) => assert_eq!(x, y), // deterministic
            _ => panic!(),
        }
    }
}
