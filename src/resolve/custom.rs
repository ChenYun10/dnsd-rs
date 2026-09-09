//! Custom domain (zone) resolution: authoritative answers served from records
//! loaded out of MySQL (zones + zone_records).
//!
//! Supports exact-name records, CNAME, and `*.zone` wildcards. The longest
//! matching zone wins. Unmatched names under a served zone get an
//! authoritative NXDOMAIN; names outside any zone fall through to recursion.

use crate::model::{Zone, ZoneRecord};
use crate::proto::{
    canonical_name, Header, Message, Question, RData, Record, CLASS_IN, RCODE_NOERROR,
    RCODE_NXDOMAIN, TYPE_CNAME,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct ZoneIndex {
    // canonical zone name -> records
    zones: HashMap<String, Vec<ZoneRecord>>,
}

impl ZoneIndex {
    pub fn new(zones: Vec<Zone>, records: Vec<ZoneRecord>) -> ZoneIndex {
        let mut id_to_name: HashMap<String, String> = HashMap::new();
        for z in zones {
            id_to_name.insert(z.id, z.name);
        }
        let mut by_zone: HashMap<String, Vec<ZoneRecord>> = HashMap::new();
        for r in records {
            if let Some(name) = id_to_name.get(&r.zone_id) {
                by_zone.entry(canonical_name(name)).or_default().push(r);
            }
        }
        ZoneIndex { zones: by_zone }
    }

    pub fn empty() -> ZoneIndex {
        ZoneIndex {
            zones: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    fn find_zone(&self, qname: &str) -> Option<(&str, &Vec<ZoneRecord>)> {
        let n = canonical_name(qname);
        let mut best: Option<(&str, &Vec<ZoneRecord>)> = None;
        for (zone, recs) in &self.zones {
            if n == *zone || n.ends_with(zone.as_str()) {
                if best.map(|(z, _)| zone.len() > z.len()).unwrap_or(true) {
                    best = Some((zone, recs));
                }
            }
        }
        best
    }

    /// Serve an authoritative answer for `q`, or None if the name is not under
    /// any custom zone (caller falls through to recursion).
    pub fn respond(&self, q: &Question) -> Option<Message> {
        let (zone, recs) = self.find_zone(&q.name)?;
        let qname = canonical_name(&q.name);

        let mut answers = Vec::new();
        let mut cname: Option<String> = None;

        for r in recs {
            let owner = owner_name(r, zone);
            if owner != qname {
                continue;
            }
            if r.rtype == "CNAME" && cname.is_none() {
                cname = Some(canonical_name(&r.value));
            }
            if r.rtype == type_label(q.qtype) {
                if let Some(rec) = build_record(&qname, r) {
                    answers.push(rec);
                }
            }
        }

        if !answers.is_empty() {
            return Some(make_response(q, answers, RCODE_NOERROR));
        }
        if let Some(target) = cname {
            answers.push(Record {
                name: qname,
                rtype: TYPE_CNAME,
                class: CLASS_IN,
                ttl: 300,
                data: RData::Name(target),
            });
            return Some(make_response(q, answers, RCODE_NOERROR));
        }

        // Wildcard: name == "*" matches any name under the zone (no exact match).
        for r in recs {
            if r.name == "*" && r.rtype == type_label(q.qtype) {
                if let Some(rec) = build_record(&qname, r) {
                    answers.push(rec);
                }
            }
        }
        if !answers.is_empty() {
            return Some(make_response(q, answers, RCODE_NOERROR));
        }

        // Under the zone but no data → authoritative NXDOMAIN.
        Some(make_response(q, Vec::new(), RCODE_NXDOMAIN))
    }
}

fn owner_name(r: &ZoneRecord, zone: &str) -> String {
    let zone = zone.trim_end_matches('.');
    if r.name == "@" {
        canonical_name(zone)
    } else {
        // relative label(s) resolved against the zone
        canonical_name(&format!("{}.{}", r.name.trim_end_matches('.'), zone))
    }
}

fn type_label(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        16 => "TXT",
        15 => "MX",
        2 => "NS",
        33 => "SRV",
        257 => "CAA",
        _ => "",
    }
}

fn build_record(owner: &str, r: &ZoneRecord) -> Option<Record> {
    let data = r.type_to_rdata()?;
    let rtype = match r.rtype.as_str() {
        "A" => 1,
        "AAAA" => 28,
        "CNAME" => 5,
        "TXT" => 16,
        "MX" => 15,
        "NS" => 2,
        "SRV" => 33,
        "CAA" => 257,
        _ => return None,
    };
    Some(Record {
        name: owner.to_string(),
        rtype,
        class: CLASS_IN,
        ttl: r.ttl,
        data,
    })
}

fn make_response(q: &Question, answers: Vec<Record>, rcode: u8) -> Message {
    Message {
        header: Header {
            id: 0,
            qr: true,
            opcode: 0,
            aa: true,
            rd: true,
            ra: true,
            rcode,
            ..Default::default()
        },
        questions: vec![q.clone()],
        answers,
        authority: Vec::new(),
        additional: Vec::new(),
    }
}

impl ZoneRecord {
    fn type_to_rdata(&self) -> Option<RData> {
        match self.rtype.as_str() {
            "A" => self.value.parse::<Ipv4Addr>().ok().map(RData::A),
            "AAAA" => self.value.parse::<Ipv6Addr>().ok().map(RData::Aaaa),
            "CNAME" | "NS" | "PTR" | "DNAME" => Some(RData::Name(canonical_name(&self.value))),
            "TXT" => Some(RData::Txt(vec![self.value.as_bytes().to_vec()])),
            "MX" => Some(RData::Mx {
                preference: self.priority,
                exchange: canonical_name(&self.value),
            }),
            "SRV" => {
                let parts: Vec<&str> = self.value.split_whitespace().collect();
                if parts.len() != 4 {
                    return None;
                }
                Some(RData::Srv {
                    priority: parts[0].parse().ok()?,
                    weight: parts[1].parse().ok()?,
                    port: parts[2].parse().ok()?,
                    target: canonical_name(parts[3]),
                })
            }
            "CAA" => {
                let mut it = self.value.split_whitespace();
                let tag = it.next().unwrap_or("").to_string();
                let val = it.collect::<Vec<_>>().join(" ");
                Some(RData::Caa {
                    flags: 0,
                    tag,
                    value: val.as_bytes().to_vec(),
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Zone;

    fn zr(id: &str, name: &str, rtype: &str, value: &str) -> ZoneRecord {
        ZoneRecord {
            id: id.into(),
            zone_id: "z1".into(),
            name: name.into(),
            rtype: rtype.into(),
            value: value.into(),
            ttl: 300,
            priority: 0,
            enabled: true,
        }
    }

    #[test]
    fn serves_authoritative_a() {
        let z = Zone {
            id: "z1".into(),
            name: "internal.example.com".into(),
            enabled: true,
        };
        let idx = ZoneIndex::new(
            vec![z],
            vec![
                zr("r1", "@", "A", "10.1.2.3"),
                zr("r2", "app", "A", "10.1.2.4"),
            ],
        );
        let q = Question {
            name: "app.internal.example.com.".into(),
            qtype: 1,
            qclass: 1,
        };
        let resp = idx.respond(&q).expect("name under zone");
        assert!(resp.header.aa, "authoritative");
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(10, 1, 2, 4)),
            other => panic!("expected A, got {:?}", other),
        }
    }

    #[test]
    fn cname_and_nxdomain() {
        let z = Zone {
            id: "z1".into(),
            name: "internal.example.com".into(),
            enabled: true,
        };
        let idx = ZoneIndex::new(
            vec![z],
            vec![zr("r1", "www", "CNAME", "app.internal.example.com.")],
        );
        let q = Question {
            name: "www.internal.example.com.".into(),
            qtype: 1,
            qclass: 1,
        };
        let resp = idx.respond(&q).unwrap();
        match &resp.answers[0].data {
            RData::Name(n) => assert_eq!(n, "app.internal.example.com."),
            other => panic!("expected CNAME, got {:?}", other),
        }
        // unknown name under zone -> NXDOMAIN
        let q2 = Question {
            name: "missing.internal.example.com.".into(),
            qtype: 1,
            qclass: 1,
        };
        let resp2 = idx.respond(&q2).unwrap();
        assert_eq!(resp2.header.rcode, crate::proto::RCODE_NXDOMAIN);
    }

    #[test]
    fn outside_zone_falls_through() {
        let z = Zone {
            id: "z1".into(),
            name: "internal.example.com".into(),
            enabled: true,
        };
        let idx = ZoneIndex::new(vec![z], vec![zr("r1", "@", "A", "10.1.2.3")]);
        let q = Question {
            name: "google.com.".into(),
            qtype: 1,
            qclass: 1,
        };
        assert!(idx.respond(&q).is_none());
    }
}
