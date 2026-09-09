//! IPv6 → IPv4 dualstack derivation: from an internal IPv6 client address,
//! recover the client's real public IPv4 and pass it as ECS.
//!
//! Three mapping sources, in priority order:
//!   1. embedded: IPv4-mapped (::ffff:a.b.c.d) and RFC 6052 NAT64 prefixes
//!   2. binding table: IPv6 subnet → IPv4, longest-prefix match (from MySQL +
//!      optional CSV file)
//!   3. external HTTP API ({ip} placeholder)
//!
//! After deriving an IPv4, a geo verifier (纯真 qqwry.dat for v4 + an IPv6 CSV)
//! confirms the two addresses point to the same location/ISP. If verification
//! fails (or the libraries are configured but mismatched), no ECS is emitted —
//! fail-closed, matching the upstream platform.

use super::qqwry::{Ipv6Geo, QQwry};
use crate::config::Config;
use crate::model::DualstackBinding;
use crate::proto::{mask_ipv4, EcsInfo};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;
use std::time::Duration;

pub struct Dualstack {
    cfg: std::sync::Arc<Config>,
    table: RwLock<BindingTable>,
    v4: Option<QQwry>,
    v6: Option<Ipv6Geo>,
}

struct BindingEntry {
    net: Ipv6NetOwned,
    ipv4: Ipv4Addr,
}

struct BindingTable {
    entries: Vec<BindingEntry>,
}

impl BindingTable {
    fn new() -> Self {
        BindingTable { entries: vec![] }
    }

    fn add(&mut self, cidr: &str, ipv4: &str) {
        let Ok(net) = cidr.parse::<Ipv6NetOwned>() else {
            return;
        };
        let Ok(ip) = ipv4.parse::<Ipv4Addr>() else {
            return;
        };
        self.entries.push(BindingEntry { net, ipv4: ip });
    }

    fn lookup(&self, ip: Ipv6Addr) -> Option<Ipv4Addr> {
        let mut best: Option<(u8, Ipv4Addr)> = None;
        for e in &self.entries {
            if e.net.contains(ip) && best.map(|(pl, _)| e.net.prefix_len > pl).unwrap_or(true) {
                best = Some((e.net.prefix_len, e.ipv4));
            }
        }
        best.map(|(_, ip)| ip)
    }
}

/// A compact owned IPv6 CIDR (128-bit addr + prefix).
pub struct Ipv6NetOwned {
    addr: u128,
    prefix_len: u8,
}

impl Ipv6NetOwned {
    fn contains(&self, ip: Ipv6Addr) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let ip = u128::from(ip);
        let mask = if self.prefix_len >= 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - self.prefix_len)
        };
        (ip & mask) == (self.addr & mask)
    }
}

impl std::str::FromStr for Ipv6NetOwned {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (addr_s, pl_s) = s.split_once('/').ok_or("missing prefix")?;
        let ip: Ipv6Addr = addr_s
            .parse::<Ipv6Addr>()
            .map_err(|e: std::net::AddrParseError| e.to_string())?;
        let pl: u8 = pl_s
            .parse::<u8>()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        if pl > 128 {
            return Err("prefix > 128".into());
        }
        Ok(Ipv6NetOwned {
            addr: u128::from(ip),
            prefix_len: pl,
        })
    }
}

impl Dualstack {
    pub fn new(cfg: std::sync::Arc<Config>) -> Dualstack {
        let v4 = match &cfg.geo_ipv4_file {
            Some(p) => QQwry::load(p).ok().or_else(|| {
                tracing::warn!(
                    "failed to load GEO_IPV4_FILE ({}); v4 geo disabled",
                    p.display()
                );
                None
            }),
            None => None,
        };
        let v6 = match &cfg.geo_ipv6_file {
            Some(p) => Ipv6Geo::load(p).ok().or_else(|| {
                tracing::warn!(
                    "failed to load GEO_IPV6_FILE ({}); v6 geo disabled",
                    p.display()
                );
                None
            }),
            None => None,
        };

        let mut table = BindingTable::new();
        if let Some(path) = &cfg.ipv6_ipv4_map_file {
            load_map_file(&mut table, path);
        }

        Dualstack {
            cfg,
            table: RwLock::new(table),
            v4,
            v6,
        }
    }

    /// Reload the binding table from MySQL rows (merged with the CSV file).
    pub fn reload(&self, bindings: &[DualstackBinding]) {
        let mut table = BindingTable::new();
        if let Some(path) = &self.cfg.ipv6_ipv4_map_file {
            load_map_file(&mut table, path);
        }
        for b in bindings {
            if b.enabled {
                table.add(&b.ipv6_subnet, &b.ipv4);
            }
        }
        *self.table.write().unwrap() = table;
    }

    /// Derive an ECS (client IPv4) from an internal IPv6 address, or None.
    pub fn derive_ecs(&self, client_ipv6: Ipv6Addr) -> Option<EcsInfo> {
        let v4 = self.map_to_ipv4(client_ipv6)?;

        // Geo verification (fail-closed on mismatch when libraries present).
        if let (Some(qqwry), Some(v6geo)) = (&self.v4, &self.v6) {
            let (v4_loc, v4_isp) = qqwry.lookup(v4)?;
            let (v6_isp, v6_city) = v6geo.lookup(client_ipv6)?;
            if !consistent(
                &v4_loc,
                &v4_isp,
                &v6_isp,
                &v6_city,
                self.cfg.geo_strict_city,
            ) {
                tracing::warn!(
                    "dualstack verify failed: {} -> {} (v4 loc={:?} isp={:?}; v6 isp={:?} city={:?})",
                    client_ipv6, v4, v4_loc, v4_isp, v6_isp, v6_city
                );
                return None;
            }
        } else {
            // No geo libraries configured: trust the mapping, warn once.
            tracing::debug!("dualstack: no geo verification configured; trusting mapping");
        }

        let mask = self.cfg.ecs_derive_mask;
        let v4 = if mask < 32 { mask_ipv4(v4, mask) } else { v4 };
        tracing::info!("dualstack derive {} -> {}/{}", client_ipv6, v4, mask);
        Some(EcsInfo {
            family: 1,
            source_prefix: mask,
            scope_prefix: 0,
            address: Some(IpAddr::V4(v4)),
        })
    }

    fn map_to_ipv4(&self, ipv6: Ipv6Addr) -> Option<Ipv4Addr> {
        // 1. embedded (IPv4-mapped / NAT64)
        if let Some(v4) = embedded_ipv4(ipv6, &self.cfg.nat64_prefixes) {
            return Some(v4);
        }
        // 2. binding table
        if let Some(v4) = self.table.read().unwrap().lookup(ipv6) {
            return Some(v4);
        }
        // 3. external API
        if let Some(url) = &self.cfg.ipv6_ipv4_map_api_url {
            if let Some(v4) = map_via_api(url, ipv6, self.cfg.ipv6_ipv4_map_api_timeout) {
                return Some(v4);
            }
        }
        None
    }
}

fn embedded_ipv4(ipv6: Ipv6Addr, nat64_prefixes: &[String]) -> Option<Ipv4Addr> {
    // IPv4-mapped (::ffff:a.b.c.d)
    if let Some(mapped) = ipv6.to_ipv4_mapped() {
        return Some(mapped);
    }
    let b = ipv6.octets();
    for p in nat64_prefixes {
        let Ok(net) = p.parse::<Ipv6NetOwned>() else {
            continue;
        };
        if net.contains(ipv6) {
            if let Some(v4) = extract_rfc6052(b, net.prefix_len) {
                return Some(v4);
            }
        }
    }
    None
}

fn extract_rfc6052(b: [u8; 16], pl: u8) -> Option<Ipv4Addr> {
    let v4 = match pl {
        32 => {
            if b[8] != 0 {
                return None;
            }
            [b[4], b[5], b[6], b[7]]
        }
        40 => {
            if b[8] != 0 {
                return None;
            }
            [b[5], b[6], b[7], b[9]]
        }
        48 => {
            if b[8] != 0 {
                return None;
            }
            [b[6], b[7], b[9], b[10]]
        }
        56 => {
            if b[8] != 0 {
                return None;
            }
            [b[7], b[9], b[10], b[11]]
        }
        64 => {
            if b[8] != 0 {
                return None;
            }
            [b[9], b[10], b[11], b[12]]
        }
        96 => [b[12], b[13], b[14], b[15]],
        _ => return None,
    };
    Some(Ipv4Addr::new(v4[0], v4[1], v4[2], v4[3]))
}

fn load_map_file(table: &mut BindingTable, path: &std::path::Path) {
    let Ok(data) = std::fs::read_to_string(path) else {
        tracing::warn!("read map file {} failed", path.display());
        return;
    };
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
        if parts.len() >= 2 {
            table.add(parts[0], parts[1]);
        }
    }
}

fn map_via_api(url: &str, ipv6: Ipv6Addr, timeout: Duration) -> Option<Ipv4Addr> {
    let url = url.replace("{ip}", &ipv6.to_string());
    let body = http_get(&url, timeout)?;
    let body = body.trim();
    // JSON {"ipv4":"..."} or plain text.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(ip) = v.get("ipv4").and_then(|x| x.as_str()) {
            if let Ok(ip) = ip.trim().parse::<Ipv4Addr>() {
                return Some(ip);
            }
        }
    }
    body.parse::<Ipv4Addr>().ok()
}

/// Minimal HTTP/1.1 GET (no TLS) for an internal mapping API. Returns the body.
fn http_get(url: &str, timeout: Duration) -> Option<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    // parse "http://host[:port]/path"
    let rest = url.strip_prefix("http://")?;
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.rfind(':') {
        Some(i) => (&host_port[..i], host_port[i + 1..].parse::<u16>().ok()?),
        None => (host_port, 80),
    };

    let mut stream = TcpStream::connect((host, port)).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: dnsd-rs\r\n\r\n",
        path, host_port
    );
    stream.write_all(req.as_bytes()).ok()?;

    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).ok()?;
    let text = String::from_utf8_lossy(&resp);
    // split headers from body
    let idx = text.find("\r\n\r\n").or_else(|| text.find("\n\n"))?;
    Some(text[idx..].trim().to_string())
}

fn consistent(v4_loc: &str, v4_isp: &str, v6_isp: &str, v6_city: &str, strict_city: bool) -> bool {
    // Heuristic: both lookups produced data, and at least one axis overlaps.
    if v4_loc.is_empty() && v4_isp.is_empty() {
        return false;
    }
    if v6_isp.is_empty() && v6_city.is_empty() {
        return false;
    }
    if strict_city {
        // require city/area overlap
        return !v6_city.is_empty() && (v4_isp.contains(v6_city) || v4_loc.contains(v6_city));
    }
    // loose: ISP overlap OR any non-empty
    let isp_overlap = !v4_isp.is_empty()
        && !v6_isp.is_empty()
        && (v4_isp.contains(v6_isp) || v6_isp.contains(v4_isp));
    isp_overlap || v4_loc == v6_city
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_ipv4_mapped() {
        let ip: Ipv6Addr = "::ffff:1.2.3.4".parse().unwrap();
        let v4 = embedded_ipv4(ip, &[]).unwrap();
        assert_eq!(v4, Ipv4Addr::new(1, 2, 3, 4));
    }

    #[test]
    fn nat64_rfc6052_96() {
        let ip: Ipv6Addr = "64:ff9b::102:304".parse().unwrap();
        let v4 = embedded_ipv4(ip, &["64:ff9b::/96".to_string()]).unwrap();
        assert_eq!(v4, Ipv4Addr::new(1, 2, 3, 4));
    }

    #[test]
    fn binding_table_longest_prefix_match() {
        let mut t = BindingTable::new();
        t.add("2001:db8::/32", "10.0.0.1");
        t.add("2001:db8:100::/48", "10.0.1.1");
        let ip: Ipv6Addr = "2001:db8:100::5".parse().unwrap();
        assert_eq!(t.lookup(ip), Some(Ipv4Addr::new(10, 0, 1, 1)));
        let ip2: Ipv6Addr = "2001:db8:200::5".parse().unwrap();
        assert_eq!(t.lookup(ip2), Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn binding_table_miss() {
        let mut t = BindingTable::new();
        t.add("2001:db8::/32", "10.0.0.1");
        let ip: Ipv6Addr = "2001:dead::1".parse().unwrap();
        assert_eq!(t.lookup(ip), None);
    }
}
