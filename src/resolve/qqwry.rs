//! 纯真 (QQWry) IPv4 location database parser.
//!
//! `qqwry.dat` stores IP ranges with country/area strings encoded in GBK. This
//! implements the standard binary-search index + record decoding (including the
//! 0x01/0x02 redirect modes).

use crate::error::{Error, Result};
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct QQwry {
    data: Vec<u8>,
    first_idx: u32,
    last_idx: u32,
}

impl QQwry {
    pub fn load(path: &std::path::Path) -> Result<QQwry> {
        let data = std::fs::read(path).map_err(Error::Io)?;
        if data.len() < 8 {
            return Err(Error::Config("qqwry.dat too small".into()));
        }
        let first_idx = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let last_idx = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        Ok(QQwry {
            data,
            first_idx,
            last_idx,
        })
    }

    fn read_u24(&self, off: usize) -> u32 {
        let d = &self.data;
        u32::from_le_bytes([d[off], d[off + 1], d[off + 2], 0])
    }

    fn read_string(&self, off: usize) -> String {
        // null-terminated GBK string
        let mut end = off;
        while end < self.data.len() && self.data[end] != 0 {
            end += 1;
        }
        let bytes = &self.data[off..end];
        let (s, _, _) = encoding_rs::GBK.decode(bytes);
        s.into_owned()
    }

    fn country_area(&self, off: usize) -> (String, String) {
        if off + 4 > self.data.len() {
            return (String::new(), String::new());
        }
        let mode = self.data[off];
        match mode {
            0x01 => {
                let redirect = self.read_u24(off + 1) as usize;
                self.country_area(redirect)
            }
            0x02 => {
                let redirect = self.read_u24(off + 1) as usize;
                let country = self.read_string(redirect);
                let area = self.read_area(off + 4);
                (country, area)
            }
            _ => {
                let len = mode as usize;
                let country = self.read_string(off + 1);
                let area = self.read_area(off + 1 + len);
                (country, area)
            }
        }
    }

    fn read_area(&self, off: usize) -> String {
        if off >= self.data.len() {
            return String::new();
        }
        let mode = self.data[off];
        match mode {
            0x01 | 0x02 => {
                let redirect = self.read_u24(off + 1) as usize;
                self.read_string(redirect)
            }
            _ => self.read_string(off),
        }
    }

    /// Return (country, area) for the given IPv4, or None if out of range.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<(String, String)> {
        let ip_u32 = u32::from(ip);
        let mut lo = self.first_idx;
        let mut hi = self.last_idx;

        // binary search for the last index whose start IP <= ip_u32
        let mut found: Option<usize> = None;
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            let start = self.index_start_ip(mid);
            if start <= ip_u32 {
                found = Some(mid as usize);
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        let idx = found?;
        let rec_off = self.index_record_offset(idx);
        let (country, area) = self.country_area(rec_off as usize);
        Some((country, area))
    }

    fn index_start_ip(&self, idx: u32) -> u32 {
        let off = (self.first_idx + idx * 7) as usize;
        if off + 4 > self.data.len() {
            return u32::MAX;
        }
        u32::from_le_bytes([
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ])
    }

    fn index_record_offset(&self, idx: usize) -> u32 {
        let off = (self.first_idx + (idx as u32) * 7 + 4) as usize;
        self.read_u24(off)
    }
}

/// A minimal IPv6 geo database (CSV: ipv6_subnet,country,province,city,isp).
pub struct Ipv6Geo {
    entries: Vec<(Ipv6Net, String, String)>, // (network, isp, city)
}

impl Ipv6Geo {
    pub fn load(path: &std::path::Path) -> Result<Ipv6Geo> {
        let data = std::fs::read_to_string(path).map_err(Error::Io)?;
        let mut entries = Vec::new();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if parts.len() < 2 {
                continue;
            }
            let Ok(net) = parts[0].parse::<Ipv6Net>() else {
                continue;
            };
            let isp = parts.get(4).copied().unwrap_or("").to_string();
            let city = parts.get(3).copied().unwrap_or("").to_string();
            entries.push((net, isp, city));
        }
        Ok(Ipv6Geo { entries })
    }

    pub fn empty() -> Ipv6Geo {
        Ipv6Geo { entries: vec![] }
    }

    /// Longest-prefix match for an IPv6 address -> (isp, city).
    pub fn lookup(&self, ip: Ipv6Addr) -> Option<(String, String)> {
        let mut best: Option<(u8, &String, &String)> = None;
        for (net, isp, city) in &self.entries {
            if net.contains(ip) && best.map(|(pl, _, _)| net.prefix_len > pl).unwrap_or(true) {
                best = Some((net.prefix_len, isp, city));
            }
        }
        best.map(|(_, isp, city)| (isp.clone(), city.clone()))
    }
}

/// A parsed IPv6 CIDR network.
pub struct Ipv6Net {
    addr: u128,
    prefix_len: u8,
}

impl Ipv6Net {
    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        let ip = u128::from(ip);
        if self.prefix_len == 0 {
            return true;
        }
        let mask = if self.prefix_len >= 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - self.prefix_len)
        };
        (ip & mask) == (self.addr & mask)
    }
}

impl std::str::FromStr for Ipv6Net {
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
        Ok(Ipv6Net {
            addr: u128::from(ip),
            prefix_len: pl,
        })
    }
}
