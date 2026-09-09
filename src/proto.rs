//! Self-built DNS wire-format codec (RFC 1035 message framing + name
//! compression, plus EDNS0/ECS per RFC 6891 / RFC 7871).
//!
//! This deliberately avoids pulling in a full resolver library: we only need
//! encode/decode, and building it ourselves keeps the dependency surface small
//! and the wire behavior fully under our control.
//!
//! Known RR types with names are fully parsed (CNAME/NS/PTR/DNAME/MX/SOA/SRV/
//! RRSIG/NSEC) so that re-encoding is always lossless; unknown types are kept
//! as opaque RDATA bytes (RFC 3597 servers do not compress names inside unknown
//! types, so verbatim re-emit is safe in practice).

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---- record type / class / rcode constants ---------------------------------
pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_DNAME: u16 = 39;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_DS: u16 = 43;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_NSEC3: u16 = 50;
pub const TYPE_CAA: u16 = 257;

pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

/// EDNS option codes.
pub const EDNS_OPT_ECS: u16 = 8; // EDNS Client Subnet (RFC 7871)
pub const EDNS_OPT_EDE: u16 = 15; // Extended DNS Errors (RFC 8914)

pub fn type_to_string(t: u16) -> String {
    match t {
        TYPE_A => "A".into(),
        TYPE_NS => "NS".into(),
        TYPE_CNAME => "CNAME".into(),
        TYPE_SOA => "SOA".into(),
        TYPE_PTR => "PTR".into(),
        TYPE_MX => "MX".into(),
        TYPE_TXT => "TXT".into(),
        TYPE_AAAA => "AAAA".into(),
        TYPE_SRV => "SRV".into(),
        TYPE_DNAME => "DNAME".into(),
        TYPE_OPT => "OPT".into(),
        TYPE_DS => "DS".into(),
        TYPE_RRSIG => "RRSIG".into(),
        TYPE_NSEC => "NSEC".into(),
        TYPE_DNSKEY => "DNSKEY".into(),
        TYPE_NSEC3 => "NSEC3".into(),
        TYPE_CAA => "CAA".into(),
        other => format!("TYPE{}", other),
    }
}

pub fn type_from_string(s: &str) -> Option<u16> {
    Some(match s.to_uppercase().as_str() {
        "A" => TYPE_A,
        "NS" => TYPE_NS,
        "CNAME" => TYPE_CNAME,
        "SOA" => TYPE_SOA,
        "PTR" => TYPE_PTR,
        "MX" => TYPE_MX,
        "TXT" => TYPE_TXT,
        "AAAA" => TYPE_AAAA,
        "SRV" => TYPE_SRV,
        "DNAME" => TYPE_DNAME,
        "DS" => TYPE_DS,
        "RRSIG" => TYPE_RRSIG,
        "NSEC" => TYPE_NSEC,
        "DNSKEY" => TYPE_DNSKEY,
        "NSEC3" => TYPE_NSEC3,
        "CAA" => TYPE_CAA,
        _ => return None,
    })
}

pub fn rcode_to_string(rc: u8) -> String {
    match rc {
        RCODE_NOERROR => "NOERROR".into(),
        RCODE_FORMERR => "FORMERR".into(),
        RCODE_SERVFAIL => "SERVFAIL".into(),
        RCODE_NXDOMAIN => "NXDOMAIN".into(),
        RCODE_NOTIMP => "NOTIMP".into(),
        RCODE_REFUSED => "REFUSED".into(),
        other => format!("RCODE{}", other),
    }
}

// ---- message model ----------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: u8,
}

#[derive(Debug, Clone)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// Domain name in RDATA: NS, CNAME, PTR, DNAME (and NSEC next name).
    Name(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Txt(Vec<Vec<u8>>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Caa {
        flags: u8,
        tag: String,
        value: Vec<u8>,
    },
    Rrsig {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer_name: String,
        signature: Vec<u8>,
    },
    Nsec {
        next_domain: String,
        type_bitmaps: Vec<u8>,
    },
    /// Opaque RDATA for fixed-layout / unknown types (DS, DNSKEY, NSEC3, ...).
    /// Emitted verbatim; must not contain name-compression pointers.
    Raw(Vec<u8>),
    Opt {
        udp_size: u16,
        ext_rcode: u8,
        version: u8,
        flags: u16,
        options: Vec<OptOption>,
    },
}

#[derive(Debug, Clone)]
pub struct OptOption {
    pub code: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

impl Message {
    /// True when this message carries a valid EDNS OPT record.
    pub fn edns(&self) -> Option<&Record> {
        self.additional.iter().find(|r| r.rtype == TYPE_OPT)
    }

    /// EDNS Client Subnet extracted from the OPT record (RFC 7871).
    pub fn ecs(&self) -> Option<EcsInfo> {
        let opt = self.edns()?;
        if let RData::Opt { options, .. } = &opt.data {
            for o in options {
                if o.code == EDNS_OPT_ECS && o.data.len() >= 4 {
                    return Some(EcsInfo::decode(&o.data));
                }
            }
        }
        None
    }

    /// Whether the DO (DNSSEC OK) bit is set in the EDNS flags.
    pub fn dnssec_ok(&self) -> bool {
        match self.edns() {
            Some(r) => match &r.data {
                RData::Opt { flags, .. } => flags & 0x8000 != 0,
                _ => false,
            },
            None => false,
        }
    }

    /// First question (there is at most one in practice).
    pub fn question(&self) -> Option<&Question> {
        self.questions.first()
    }

    pub fn is_response(&self) -> bool {
        self.header.qr
    }
}

// ---- ECS (EDNS Client Subnet) ----------------------------------------------

#[derive(Debug, Clone)]
pub struct EcsInfo {
    pub family: u16, // 1 = IPv4, 2 = IPv6
    pub source_prefix: u8,
    pub scope_prefix: u8,
    pub address: Option<std::net::IpAddr>,
}

impl EcsInfo {
    pub fn decode(data: &[u8]) -> EcsInfo {
        if data.len() < 4 {
            return EcsInfo {
                family: 0,
                source_prefix: 0,
                scope_prefix: 0,
                address: None,
            };
        }
        let family = u16::from_be_bytes([data[0], data[1]]);
        let source_prefix = data[2];
        let scope_prefix = data[3];
        let addr_bytes = &data[4..];
        let address = match family {
            1 => {
                if addr_bytes.len() >= 4 {
                    Some(std::net::IpAddr::V4(Ipv4Addr::new(
                        addr_bytes[0],
                        addr_bytes[1],
                        addr_bytes[2],
                        addr_bytes[3],
                    )))
                } else {
                    None
                }
            }
            2 => {
                if addr_bytes.len() >= 16 {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&addr_bytes[..16]);
                    Some(std::net::IpAddr::V6(Ipv6Addr::from(b)))
                } else {
                    None
                }
            }
            _ => None,
        };
        EcsInfo {
            family,
            source_prefix,
            scope_prefix,
            address,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20);
        out.extend_from_slice(&self.family.to_be_bytes());
        out.push(self.source_prefix);
        out.push(self.scope_prefix);
        match self.address {
            Some(std::net::IpAddr::V4(ip)) => {
                out.extend_from_slice(&ip.octets());
            }
            Some(std::net::IpAddr::V6(ip)) => {
                out.extend_from_slice(&ip.octets());
            }
            None => {}
        }
        out
    }

    /// Clamp an IPv4 source prefix to `max` (0..32). IPv6 is untouched.
    pub fn clamp_scope(&mut self, max: u8) {
        if self.family != 1 || self.source_prefix <= max {
            return;
        }
        self.source_prefix = max;
        if let Some(std::net::IpAddr::V4(ip)) = self.address {
            self.address = Some(std::net::IpAddr::V4(mask_ipv4(ip, max)));
        }
    }

    pub fn cache_token(&self) -> String {
        match self.address {
            Some(std::net::IpAddr::V4(ip)) => format!("{}/{}", ip, self.source_prefix),
            Some(std::net::IpAddr::V6(ip)) => format!("{}/{}", ip, self.source_prefix),
            None => String::new(),
        }
    }
}

pub fn mask_ipv4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    if prefix >= 32 {
        return ip;
    }
    let mask: u32 = u32::MAX << (32 - prefix);
    Ipv4Addr::from(u32::from(ip) & mask)
}

pub fn mask_ipv6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    if prefix == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    if prefix >= 128 {
        return ip;
    }
    let mut octets = ip.octets();
    let full_bytes = (prefix / 8) as usize;
    let rem_bits = prefix % 8;
    for i in full_bytes..16 {
        octets[i] = 0;
    }
    if rem_bits > 0 && full_bytes < 16 {
        octets[full_bytes] &= 0xFF << (8 - rem_bits);
    }
    Ipv6Addr::from(octets)
}

// ---- parsing ----------------------------------------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(Error::Parse("truncated: u8".into()));
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16> {
        if self.remaining() < 2 {
            return Err(Error::Parse("truncated: u16".into()));
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(Error::Parse("truncated: u32".into()));
        }
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Parse("truncated: bytes".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// Read a (possibly compressed) domain name. Compression pointers are absolute
/// offsets into the whole message.
fn read_name(buf: &[u8], pos: &mut usize) -> Result<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut next = *pos;
    let mut guard = 0usize;

    loop {
        guard += 1;
        if guard > 256 {
            return Err(Error::Parse("name compression loop".into()));
        }
        if next >= buf.len() {
            return Err(Error::Parse("name runs past end".into()));
        }
        let len = buf[next];
        if len & 0xC0 == 0xC0 {
            // compression pointer
            if next + 1 >= buf.len() {
                return Err(Error::Parse("truncated pointer".into()));
            }
            let ptr = (((len & 0x3F) as usize) << 8) | buf[next + 1] as usize;
            if !jumped {
                *pos = next + 2;
                jumped = true;
            }
            next = ptr;
            continue;
        }
        if len & 0xC0 != 0 {
            return Err(Error::Parse("bad label length".into()));
        }
        next += 1;
        if len == 0 {
            break; // root label
        }
        if len as usize > 63 || next + len as usize > buf.len() {
            return Err(Error::Parse("bad label".into()));
        }
        let raw = &buf[next..next + len as usize];
        let label = String::from_utf8_lossy(raw).to_lowercase();
        labels.push(label);
        next += len as usize;
    }

    if !jumped {
        *pos = next;
    }
    if labels.is_empty() {
        Ok(".".into())
    } else {
        let mut s = labels.join(".");
        s.push('.');
        Ok(s)
    }
}

fn read_record(buf: &[u8], pos: &mut usize) -> Result<Record> {
    let name = read_name(buf, pos)?;
    let rtype = read_u16_at(buf, pos)?;
    let class = read_u16_at(buf, pos)?;
    let ttl = read_u32_at(buf, pos)?;
    let rdlen = read_u16_at(buf, pos)? as usize;
    if *pos + rdlen > buf.len() {
        return Err(Error::Parse("rdata past end".into()));
    }
    let rd_start = *pos;
    let data = parse_rdata(buf, rd_start, rdlen, rtype)?;
    *pos = rd_start + rdlen;
    Ok(Record {
        name,
        rtype,
        class,
        ttl,
        data,
    })
}

fn read_u16_at(buf: &[u8], pos: &mut usize) -> Result<u16> {
    if *pos + 2 > buf.len() {
        return Err(Error::Parse("truncated u16".into()));
    }
    let v = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
    *pos += 2;
    Ok(v)
}
fn read_u32_at(buf: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > buf.len() {
        return Err(Error::Parse("truncated u32".into()));
    }
    let v = u32::from_be_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

fn parse_rdata(buf: &[u8], start: usize, len: usize, rtype: u16) -> Result<RData> {
    let mut c = Cursor::new(&buf[start..start + len]);
    match rtype {
        TYPE_A => {
            if len != 4 {
                return Err(Error::Parse("A rdata len != 4".into()));
            }
            let b = c.bytes(4)?;
            Ok(RData::A(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
        }
        TYPE_AAAA => {
            if len != 16 {
                return Err(Error::Parse("AAAA rdata len != 16".into()));
            }
            let b = c.bytes(16)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(b);
            Ok(RData::Aaaa(Ipv6Addr::from(o)))
        }
        TYPE_NS | TYPE_CNAME | TYPE_PTR | TYPE_DNAME => {
            let mut p = start;
            let name = read_name(buf, &mut p)?;
            Ok(RData::Name(name))
        }
        TYPE_MX => {
            let preference = c.u16()?;
            let mut p = start + 2;
            let exchange = read_name(buf, &mut p)?;
            Ok(RData::Mx {
                preference,
                exchange,
            })
        }
        TYPE_SOA => {
            let mut p = start;
            let mname = read_name(buf, &mut p)?;
            let rname = read_name(buf, &mut p)?;
            let serial = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            p += 4;
            let refresh = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            p += 4;
            let retry = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            p += 4;
            let expire = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            p += 4;
            let minimum = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            Ok(RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
        }
        TYPE_TXT => {
            let mut strings = Vec::new();
            while c.remaining() > 0 {
                let l = c.u8()? as usize;
                strings.push(c.bytes(l)?.to_vec());
            }
            Ok(RData::Txt(strings))
        }
        TYPE_SRV => {
            let priority = c.u16()?;
            let weight = c.u16()?;
            let port = c.u16()?;
            let mut p = start + 6;
            let target = read_name(buf, &mut p)?;
            Ok(RData::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        TYPE_CAA => {
            let flags = c.u8()?;
            let tag_len = c.u8()? as usize;
            let tag = String::from_utf8_lossy(c.bytes(tag_len)?).to_string();
            let value = c.bytes(c.remaining())?.to_vec();
            Ok(RData::Caa { flags, tag, value })
        }
        TYPE_RRSIG => {
            let type_covered = c.u16()?;
            let algorithm = c.u8()?;
            let labels = c.u8()?;
            let original_ttl = c.u32()?;
            let expiration = c.u32()?;
            let inception = c.u32()?;
            let key_tag = c.u16()?;
            let signer_offset = start + 18;
            let mut p = signer_offset;
            let signer_name = read_name(buf, &mut p)?;
            let sig_start = p;
            let signature = buf[sig_start..start + len].to_vec();
            Ok(RData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name,
                signature,
            })
        }
        TYPE_NSEC => {
            let mut p = start;
            let next_domain = read_name(buf, &mut p)?;
            let type_bitmaps = buf[p..start + len].to_vec();
            Ok(RData::Nsec {
                next_domain,
                type_bitmaps,
            })
        }
        TYPE_OPT => {
            // OPT pseudo-record: name (root), class = UDP size, ttl = ext-rcode/
            // version/flags. We parse only the option payload here; the header
            // fields are recovered in read_record -> we re-read them below.
            parse_opt_rdata(&mut c)
        }
        // Fixed-layout / unknown types: opaque.
        _ => Ok(RData::Raw(buf[start..start + len].to_vec())),
    }
}

fn parse_opt_rdata(c: &mut Cursor) -> Result<RData> {
    let mut options = Vec::new();
    while c.remaining() >= 4 {
        let code = c.u16()?;
        let len = c.u16()? as usize;
        let data = c.bytes(len)?.to_vec();
        options.push(OptOption { code, data });
    }
    // UDP size / ext-rcode / version / flags come from the record's class/ttl
    // fields, filled in read_record's caller via a placeholder.
    Ok(RData::Opt {
        udp_size: 0,
        ext_rcode: 0,
        version: 0,
        flags: 0,
        options,
    })
}

impl Message {
    pub fn parse(buf: &[u8]) -> Result<Message> {
        let mut c = Cursor::new(buf);
        if c.remaining() < 12 {
            return Err(Error::Parse("message shorter than header".into()));
        }
        let id = c.u16()?;
        let flags = c.u16()?;
        let qd = c.u16()?;
        let an = c.u16()?;
        let ns = c.u16()?;
        let ar = c.u16()?;

        let header = Header {
            id,
            qr: flags & 0x8000 != 0,
            opcode: ((flags >> 11) & 0xF) as u8,
            aa: flags & 0x0400 != 0,
            tc: flags & 0x0200 != 0,
            rd: flags & 0x0100 != 0,
            ra: flags & 0x0080 != 0,
            ad: flags & 0x0020 != 0,
            cd: flags & 0x0010 != 0,
            rcode: (flags & 0xF) as u8,
        };

        let mut msg = Message {
            header,
            ..Default::default()
        };

        for _ in 0..qd {
            let name = read_name(buf, &mut c.pos)?;
            let qtype = c.u16()?;
            let qclass = c.u16()?;
            msg.questions.push(Question {
                name,
                qtype,
                qclass,
            });
        }
        for _ in 0..an {
            msg.answers.push(read_record(buf, &mut c.pos)?);
        }
        for _ in 0..ns {
            msg.authority.push(read_record(buf, &mut c.pos)?);
        }
        for _ in 0..ar {
            let rec = read_record(buf, &mut c.pos)?;
            // Recover OPT header fields from class/ttl (RFC 6891 §6.1.2).
            let rec = if rec.rtype == TYPE_OPT {
                match rec.data {
                    RData::Opt { options, .. } => {
                        let udp_size = rec.class;
                        let ext_rcode = ((rec.ttl >> 24) & 0xFF) as u8;
                        let version = ((rec.ttl >> 16) & 0xFF) as u8;
                        let flags = (rec.ttl & 0xFFFF) as u16;
                        Record {
                            data: RData::Opt {
                                udp_size,
                                ext_rcode,
                                version,
                                flags,
                                options,
                            },
                            ..rec
                        }
                    }
                    other => Record { data: other, ..rec },
                }
            } else {
                rec
            };
            msg.additional.push(rec);
        }

        // Fold extended RCODE from OPT into header.rcode.
        if let Some(opt) = msg.edns() {
            if let RData::Opt { ext_rcode, .. } = &opt.data {
                msg.header.rcode |= ext_rcode << 4;
            }
        }

        Ok(msg)
    }
}

// ---- encoding ---------------------------------------------------------------

struct Encoder {
    out: Vec<u8>,
    // canonical (lowercase, trailing-dot) name -> absolute offset
    name_map: HashMap<String, u16>,
}

impl Encoder {
    fn new() -> Self {
        Encoder {
            out: Vec::with_capacity(512),
            name_map: HashMap::new(),
        }
    }

    fn write_name(&mut self, name: &str) -> Result<()> {
        let name = canonical_name(name);
        if name == "." {
            self.out.push(0);
            return Ok(());
        }
        let trimmed = name.trim_end_matches('.').to_string();
        let labels: Vec<&str> = trimmed.split('.').collect();

        // Try longest-suffix compression: write leading labels uncompressed,
        // then a pointer to the already-written suffix.
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".") + ".";
            if let Some(&off) = self.name_map.get(&suffix) {
                for label in &labels[..i] {
                    if label.len() > 63 {
                        return Err(Error::Encode("label too long".into()));
                    }
                    self.out.push(label.len() as u8);
                    self.out.extend_from_slice(label.as_bytes());
                }
                let ptr = 0xC000u16 | off;
                self.out.extend_from_slice(&ptr.to_be_bytes());
                return Ok(());
            }
        }

        // Emit full name uncompressed, recording each suffix offset.
        for (i, label) in labels.iter().enumerate() {
            if label.len() > 63 {
                return Err(Error::Encode("label too long".into()));
            }
            let label_start = self.out.len();
            self.out.push(label.len() as u8);
            self.out.extend_from_slice(label.as_bytes());
            if label_start <= 0x3FFF {
                let suffix_key = labels[i..].join(".") + ".";
                self.name_map.insert(suffix_key, label_start as u16);
            }
        }
        self.out.push(0);
        Ok(())
    }

    fn write_question(&mut self, q: &Question) -> Result<()> {
        self.write_name(&q.name)?;
        self.out.extend_from_slice(&q.qtype.to_be_bytes());
        self.out.extend_from_slice(&q.qclass.to_be_bytes());
        Ok(())
    }

    fn write_record(&mut self, r: &Record) -> Result<()> {
        self.write_name(&r.name)?;
        self.out.extend_from_slice(&r.rtype.to_be_bytes());

        if r.rtype == TYPE_OPT {
            // OPT: class = UDP size, ttl = ext-rcode|version|flags
            if let RData::Opt {
                udp_size,
                ext_rcode,
                version,
                flags,
                ..
            } = &r.data
            {
                self.out.extend_from_slice(&udp_size.to_be_bytes());
                let ttl = ((*ext_rcode as u32) << 24) | ((*version as u32) << 16) | (*flags as u32);
                self.out.extend_from_slice(&ttl.to_be_bytes());
                let payload = encode_opt_rdata(r)?;
                self.out
                    .extend_from_slice(&(payload.len() as u16).to_be_bytes());
                self.out.extend_from_slice(&payload);
                return Ok(());
            }
        }

        self.out.extend_from_slice(&r.class.to_be_bytes());
        self.out.extend_from_slice(&r.ttl.to_be_bytes());

        let rdata = encode_rdata(self, r)?;
        self.out
            .extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        self.out.extend_from_slice(&rdata);
        Ok(())
    }
}

fn encode_opt_rdata(r: &Record) -> Result<Vec<u8>> {
    if let RData::Opt { options, .. } = &r.data {
        let mut out = Vec::new();
        for o in options {
            out.extend_from_slice(&o.code.to_be_bytes());
            out.extend_from_slice(&(o.data.len() as u16).to_be_bytes());
            out.extend_from_slice(&o.data);
        }
        Ok(out)
    } else {
        Err(Error::Encode("OPT record missing Opt data".into()))
    }
}

fn encode_rdata(enc: &mut Encoder, r: &Record) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match &r.data {
        RData::A(ip) => out.extend_from_slice(&ip.octets()),
        RData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
        RData::Name(name) => {
            // Need a temporary name encoder to capture bytes; reuse via a
            // nested encoder for name-only (offsets won't be shared, but name
            // compression within rdata is not required for validity).
            let mut tmp = Encoder::new();
            tmp.write_name(name)?;
            out.extend_from_slice(&tmp.out);
        }
        RData::Mx {
            preference,
            exchange,
        } => {
            out.extend_from_slice(&preference.to_be_bytes());
            let mut tmp = Encoder::new();
            tmp.write_name(exchange)?;
            out.extend_from_slice(&tmp.out);
        }
        RData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            let mut tmp = Encoder::new();
            tmp.write_name(mname)?;
            tmp.write_name(rname)?;
            out.extend_from_slice(&tmp.out);
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&refresh.to_be_bytes());
            out.extend_from_slice(&retry.to_be_bytes());
            out.extend_from_slice(&expire.to_be_bytes());
            out.extend_from_slice(&minimum.to_be_bytes());
        }
        RData::Txt(strings) => {
            for s in strings {
                out.push(s.len() as u8);
                out.extend_from_slice(s);
            }
        }
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            let mut tmp = Encoder::new();
            tmp.write_name(target)?;
            out.extend_from_slice(&tmp.out);
        }
        RData::Caa { flags, tag, value } => {
            out.push(*flags);
            out.push(tag.len() as u8);
            out.extend_from_slice(tag.as_bytes());
            out.extend_from_slice(value);
        }
        RData::Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        } => {
            out.extend_from_slice(&type_covered.to_be_bytes());
            out.push(*algorithm);
            out.push(*labels);
            out.extend_from_slice(&original_ttl.to_be_bytes());
            out.extend_from_slice(&expiration.to_be_bytes());
            out.extend_from_slice(&inception.to_be_bytes());
            out.extend_from_slice(&key_tag.to_be_bytes());
            let mut tmp = Encoder::new();
            tmp.write_name(signer_name)?;
            out.extend_from_slice(&tmp.out);
            out.extend_from_slice(signature);
        }
        RData::Nsec {
            next_domain,
            type_bitmaps,
        } => {
            let mut tmp = Encoder::new();
            tmp.write_name(next_domain)?;
            out.extend_from_slice(&tmp.out);
            out.extend_from_slice(type_bitmaps);
        }
        RData::Raw(bytes) => out.extend_from_slice(bytes),
        RData::Opt { .. } => {
            // Handled by write_record directly; never reached for OPT payload.
            return Err(Error::Encode("unexpected OPT in encode_rdata".into()));
        }
    }
    // NOTE: name compression is not applied inside RDATA (names are written
    // fully). This is always valid per RFC 1035.
    let _ = enc;
    Ok(out)
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut enc = Encoder::new();
        enc.out.extend_from_slice(&self.header.id.to_be_bytes());

        let mut flags: u16 = 0;
        if self.header.qr {
            flags |= 0x8000;
        }
        flags |= ((self.header.opcode as u16) & 0xF) << 11;
        if self.header.aa {
            flags |= 0x0400;
        }
        if self.header.tc {
            flags |= 0x0200;
        }
        if self.header.rd {
            flags |= 0x0100;
        }
        if self.header.ra {
            flags |= 0x0080;
        }
        if self.header.ad {
            flags |= 0x0020;
        }
        if self.header.cd {
            flags |= 0x0010;
        }
        flags |= (self.header.rcode & 0xF) as u16;
        enc.out.extend_from_slice(&flags.to_be_bytes());

        enc.out
            .extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        enc.out
            .extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        enc.out
            .extend_from_slice(&(self.authority.len() as u16).to_be_bytes());
        enc.out
            .extend_from_slice(&(self.additional.len() as u16).to_be_bytes());

        for q in &self.questions {
            enc.write_question(q)?;
        }
        for r in &self.answers {
            enc.write_record(r)?;
        }
        for r in &self.authority {
            enc.write_record(r)?;
        }
        for r in &self.additional {
            enc.write_record(r)?;
        }
        Ok(enc.out)
    }
}

/// Canonicalize a name to lowercase with a single trailing dot.
pub fn canonical_name(name: &str) -> String {
    let name = name.trim();
    let name = name.trim_end_matches('.');
    let lower = name.to_lowercase();
    if lower.is_empty() {
        ".".into()
    } else {
        format!("{}.", lower)
    }
}

/// Build a standard A/AAAA query with RD set and EDNS0 OPT.
pub fn build_query(name: &str, qtype: u16, id: u16, ecs: Option<&EcsInfo>) -> Message {
    let mut m = Message {
        header: Header {
            id,
            qr: false,
            opcode: 0,
            rd: true,
            ..Default::default()
        },
        questions: vec![Question {
            name: canonical_name(name),
            qtype,
            qclass: CLASS_IN,
        }],
        ..Default::default()
    };
    add_edns(&mut m, 1232, ecs);
    m
}

/// Add an EDNS0 OPT record (with optional ECS) to a message.
pub fn add_edns(m: &mut Message, udp_size: u16, ecs: Option<&EcsInfo>) {
    let mut options = Vec::new();
    if let Some(e) = ecs {
        options.push(OptOption {
            code: EDNS_OPT_ECS,
            data: e.encode(),
        });
    }
    m.additional.push(Record {
        name: ".".into(),
        rtype: TYPE_OPT,
        class: udp_size,
        ttl: 0,
        data: RData::Opt {
            udp_size,
            ext_rcode: 0,
            version: 0,
            flags: 0,
            options,
        },
    });
}

/// Strip the ECS option from an OPT record's option list (in place).
pub fn strip_ecs(m: &mut Message) {
    for r in m.additional.iter_mut() {
        if r.rtype == TYPE_OPT {
            if let RData::Opt { options, .. } = &mut r.data {
                options.retain(|o| o.code != EDNS_OPT_ECS);
            }
        }
    }
}

/// Echo an ECS scope into the response's OPT (RFC 7871 §7.2.2).
pub fn echo_ecs(m: &mut Message, ecs: &EcsInfo) {
    for r in m.additional.iter_mut() {
        if r.rtype == TYPE_OPT {
            if let RData::Opt { options, .. } = &mut r.data {
                if !options.iter().any(|o| o.code == EDNS_OPT_ECS) {
                    options.push(OptOption {
                        code: EDNS_OPT_ECS,
                        data: ecs.encode(),
                    });
                }
            }
            return;
        }
    }
    add_edns(m, 1232, Some(ecs));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_query() {
        let m = build_query("www.example.com", TYPE_A, 0x1234, None);
        let bytes = m.encode().unwrap();
        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(parsed.header.id, 0x1234);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "www.example.com.");
        assert_eq!(parsed.questions[0].qtype, TYPE_A);
        assert!(parsed.edns().is_some());
    }

    #[test]
    fn roundtrip_answer() {
        let mut m = build_query("example.com", TYPE_A, 1, None);
        m.header.qr = true;
        m.header.aa = true;
        m.answers.push(Record {
            name: "example.com.".into(),
            rtype: TYPE_A,
            class: CLASS_IN,
            ttl: 300,
            data: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
        });
        let bytes = m.encode().unwrap();
        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        match &parsed.answers[0].data {
            RData::A(ip) => assert_eq!(*ip, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("wrong rdata {:?}", other),
        }
    }

    #[test]
    fn ecs_roundtrip() {
        let ecs = EcsInfo {
            family: 1,
            source_prefix: 24,
            scope_prefix: 0,
            address: Some(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0))),
        };
        let m = build_query("example.com", TYPE_A, 1, Some(&ecs));
        let bytes = m.encode().unwrap();
        let parsed = Message::parse(&bytes).unwrap();
        let got = parsed.ecs().unwrap();
        assert_eq!(got.source_prefix, 24);
        assert_eq!(got.family, 1);
        match got.address {
            Some(std::net::IpAddr::V4(ip)) => assert_eq!(ip, Ipv4Addr::new(203, 0, 113, 0)),
            _ => panic!("wrong ecs addr"),
        }
    }

    #[test]
    fn compression_pointers_resolve() {
        // Build a referral: NS + glue, encode, reparse, check names.
        let mut m = Message::default();
        m.header.qr = true;
        m.questions.push(Question {
            name: "www.example.com.".into(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        });
        m.authority.push(Record {
            name: "example.com.".into(),
            rtype: TYPE_NS,
            class: CLASS_IN,
            ttl: 172800,
            data: RData::Name("ns1.example.com.".into()),
        });
        m.additional.push(Record {
            name: "ns1.example.com.".into(),
            rtype: TYPE_A,
            class: CLASS_IN,
            ttl: 172800,
            data: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        });
        let bytes = m.encode().unwrap();
        let parsed = Message::parse(&bytes).unwrap();
        assert_eq!(parsed.authority.len(), 1);
        match &parsed.authority[0].data {
            RData::Name(n) => assert_eq!(n, "ns1.example.com."),
            other => panic!("wrong ns rdata {:?}", other),
        }
        assert_eq!(parsed.additional[0].name, "ns1.example.com.");
    }
}
