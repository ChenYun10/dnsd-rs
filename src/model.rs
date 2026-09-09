//! Domain models shared across the resolver, store and API layers.
//!
//! Mirrors the upstream Go platform's data model, trimmed to the features this
//! resolver needs: custom zones, domain blocking, dualstack bindings, RBAC
//! users, query logs (等保) and tamper-evident audit logs.

use serde::{Deserialize, Serialize};

/// 等保三员分立 roles. `admin` is the legacy super-admin alias for `sysadmin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Admin,
    SysAdmin,
    SecAdmin,
    AuditAdmin,
    Tenant,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::SysAdmin => "sysadmin",
            Role::SecAdmin => "secadmin",
            Role::AuditAdmin => "auditadmin",
            Role::Tenant => "tenant",
        }
    }

    pub fn from_str(s: &str) -> Role {
        match s {
            "admin" => Role::Admin,
            "sysadmin" => Role::SysAdmin,
            "secadmin" => Role::SecAdmin,
            "auditadmin" => Role::AuditAdmin,
            _ => Role::Tenant,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: Role,
    pub must_change_pwd: bool,
    pub failed_attempts: i32,
    pub locked_until: Option<i64>,
}

/// A custom DNS zone (authoritative domain we serve ourselves).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String, // canonical, lowercase, no trailing dot
    pub enabled: bool,
}

/// One record inside a custom zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneRecord {
    pub id: String,
    pub zone_id: String,
    /// Full name (subdomain) or "@" for apex. Lowercase.
    pub name: String,
    /// A, AAAA, CNAME, TXT, MX, NS, SRV, CAA, PTR
    pub rtype: String,
    /// rdata string in presentation format (e.g. "192.0.2.1", "mail.example.com.")
    pub value: String,
    pub ttl: u32,
    pub priority: u16, // for MX/SRV
    pub enabled: bool,
}

/// A blocked domain. Blocked qnames resolve to 127.0.0.1/::1 or a random IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedDomain {
    pub id: String,
    pub domain: String, // exact or wildcard ("*.example.com")
    pub mode: BlockMode,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockMode {
    Loopback, // 127.0.0.1 / ::1
    Random,   // random RFC1918-style private IP, stable per qname+client
}

impl BlockMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockMode::Loopback => "loopback",
            BlockMode::Random => "random",
        }
    }
    pub fn from_str(s: &str) -> BlockMode {
        match s {
            "random" => BlockMode::Random,
            _ => BlockMode::Loopback,
        }
    }
}

/// IPv6 subnet -> client real IPv4 binding (运营商 BRAS / 地址分配).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualstackBinding {
    pub id: String,
    pub ipv6_subnet: String, // e.g. 2001:db8:100::/48
    pub ipv4: String,        // e.g. 116.62.52.1
    pub isp: String,
    pub region: String,
    pub enabled: bool,
}

/// One DNS query record, written asynchronously to MySQL (等保 query log).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogRow {
    pub ts_ms: i64,
    pub client_ip: String,
    pub ecs: String,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub cache_hit: bool,
    pub upstream: String, // authoritative NS used, or "cache" / "block" / "zone"
    pub rtt_ms: i64,
    pub blocked: bool,
    pub via: String, // udp|tcp|doh|dot
}

/// Tamper-evident audit log row (append-only, SHA-256 hash chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRow {
    pub ts_ms: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String, // JSON
    pub client_ip: String,
    pub prev_hash: String,
    pub entry_hash: String,
}
