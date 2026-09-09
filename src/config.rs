//! Runtime configuration loaded from environment variables (with optional
//! `.env` dotenv file). Mirrors the upstream Go platform's env surface for the
//! features this resolver keeps.

use crate::error::{Error, Result};
use std::env;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub env: String,
    pub instance_id: String,

    // Listeners (downstream, client-facing)
    pub dns_listen_udp: String,
    pub dns_listen_tcp: String,
    pub doh_listen: String,
    pub dot_listen: String,
    pub tls_cert_file: Option<PathBuf>,
    pub tls_key_file: Option<PathBuf>,

    // MySQL (primary store: metadata + logs + audit)
    pub mysql_dsn: String,
    pub mysql_max_conns: u32,

    // Cache tiers
    pub l1_max_entries: usize,
    pub l1_ttl_secs: u64,
    pub l2_path: PathBuf,
    pub l2_max_bytes: u64,
    pub redis_addr: String,
    pub redis_db: i64,
    pub cache_max_ttl: Duration,
    pub neg_cache_ttl: Duration,

    // Recursion
    pub root_hints: Vec<String>, // fallback when built-in hints unavailable
    pub recurse_timeout: Duration,
    pub recurse_max_depth: u8,
    pub upstream_timeout: Duration,
    pub ns_probe_timeout: Duration,

    // Logging / audit
    pub log_batch_size: usize,
    pub log_flush_interval: Duration,

    // ECS
    pub ecs_passthrough: bool,
    pub ecs_scope_max: u8,

    // IPv6 -> IPv4 dualstack
    pub dualstack_enabled: bool,
    pub nat64_prefixes: Vec<String>,
    pub ipv6_ipv4_map_file: Option<PathBuf>,
    pub ipv6_ipv4_map_api_url: Option<String>,
    pub ipv6_ipv4_map_api_timeout: Duration,
    pub ecs_derive_mask: u8,
    pub geo_ipv4_file: Option<PathBuf>, // 纯真 qqwry.dat
    pub geo_ipv6_file: Option<PathBuf>,
    pub geo_strict_city: bool,

    // Rate limiting
    pub rate_limit_qps: u32,

    // API
    pub api_listen: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // Optional .env loading (KEY=VALUE per line, env vars win).
        if let Some(path) = env::var_os("DNSD_ENV_FILE") {
            load_dotenv(&PathBuf::from(path));
        } else if PathBuf::from(".env").exists() {
            load_dotenv(&PathBuf::from(".env"));
        }

        let cfg = Config {
            env: get("ENV", "dev"),
            instance_id: get("INSTANCE_ID", &format!("inst-{}", hostname())),

            dns_listen_udp: get("DNS_LISTEN_UDP", "0.0.0.0:5300"),
            dns_listen_tcp: get("DNS_LISTEN_TCP", "0.0.0.0:5300"),
            doh_listen: get("DOH_LISTEN", ""),
            dot_listen: get("DOT_LISTEN", ""),
            tls_cert_file: get_opt("TLS_CERT_FILE").map(PathBuf::from),
            tls_key_file: get_opt("TLS_KEY_FILE").map(PathBuf::from),

            mysql_dsn: get("MYSQL_DSN", "mysql://dns:dns@127.0.0.1:3306/dns_platform"),
            mysql_max_conns: get_u32("MYSQL_MAX_CONNS", 32),

            l1_max_entries: get_usize("L1_MAX_ENTRIES", 131072),
            l1_ttl_secs: get_u64("L1_TTL_SECS", 60),
            l2_path: PathBuf::from(get("L2_PATH", "data/l2-cache")),
            l2_max_bytes: get_u64("L2_MAX_BYTES", 4 * 1024 * 1024 * 1024),
            redis_addr: get("REDIS_ADDR", "127.0.0.1:6379"),
            redis_db: get_i64("REDIS_DB", 0),
            cache_max_ttl: Duration::from_secs(get_u64("CACHE_MAX_TTL", 21600)),
            neg_cache_ttl: Duration::from_secs(get_u64("NEG_CACHE_TTL", 30)),

            root_hints: get_csv("ROOT_HINTS"),
            recurse_timeout: Duration::from_secs(get_u64("RECURSE_TIMEOUT", 10)),
            recurse_max_depth: get_u8("RECURSE_MAX_DEPTH", 12),
            upstream_timeout: Duration::from_millis(get_u64("UPSTREAM_TIMEOUT_MS", 4000)),
            ns_probe_timeout: Duration::from_millis(get_u64("NS_PROBE_TIMEOUT_MS", 2000)),

            log_batch_size: get_usize("LOG_BATCH_SIZE", 500),
            log_flush_interval: Duration::from_secs(get_u64("LOG_FLUSH_INTERVAL", 2)),

            ecs_passthrough: get_bool("ECS_PASSTHROUGH", true),
            ecs_scope_max: get_u8("ECS_SCOPE_MAX", 24),

            dualstack_enabled: get_bool("DUALSTACK_ENABLED", false),
            nat64_prefixes: get_csv("NAT64_PREFIXES"),
            ipv6_ipv4_map_file: get_opt("IPV6_IPV4_MAP_FILE").map(PathBuf::from),
            ipv6_ipv4_map_api_url: get_opt("IPV6_IPV4_MAP_API_URL"),
            ipv6_ipv4_map_api_timeout: Duration::from_millis(get_u64(
                "IPV6_IPV4_MAP_API_TIMEOUT_MS",
                500,
            )),
            ecs_derive_mask: get_u8("ECS_DERIVE_MASK", 32),
            geo_ipv4_file: get_opt("GEO_IPV4_FILE").map(PathBuf::from),
            geo_ipv6_file: get_opt("GEO_IPV6_FILE").map(PathBuf::from),
            geo_strict_city: get_bool("GEO_STRICT_CITY", false),

            rate_limit_qps: get_u32("RATE_LIMIT_QPS", 100),

            api_listen: get("API_LISTEN", "127.0.0.1:8080"),
        };

        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.env != "dev" && self.env != "prod" {
            return Err(Error::Config("ENV must be dev or prod".into()));
        }
        if self.ecs_scope_max > 32 {
            return Err(Error::Config("ECS_SCOPE_MAX must be 0..32".into()));
        }
        if self.ecs_derive_mask > 32 {
            return Err(Error::Config("ECS_DERIVE_MASK must be 0..32".into()));
        }
        Ok(())
    }
}

fn hostname() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

fn load_dotenv(path: &PathBuf) {
    let Ok(data) = std::fs::read_to_string(path) else {
        return;
    };
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim().trim_matches('"').trim_matches('\'');
            if env::var_os(k).is_none() {
                env::set_var(k, v);
            }
        }
    }
}

fn get(key: &str, def: &str) -> String {
    env::var(key).unwrap_or_else(|_| def.to_string())
}

fn get_opt(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

fn get_u32(key: &str, def: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(def)
}

fn get_u64(key: &str, def: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(def)
}

fn get_i64(key: &str, def: i64) -> i64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(def)
}

fn get_usize(key: &str, def: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(def)
}

fn get_u8(key: &str, def: u8) -> u8 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(def)
}

fn get_bool(key: &str, def: bool) -> bool {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(def)
}

fn get_csv(key: &str) -> Vec<String> {
    env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Placeholder secret detection (等保: reject un-replaced sample secrets).
#[allow(dead_code)]
fn is_placeholder(s: &str) -> bool {
    let up = s.to_uppercase();
    [
        "CHANGE_ME",
        "CHANGEME",
        "PLACEHOLDER",
        "YOUR_SECRET",
        "EXAMPLE",
    ]
    .iter()
    .any(|p| up.contains(p))
}
