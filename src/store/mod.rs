//! MySQL primary store: schema bootstrap + repositories for zones, records,
//! blocklist, dualstack bindings and users.
//!
//! The resolver loads these into memory at startup and hot-reloads them via
//! the management API. MySQL is treated as the system of record (primary DB);
//! if it is unreachable at boot the resolver still serves recursion with empty
//! policy tables and logs a warning (never crashes the data plane).

use crate::error::{Error, Result};
use crate::model::{BlockMode, BlockedDomain, DualstackBinding, Role, User, Zone, ZoneRecord};
use mysql::prelude::Queryable;
use mysql::{Pool, PooledConn};

pub mod logs;
pub use logs::{AuditWriter, QueryLogWriter};

#[derive(Clone)]
pub struct Store {
    pool: Option<Pool>,
}

impl Store {
    pub fn connect(dsn: &str, _max_conns: u32) -> Store {
        match Pool::new(mysql::Opts::from_url(dsn).expect("bad mysql dsn")) {
            Ok(pool) => Store { pool: Some(pool) },
            Err(e) => {
                tracing::warn!("MySQL connect failed ({}); running without primary DB", e);
                Store { pool: None }
            }
        }
    }

    pub fn available(&self) -> bool {
        self.pool.is_some()
    }

    fn conn(&self) -> Result<PooledConn> {
        match &self.pool {
            Some(p) => Ok(p.get_conn().map_err(Error::from)?),
            None => Err(Error::Db("MySQL unavailable".into())),
        }
    }

    pub fn ping(&self) -> Result<()> {
        let mut c = self.conn()?;
        c.query_drop("SELECT 1").map_err(Error::from)
    }

    /// Create tables if absent (idempotent).
    pub fn ensure_schema(&self) -> Result<()> {
        if self.pool.is_none() {
            return Ok(());
        }
        let mut c = self.conn()?;
        c.query_drop(SCHEMA).map_err(Error::from)
    }

    // ---- reads -------------------------------------------------------------

    pub fn load_zones(&self) -> Result<Vec<Zone>> {
        if self.pool.is_none() {
            return Ok(vec![]);
        }
        let mut c = self.conn()?;
        let rows = c
            .exec_map(
                "SELECT id, name, enabled FROM zones WHERE enabled = 1",
                (),
                |(id, name, enabled): (String, String, i8)| Zone {
                    id,
                    name,
                    enabled: enabled != 0,
                },
            )
            .map_err(Error::from)?;
        Ok(rows)
    }

    pub fn load_zone_records(&self) -> Result<Vec<ZoneRecord>> {
        if self.pool.is_none() {
            return Ok(vec![]);
        }
        let mut c = self.conn()?;
        let rows = c
            .exec_map(
                "SELECT id, zone_id, name, rtype, value, ttl, priority, enabled \
                 FROM zone_records WHERE enabled = 1",
                (),
                |(id, zone_id, name, rtype, value, ttl, priority, enabled): (
                    String,
                    String,
                    String,
                    String,
                    String,
                    u32,
                    u16,
                    i8,
                )| ZoneRecord {
                    id,
                    zone_id,
                    name,
                    rtype,
                    value,
                    ttl,
                    priority,
                    enabled: enabled != 0,
                },
            )
            .map_err(Error::from)?;
        Ok(rows)
    }

    pub fn load_blocked(&self) -> Result<Vec<BlockedDomain>> {
        if self.pool.is_none() {
            return Ok(vec![]);
        }
        let mut c = self.conn()?;
        let rows = c
            .exec_map(
                "SELECT id, domain, mode, enabled FROM blocked_domains WHERE enabled = 1",
                (),
                |(id, domain, mode, enabled): (String, String, String, i8)| BlockedDomain {
                    id,
                    domain,
                    mode: BlockMode::from_str(&mode),
                    enabled: enabled != 0,
                },
            )
            .map_err(Error::from)?;
        Ok(rows)
    }

    pub fn load_bindings(&self) -> Result<Vec<DualstackBinding>> {
        if self.pool.is_none() {
            return Ok(vec![]);
        }
        let mut c = self.conn()?;
        let rows = c
            .exec_map(
                "SELECT id, ipv6_subnet, ipv4, isp, region, enabled \
                 FROM dualstack_bindings WHERE enabled = 1",
                (),
                |(id, ipv6_subnet, ipv4, isp, region, enabled): (
                    String,
                    String,
                    String,
                    String,
                    String,
                    i8,
                )| DualstackBinding {
                    id,
                    ipv6_subnet,
                    ipv4,
                    isp,
                    region,
                    enabled: enabled != 0,
                },
            )
            .map_err(Error::from)?;
        Ok(rows)
    }

    pub fn load_user(&self, username: &str) -> Result<Option<User>> {
        if self.pool.is_none() {
            return Ok(None);
        }
        let mut c = self.conn()?;
        let row: Option<(String, String, String, String, i8, i32, Option<i64>)> = c
            .exec_first(
                "SELECT id, username, password_hash, role, must_change_pwd, \
                 failed_attempts, UNIX_TIMESTAMP(locked_until) \
                 FROM users WHERE username = ?",
                (username,),
            )
            .map_err(Error::from)?;
        Ok(row.map(
            |(
                id,
                username,
                password_hash,
                role,
                must_change_pwd,
                failed_attempts,
                locked_until,
            )| {
                User {
                    id,
                    username,
                    password_hash,
                    role: Role::from_str(&role),
                    must_change_pwd: must_change_pwd != 0,
                    failed_attempts,
                    locked_until,
                }
            },
        ))
    }

    // ---- writes (admin API) -------------------------------------------------

    pub fn insert_zone(&self, name: &str) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut c = self.conn()?;
        c.exec_drop(
            "INSERT INTO zones (id, name, enabled) VALUES (?, ?, 1)",
            (id.clone(), name.to_lowercase()),
        )
        .map_err(Error::from)?;
        Ok(id)
    }

    pub fn insert_zone_record(&self, zr: &ZoneRecord) -> Result<()> {
        let mut c = self.conn()?;
        c.exec_drop(
            "INSERT INTO zone_records (id, zone_id, name, rtype, value, ttl, priority, enabled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            (
                zr.id.clone(),
                zr.zone_id.clone(),
                zr.name.clone(),
                zr.rtype.clone(),
                zr.value.clone(),
                zr.ttl,
                zr.priority,
            ),
        )
        .map_err(Error::from)?;
        Ok(())
    }

    pub fn insert_blocked(&self, domain: &str, mode: &str) -> Result<()> {
        let mut c = self.conn()?;
        c.exec_drop(
            "INSERT INTO blocked_domains (id, domain, mode, enabled) VALUES (?, ?, ?, 1)",
            (
                uuid::Uuid::new_v4().to_string(),
                domain.to_lowercase(),
                mode,
            ),
        )
        .map_err(Error::from)?;
        Ok(())
    }

    pub fn delete_blocked(&self, domain: &str) -> Result<()> {
        let mut c = self.conn()?;
        c.exec_drop(
            "DELETE FROM blocked_domains WHERE domain = ?",
            (domain.to_lowercase(),),
        )
        .map_err(Error::from)?;
        Ok(())
    }
}

/// Minimal schema (MySQL 8.x / MariaDB 10.6+), idempotent.
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS zones (
  id CHAR(36) NOT NULL PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_zones_name (name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS zone_records (
  id CHAR(36) NOT NULL PRIMARY KEY,
  zone_id CHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  rtype VARCHAR(16) NOT NULL,
  value VARCHAR(512) NOT NULL,
  ttl INT UNSIGNED NOT NULL DEFAULT 300,
  priority SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_zr_zone (zone_id),
  INDEX idx_zr_name (name),
  CONSTRAINT fk_zr_zone FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS blocked_domains (
  id CHAR(36) NOT NULL PRIMARY KEY,
  domain VARCHAR(255) NOT NULL UNIQUE,
  mode ENUM('loopback','random') NOT NULL DEFAULT 'loopback',
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_bd_domain (domain)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS dualstack_bindings (
  id CHAR(36) NOT NULL PRIMARY KEY,
  ipv6_subnet VARCHAR(45) NOT NULL,
  ipv4 VARCHAR(15) NOT NULL,
  isp VARCHAR(64) NULL,
  region VARCHAR(128) NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_dsb_subnet (ipv6_subnet)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS users (
  id CHAR(36) NOT NULL PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin','sysadmin','secadmin','auditadmin','tenant') NOT NULL DEFAULT 'tenant',
  must_change_pwd TINYINT(1) NOT NULL DEFAULT 1,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until DATETIME(3) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS password_history (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id CHAR(36) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_ph_user (user_id),
  CONSTRAINT fk_ph_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS query_logs (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ts_ms BIGINT NOT NULL,
  client_ip VARCHAR(45) NOT NULL,
  ecs VARCHAR(45) NULL,
  qname VARCHAR(255) NOT NULL,
  qtype VARCHAR(16) NOT NULL,
  rcode VARCHAR(16) NOT NULL,
  cache_hit TINYINT(1) NOT NULL DEFAULT 0,
  upstream VARCHAR(128) NULL,
  rtt_ms INT NOT NULL DEFAULT 0,
  blocked TINYINT(1) NOT NULL DEFAULT 0,
  via VARCHAR(8) NOT NULL DEFAULT 'udp',
  INDEX idx_ql_ts (ts_ms),
  INDEX idx_ql_qname (qname(64))
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ts_ms BIGINT NOT NULL,
  actor VARCHAR(64) NULL,
  action VARCHAR(64) NOT NULL,
  target VARCHAR(255) NULL,
  detail JSON NULL,
  client_ip VARCHAR(45) NULL,
  prev_hash CHAR(64) NULL,
  entry_hash CHAR(64) NULL,
  verifier VARCHAR(64) NULL,
  INDEX idx_audit_ts (ts_ms),
  INDEX idx_audit_hash (entry_hash)
) ENGINE=InnoDB;
"#;
