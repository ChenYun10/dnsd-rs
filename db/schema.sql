-- ============================================================================
-- dnsd-rs schema (MySQL 8.x / MariaDB 10.6+)
-- 幂等：全部 CREATE TABLE IF NOT EXISTS
-- 应用方式:  mysql -u root -p dns_platform < db/schema.sql
-- 注意：先 CREATE DATABASE dns_platform（见下方）
-- ============================================================================

CREATE DATABASE IF NOT EXISTS dns_platform
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE dns_platform;

-- 自定义域名（权威区）
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

-- 域名拦截（拦截后解析 127.0.0.1 或随机 IP）
CREATE TABLE IF NOT EXISTS blocked_domains (
  id CHAR(36) NOT NULL PRIMARY KEY,
  domain VARCHAR(255) NOT NULL UNIQUE,
  mode ENUM('loopback','random') NOT NULL DEFAULT 'loopback',
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  INDEX idx_bd_domain (domain)
) ENGINE=InnoDB;

-- 内网双栈绑定表（IPv6 子网 → 客户端真实公网 IPv4）
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

-- 用户（等保三员分立）
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

-- 查询日志（等保：全量查询留痕，异步批量写入）
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

-- 审计日志（等保：只追加 + SHA-256 哈希链防篡改）
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

-- ---------------------------------------------------------------------------
-- 种子数据示例（可选）
-- ---------------------------------------------------------------------------
INSERT INTO blocked_domains (id, domain, mode, enabled)
SELECT '11111111-0000-0000-0000-000000000001', 'ads.example.com', 'loopback', 1
WHERE NOT EXISTS (SELECT 1 FROM blocked_domains WHERE domain = 'ads.example.com');
