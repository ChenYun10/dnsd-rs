# dnsd-rs — 自建 Rust DNS 递归解析器

一个用 Rust 从零实现的 **递归 DNS 解析器**（迭代解析：根服务器 → 顶级域 → 权威 NS），
数据库主用 **MySQL**，缓存走 **L1(内存) + L2(自建内嵌 KV) + L3(Redis 备用)** 三层，
保留等保审计日志、自定义域名解析、域名拦截、ECS、IPv6→IPv4 双栈推导等能力。

核心定位与参考项目 [DNSD-DNS-Management-System](https://github.com/ChenYun10/DNSD-DNS-Management-System)
（Go 实现）一致，但把「转发网关」升级为「真正的递归解析器」，并强化了缓存分层。

## 架构

```
┌──────────┐  UDP/TCP:53  ┌──────────────────────────────┐
│  客户端   │ ───────────► │  dnsd 数据面（多线程）        │
│  DoH      │ ──(HTTP)───► │   ┌────────────────────────┐ │
└──────────┘              │   │  Pipeline               │ │
                          │   │  parse→rate→ECS→block→  │ │
┌──────────┐  REST:8080   │   │  zone→cache→recurse→log │ │
│  管理端   │ ───────────► │   └───────┬────────────────┘ │
└──────────┘              │           │                   │
                          │   ┌───────▼────────┐  ┌───────▼─────────┐
                          │   │ 递归解析器      │  │ 三层缓存         │
                          │   │ 根→权威(NS连通) │  │ L1内存/L2内嵌KV  │
                          │   └────────────────┘  │ L3 Redis(备用)   │
                          └──────────┬────────────┴────────┬─────────┘
                                     │                     │
                            MySQL(元数据+日志+审计)     Redis(备用缓存)
```

## 功能清单

| 模块 | 说明 |
|---|---|
| **递归解析** | 内置 13 台根服务器，迭代解析到权威 NS；UDP 超时 + 截断转 TCP（RFC 7766）；**逐台尝试 NS，挂了的自动跳过**（保证到目标域名 NS 通联正常）；glue + CNAME 追逐；单飞防缓存击穿 |
| **MySQL 主库** | 元数据（自定义域名/拦截表/双栈绑定表）+ 全量查询日志 + 审计日志；连接池；**不可用时数据面仍运行**（降级为空策略） |
| **三层缓存** | **L1**：进程内分片内存缓存（热路径，<1ms）；**L2**：自建 Bitcask 风格内嵌 KV（追加日志 + 内存索引 + 后台压缩，持久化）；**L3**：Redis 备用（自建最小 RESP 客户端，fire-and-forget 写入） |
| **日志审查（等保）** | 全量查询日志异步批量落库（不阻塞解析）；审计日志只追加 + **SHA-256 哈希链防篡改**（prev_hash/entry_hash） |
| **自定义域名解析** | `zones` + `zone_records` 表，权威应答（A/AAAA/CNAME/TXT/MX/NS/SRV/CAA，支持 `@` 与 `*.zone` 通配），热加载 |
| **域名拦截** | `blocked_domains` 表，精确 + `*.example.com` 通配；拦截后解析 **127.0.0.1/::1 或随机 IP**（按域名+客户端确定性生成，稳定） |
| **ECS** | RFC 7871 提取/收敛 scope/回显/透传，缓存按 `域名×类型×ECS` 分片 |
| **IPv6→IPv4 双栈** | 内网 IPv6 客户端反推公网 IPv4 透传 ECS：内嵌(::ffff/NAT64) → 绑定表最长前缀匹配 → 外部 API；纯真 qqwry.dat + IPv6 CSV 归属地/运营商一致性校验（失败不携带 ECS） |
| **协议** | UDP / TCP（RFC 1035）、DoH（RFC 8484，明文 HTTP，生产由 nginx 提供 TLS） |
| **管理 API** | healthz/readyz/stats/reload + 自定义域名、记录、拦截表 CRUD |

## 目录结构

```
dnsd-rs/
├── src/
│   ├── main.rs            # 入口：装配 + 启动监听
│   ├── config.rs          # 环境变量配置
│   ├── model.rs           # 领域模型
│   ├── proto.rs           # 自建 DNS wire 编解码（RFC 1035 + 压缩 + EDNS/ECS）
│   ├── cache/             # L1 内存 / L2 内嵌 KV / L3 Redis / 门面
│   ├── store/             # MySQL 仓储 + 查询日志 + 审计哈希链
│   ├── resolve/           # 递归解析器 / ECS / 拦截 / 自定义域名 / 双栈 / 纯真库
│   ├── server/            # UDP / TCP / DoH / HTTP
│   └── api/               # 管理 REST API
├── db/schema.sql          # MySQL 建表脚本（幂等）
├── .env.example           # 配置示例
└── Makefile
```

## 构建

```bash
cargo build --release        # 产物 target/release/dnsd.exe（Windows）或 dnsd（Linux）
```

> Windows 无 MSVC Build Tools 时，本仓库 `.cargo/config.toml` 已用 `rust-lld` 作链接器，
> 并安装 `stable-x86_64-pc-windows-msvc` 工具链即可，无需 Visual Studio。

## 快速开始

1. 建库：`mysql -u root -p < db/schema.sql`
2. 配置：`cp .env.example .env`，改 `MYSQL_DSN`、监听端口
3. 运行：`cargo run`
4. 验证（本机开发端口 :5300）：

```bash
# 递归解析（会从根服务器迭代到权威 NS）
dig @127.0.0.1 -p 5300 www.example.com A

# 添加拦截域名
curl -X POST http://127.0.0.1:8080/api/v1/blocked -H "Content-Type: application/json" \
  -d '{"domain":"ads.example.com","mode":"loopback"}'

# 添加自定义域名 + 记录
curl -X POST http://127.0.0.1:8080/api/v1/zones -H "Content-Type: application/json" \
  -d '{"name":"internal.example.com"}'
curl -X POST http://127.0.0.1:8080/api/v1/zones/records -H "Content-Type: application/json" \
  -d '{"zone_id":"<上一步返回或查询 zones>","name":"@","rtype":"A","value":"10.1.2.3","ttl":300}'

# 热加载（写库后手动触发，或写接口已自动 reload）
curl -X POST http://127.0.0.1:8080/api/v1/reload
```

## 关键配置项

见 `.env.example`。要点：

- `MYSQL_DSN`：主库连接串（元数据 + 日志 + 审计）
- `L2_PATH` / `L2_MAX_BYTES`：自建内嵌 KV 的目录与容量上限
- `REDIS_ADDR`：L3 备用缓存（留空禁用）
- `DUALSTACK_ENABLED` + `NAT64_PREFIXES` + `IPV6_IPV4_MAP_FILE`/`dualsack_bindings` 表 + `GEO_IPV4_FILE`(纯真 qqwry.dat) + `GEO_IPV6_FILE`(IPv6 归属 CSV)：IPv6→IPv4 反推
- `ECS_SCOPE_MAX` / `ECS_DERIVE_MASK`：ECS 收敛与推导掩码

## 说明与边界

- **DoT/DoQ 未实现**：DoH 走明文 HTTP，生产环境由 nginx/前置网关提供 TLS。若需进程内 TLS，
  可加回 `rustls`（需对应 C 编译环境，见提交历史）。
- **DNSSEC 为透传**（DO/AD 位透传），未做本地 RRSIG 校验；等保场景如需校验可后续加。
- **管理 API 默认绑定 127.0.0.1**，生产环境应置于反代之后并加认证/审计（审计哈希链已就绪）。
- 纯真库 `qqwry.dat` 与 IPv6 归属 CSV 需自行获取，路径见 `.env.example`。
