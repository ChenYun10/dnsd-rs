//! dnsd-rs — self-built Rust DNS recursive resolver.
//!
//! Entry point: wires config → MySQL store → tiered cache (L1/L2/L3) →
//! recursive resolver → dualstack → pipeline, then starts UDP/TCP/DoH/API.

mod api;
mod cache;
mod config;
mod error;
mod model;
mod proto;
mod resolve;
mod server;
mod store;

use config::Config;
use resolve::dualstack::Dualstack;
use resolve::recurse::Resolver;
use resolve::Pipeline;
use std::sync::Arc;
use store::{AuditWriter, QueryLogWriter, Store};

fn main() {
    // Logging
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    // Config
    let cfg = match Config::from_env() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!("config error: {}", e);
            std::process::exit(1);
        }
    };

    // MySQL (primary store). Best-effort: resolver still runs without it.
    let store = Store::connect(&cfg.mysql_dsn, cfg.mysql_max_conns);
    if let Err(e) = store.ensure_schema() {
        tracing::warn!("schema bootstrap failed: {}", e);
    }

    // Cache tiers.
    let cache = cache::TieredCache::new(&cfg);

    // Recursive resolver.
    let resolver = Resolver::new(Arc::clone(&cfg));

    // IPv6 → IPv4 dualstack.
    let dualstack = Dualstack::new(Arc::clone(&cfg));

    // Log writers (等保 query log + tamper-evident audit log).
    let logger = QueryLogWriter::new(store.clone(), cfg.log_batch_size, cfg.log_flush_interval);
    let audit = AuditWriter::new(store.clone(), &cfg.instance_id);

    // Pipeline.
    let pipeline = Arc::new(Pipeline::new(
        Arc::clone(&cfg),
        cache,
        resolver,
        logger,
        dualstack,
    ));

    // Initial policy load (zones / blocklist / bindings).
    if let Err(e) = api::reload_all(&store, &pipeline) {
        tracing::warn!("initial policy load failed: {}", e);
    }

    // Start DNS listeners.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        * 2;

    if let Err(e) = server::serve_udp(&cfg.dns_listen_udp, Arc::clone(&pipeline), workers) {
        tracing::error!("UDP listen failed on {}: {}", cfg.dns_listen_udp, e);
        std::process::exit(1);
    }
    if let Err(e) = server::serve_tcp(&cfg.dns_listen_tcp, Arc::clone(&pipeline)) {
        tracing::error!("TCP listen failed on {}: {}", cfg.dns_listen_tcp, e);
        std::process::exit(1);
    }

    // DoH (plaintext HTTP; put nginx in front for TLS in production).
    if !cfg.doh_listen.is_empty() {
        match std::net::TcpListener::bind(&cfg.doh_listen) {
            Ok(l) => {
                tracing::info!("DoH listening on {}", cfg.doh_listen);
                server::doh::serve_doh(l, Arc::clone(&pipeline));
            }
            Err(e) => tracing::warn!("DoH listen failed on {}: {}", cfg.doh_listen, e),
        }
    }

    // Management API.
    if !cfg.api_listen.is_empty() {
        let api = api::Api::new(store.clone(), Arc::clone(&pipeline), audit);
        if let Err(e) = api.serve(&cfg.api_listen) {
            tracing::warn!("API listen failed on {}: {}", cfg.api_listen, e);
        }
    }

    tracing::info!(
        "dnsd-rs started (instance={}, udp={}, tcp={})",
        cfg.instance_id,
        cfg.dns_listen_udp,
        cfg.dns_listen_tcp
    );

    // Keep the process alive (all listeners run on their own threads).
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
