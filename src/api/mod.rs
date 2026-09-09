//! Management REST API: health, stats, reload, and CRUD for custom zones,
//! records, and the blocklist. Minimal hand-rolled HTTP (no framework).

use crate::model::ZoneRecord;
use crate::resolve::Pipeline;
use crate::server::http::{read_request, write_response};
use crate::store::{AuditWriter, Store};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

pub struct Api {
    store: Store,
    pipeline: Arc<Pipeline>,
    audit: Arc<AuditWriter>,
}

impl Api {
    pub fn new(store: Store, pipeline: Arc<Pipeline>, audit: Arc<AuditWriter>) -> Arc<Api> {
        Arc::new(Api {
            store,
            pipeline,
            audit,
        })
    }

    pub fn serve(self: Arc<Self>, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        tracing::info!("management API listening on {}", addr);
        thread::Builder::new()
            .name("api-accept".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    if let Ok(mut stream) = conn {
                        let this = Arc::clone(&self);
                        thread::Builder::new()
                            .name("api-conn".into())
                            .spawn(move || {
                                let _ = stream
                                    .set_read_timeout(Some(std::time::Duration::from_secs(15)));
                                this.handle(&mut stream);
                            })
                            .ok();
                    }
                }
            })?;
        Ok(())
    }

    fn handle(&self, stream: &mut std::net::TcpStream) {
        let Ok(Some(req)) = read_request(stream) else {
            return;
        };
        let client_ip = stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();

        let (status, reason, ctype, body) = self.route(&req, &client_ip);

        let _ = write_response(stream, status, reason, ctype, &body, &[]);
    }

    fn route(
        &self,
        req: &crate::server::http::HttpRequest,
        client_ip: &str,
    ) -> (u16, &'static str, &'static str, Vec<u8>) {
        let path = req.path.as_str();
        let json =
            |v: serde_json::Value| (200, "OK", "application/json", v.to_string().into_bytes());
        let not_found = || {
            (
                404,
                "Not Found",
                "application/json",
                b"{\"error\":\"not found\"}".to_vec(),
            )
        };

        match (req.method.as_str(), path) {
            ("GET", "/healthz") => (200, "OK", "text/plain", b"ok".to_vec()),
            ("GET", "/readyz") => {
                let mysql_ok = self.store.available() && self.store.ping().is_ok();
                if mysql_ok {
                    (200, "OK", "text/plain", b"ready".to_vec())
                } else {
                    (503, "Unavailable", "text/plain", b"not ready".to_vec())
                }
            }
            ("GET", "/api/v1/stats") => {
                let (l1, l2) = self.pipeline_cache_stats();
                json(serde_json::json!({"l1_entries": l1, "l2_entries": l2}))
            }
            ("POST", "/api/v1/reload") => {
                self.audit
                    .record("api", "reload", "policy", "{}", client_ip);
                match reload_all(&self.store, &self.pipeline) {
                    Ok(()) => json(serde_json::json!({"ok": true})),
                    Err(e) => (
                        500,
                        "Internal Error",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", e).into_bytes(),
                    ),
                }
            }
            ("POST", "/api/v1/zones") => {
                let name = parse_json_field(&req.body, "name").unwrap_or_default();
                if name.is_empty() {
                    return (
                        400,
                        "Bad Request",
                        "application/json",
                        b"{\"error\":\"name required\"}".to_vec(),
                    );
                }
                self.audit
                    .record("api", "zone.create", &name, "{}", client_ip);
                match self
                    .store
                    .insert_zone(&name)
                    .and_then(|_| reload_all(&self.store, &self.pipeline))
                {
                    Ok(()) => json(serde_json::json!({"ok": true})),
                    Err(e) => (
                        500,
                        "Internal Error",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", e).into_bytes(),
                    ),
                }
            }
            ("POST", "/api/v1/zones/records") => match parse_record(&req.body) {
                Some(zr) => {
                    self.audit
                        .record("api", "record.create", &zr.name, "{}", client_ip);
                    match self
                        .store
                        .insert_zone_record(&zr)
                        .and_then(|_| reload_all(&self.store, &self.pipeline))
                    {
                        Ok(()) => json(serde_json::json!({"ok": true})),
                        Err(e) => (
                            500,
                            "Internal Error",
                            "application/json",
                            format!("{{\"error\":\"{}\"}}", e).into_bytes(),
                        ),
                    }
                }
                None => (
                    400,
                    "Bad Request",
                    "application/json",
                    b"{\"error\":\"bad record\"}".to_vec(),
                ),
            },
            ("GET", "/api/v1/zones") => match self.store.load_zones() {
                Ok(zones) => json(serde_json::to_value(&zones).unwrap_or_default()),
                Err(_) => (
                    500,
                    "Internal Error",
                    "application/json",
                    b"{\"error\":\"db\"}".to_vec(),
                ),
            },
            ("POST", "/api/v1/blocked") => {
                let domain = parse_json_field(&req.body, "domain").unwrap_or_default();
                let mode =
                    parse_json_field(&req.body, "mode").unwrap_or_else(|| "loopback".to_string());
                if domain.is_empty() {
                    return (
                        400,
                        "Bad Request",
                        "application/json",
                        b"{\"error\":\"domain required\"}".to_vec(),
                    );
                }
                self.audit.record(
                    "api",
                    "block.add",
                    &domain,
                    &format!("{{\"mode\":\"{}\"}}", mode),
                    client_ip,
                );
                match self
                    .store
                    .insert_blocked(&domain, &mode)
                    .and_then(|_| reload_all(&self.store, &self.pipeline))
                {
                    Ok(()) => json(serde_json::json!({"ok": true})),
                    Err(e) => (
                        500,
                        "Internal Error",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", e).into_bytes(),
                    ),
                }
            }
            ("DELETE", "/api/v1/blocked") => {
                let domain = req.query.get("domain").cloned().unwrap_or_default();
                self.audit
                    .record("api", "block.remove", &domain, "{}", client_ip);
                match self
                    .store
                    .delete_blocked(&domain)
                    .and_then(|_| reload_all(&self.store, &self.pipeline))
                {
                    Ok(()) => json(serde_json::json!({"ok": true})),
                    Err(e) => (
                        500,
                        "Internal Error",
                        "application/json",
                        format!("{{\"error\":\"{}\"}}", e).into_bytes(),
                    ),
                }
            }
            ("GET", "/api/v1/blocked") => match self.store.load_blocked() {
                Ok(rows) => json(serde_json::to_value(&rows).unwrap_or_default()),
                Err(_) => (
                    500,
                    "Internal Error",
                    "application/json",
                    b"{\"error\":\"db\"}".to_vec(),
                ),
            },
            _ => not_found(),
        }
    }

    fn pipeline_cache_stats(&self) -> (usize, usize) {
        // Pipeline exposes cache stats through a helper; use the pipeline's
        // cache via a public accessor (see Pipeline::cache_stats).
        self.pipeline.cache_stats()
    }
}

pub fn reload_all(store: &Store, pipeline: &Pipeline) -> crate::error::Result<()> {
    let zones = store.load_zones()?;
    let records = store.load_zone_records()?;
    let blocked = store.load_blocked()?;
    let bindings = store.load_bindings()?;
    pipeline.reload(zones, records, blocked);
    pipeline.reload_bindings(&bindings);
    Ok(())
}

fn parse_json_field(body: &[u8], field: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get(field)?.as_str().map(|s| s.to_string())
}

fn parse_record(body: &[u8]) -> Option<ZoneRecord> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    Some(ZoneRecord {
        id: uuid::Uuid::new_v4().to_string(),
        zone_id: v.get("zone_id")?.as_str()?.to_string(),
        name: v.get("name")?.as_str()?.to_string(),
        rtype: v.get("rtype")?.as_str()?.to_string(),
        value: v.get("value")?.as_str()?.to_string(),
        ttl: v.get("ttl").and_then(|x| x.as_u64()).unwrap_or(300) as u32,
        priority: v.get("priority").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
        enabled: true,
    })
}
