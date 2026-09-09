//! DNS over HTTPS (RFC 8484) — GET `?dns=` (base64url) and POST
//! (application/dns-message). Runs over plain HTTP (dev) or TLS when a cert is
//! configured.

use super::http::{read_request, write_response};
use crate::resolve::Pipeline;
use base64::Engine;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

pub fn serve_doh(listener: TcpListener, pipeline: Arc<Pipeline>) {
    thread::Builder::new()
        .name("doh-accept".into())
        .spawn(move || {
            for conn in listener.incoming() {
                if let Ok(mut stream) = conn {
                    let p = Arc::clone(&pipeline);
                    thread::Builder::new()
                        .name("doh-conn".into())
                        .spawn(move || {
                            let _ =
                                stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
                            handle_doh(&mut stream, &p);
                        })
                        .ok();
                }
            }
        })
        .ok();
}

fn handle_doh(stream: &mut std::net::TcpStream, pipeline: &Pipeline) {
    let Ok(Some(req)) = read_request(stream) else {
        return;
    };
    let client_ip = stream
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());

    let dns_bytes: Option<Vec<u8>> = if req.method == "GET" {
        req.query.get("dns").and_then(|d| decode_base64url(d))
    } else if req.method == "POST" {
        Some(req.body.clone())
    } else {
        None
    };

    match dns_bytes {
        Some(bytes) => {
            let resp = pipeline.handle(&bytes, client_ip, "doh");
            let _ = write_response(
                stream,
                200,
                "OK",
                "application/dns-message",
                &resp,
                &[("Cache-Control", "max-age=0")],
            );
        }
        None => {
            let body = b"bad request";
            let _ = write_response(stream, 400, "Bad Request", "text/plain", body, &[]);
        }
    }
}

fn decode_base64url(s: &str) -> Option<Vec<u8>> {
    use base64::alphabet;
    let engine = base64::engine::GeneralPurpose::new(
        &alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD,
    );
    engine.decode(s).ok()
}
