//! TCP DNS listener (RFC 1035 §4.2.2 length-prefixed framing). Thread per
//! connection.

use crate::resolve::Pipeline;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

pub fn serve_tcp(addr: &str, pipeline: Arc<Pipeline>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    tracing::info!("TCP DNS listening on {}", addr);

    thread::Builder::new()
        .name("dns-tcp-accept".into())
        .spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(stream) => {
                        let p = Arc::clone(&pipeline);
                        thread::Builder::new()
                            .name("dns-tcp-conn".into())
                            .spawn(move || handle_conn(stream, p))
                            .ok();
                    }
                    Err(_) => continue,
                }
            }
        })?;
    Ok(())
}

fn handle_conn(mut stream: TcpStream, pipeline: Arc<Pipeline>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).is_err() {
            return;
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        if stream.read_exact(&mut buf).is_err() {
            return;
        }
        let resp = pipeline.handle(&buf, peer, "tcp");
        if resp.is_empty() {
            return;
        }
        let rlen = (resp.len() as u16).to_be_bytes();
        if stream.write_all(&rlen).is_err() || stream.write_all(&resp).is_err() {
            return;
        }
    }
}
