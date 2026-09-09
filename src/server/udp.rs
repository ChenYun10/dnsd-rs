//! UDP DNS listener. One reader thread fans datagrams out to a worker pool;
//! workers resolve and reply on the same socket.

use crate::resolve::Pipeline;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

pub fn serve_udp(addr: &str, pipeline: Arc<Pipeline>, workers: usize) -> std::io::Result<()> {
    let socket = UdpSocket::bind(addr)?;
    let socket = Arc::new(socket);
    let workers = workers.max(4);

    let (tx, rx): (
        Sender<(Vec<u8>, SocketAddr)>,
        Receiver<(Vec<u8>, SocketAddr)>,
    ) = channel();

    // reader thread
    let reader = Arc::clone(&socket);
    thread::Builder::new()
        .name("dns-udp-reader".into())
        .spawn(move || {
            let mut buf = vec![0u8; 4096];
            loop {
                match reader.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        if tx.send((buf[..n].to_vec(), addr)).is_err() {
                            return;
                        }
                    }
                    Err(_) => continue,
                }
            }
        })?;

    let rx = Arc::new(Mutex::new(rx));
    for i in 0..workers {
        let socket = Arc::clone(&socket);
        let pipeline = Arc::clone(&pipeline);
        let rx = Arc::clone(&rx);
        thread::Builder::new()
            .name(format!("dns-udp-worker-{}", i))
            .spawn(move || loop {
                let (data, addr) = {
                    let rx = rx.lock().unwrap();
                    match rx.recv() {
                        Ok(x) => x,
                        Err(_) => return,
                    }
                };
                let resp = pipeline.handle(&data, addr.ip(), "udp");
                let _ = socket.send_to(&resp, addr);
            })?;
    }

    tracing::info!("UDP DNS listening on {} ({} workers)", addr, workers);
    Ok(())
}
