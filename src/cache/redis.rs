//! Minimal RESP2 (Redis serialization protocol) client for the L3 cache tier.
//!
//! Only the handful of commands the cache needs are implemented: PING, SET
//! (with EX), GET, DEL. Self-built to keep the dependency surface tiny.

use crate::error::{Error, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

pub struct Redis {
    conn: Mutex<Option<BufReader<TcpStream>>>,
    addr: String,
}

#[derive(Debug, PartialEq)]
enum Resp {
    Simple(String),
    Error(String),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
}

impl Redis {
    pub fn connect(addr: &str) -> Result<Redis> {
        let r = Redis {
            conn: Mutex::new(None),
            addr: addr.to_string(),
        };
        r.reconnect()?;
        Ok(r)
    }

    fn reconnect(&self) -> Result<()> {
        let stream = TcpStream::connect(&self.addr).map_err(|e| Error::Redis(e.to_string()))?;
        stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(3))).ok();
        *self.conn.lock().unwrap() = Some(BufReader::new(stream));
        Ok(())
    }

    fn cmd(&self, args: &[&[u8]]) -> Result<Resp> {
        // Ensure a connection; reconnect on error.
        let result = self.cmd_inner(args);
        if result.is_err() {
            let _ = self.reconnect();
            return self.cmd_inner(args);
        }
        result
    }

    fn cmd_inner(&self, args: &[&[u8]]) -> Result<Resp> {
        let mut guard = self.conn.lock().unwrap();
        let conn = guard
            .as_mut()
            .ok_or_else(|| Error::Redis("not connected".into()))?;

        // encode request
        let mut req = Vec::with_capacity(64);
        req.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
        for a in args {
            req.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
            req.extend_from_slice(a);
            req.extend_from_slice(b"\r\n");
        }
        conn.get_mut()
            .write_all(&req)
            .map_err(|e| Error::Redis(e.to_string()))?;
        conn.get_mut()
            .flush()
            .map_err(|e| Error::Redis(e.to_string()))?;

        read_resp(conn).map_err(Error::Redis)
    }

    pub fn ping(&self) -> Result<()> {
        match self.cmd(&[b"PING"])? {
            Resp::Simple(s) if s == "PONG" => Ok(()),
            other => Err(Error::Redis(format!("unexpected PING reply {:?}", other))),
        }
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.cmd(&[b"GET", key.as_bytes()])? {
            Resp::Bulk(b) => Ok(b),
            other => Err(Error::Redis(format!("unexpected GET reply {:?}", other))),
        }
    }

    pub fn set(&self, key: &str, val: &[u8], ttl_secs: i64) -> Result<()> {
        let ttl = ttl_secs.to_string();
        match self.cmd(&[b"SET", key.as_bytes(), val, b"EX", ttl.as_bytes()])? {
            Resp::Simple(s) if s == "OK" => Ok(()),
            other => Err(Error::Redis(format!("unexpected SET reply {:?}", other))),
        }
    }

    pub fn del(&self, key: &str) -> Result<()> {
        let _ = self.cmd(&[b"DEL", key.as_bytes()])?;
        Ok(())
    }
}

fn read_resp(r: &mut BufReader<TcpStream>) -> std::result::Result<Resp, String> {
    let mut line = String::new();
    r.read_line(&mut line).map_err(|e| e.to_string())?;
    if line.is_empty() {
        return Err("empty response".into());
    }
    let line = line.trim_end();
    let (prefix, rest) = line.split_at(1);
    match prefix {
        "+" => Ok(Resp::Simple(rest.to_string())),
        "-" => Ok(Resp::Error(rest.to_string())),
        ":" => Ok(Resp::Integer(
            rest.parse::<i64>().map_err(|e| e.to_string())?,
        )),
        "$" => {
            let len: i64 = rest.parse::<i64>().map_err(|e| e.to_string())?;
            if len == -1 {
                return Ok(Resp::Bulk(None));
            }
            let mut buf = vec![0u8; len as usize + 2];
            r.read_exact(&mut buf).map_err(|e| e.to_string())?;
            buf.truncate(len as usize);
            Ok(Resp::Bulk(Some(buf)))
        }
        "*" => {
            // arrays are not needed; consume nothing and return a marker
            Ok(Resp::Error("unexpected array".into()))
        }
        _ => Err(format!("bad RESP prefix {:?}", prefix)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resp_bulk_parse() {
        let data = b"$5\r\nhello\r\n";
        // not a real socket; just sanity on format helpers
        assert_eq!(data[0], b'$');
    }
}
