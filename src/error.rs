//! Central error type for dnsd-rs.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("dns parse error: {0}")]
    Parse(String),
    #[error("dns encode error: {0}")]
    Encode(String),
    #[error("resolver error: {0}")]
    Resolver(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("database error: {0}")]
    Db(String),
    #[error("redis error: {0}")]
    Redis(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("tls error: {0}")]
    Tls(String),
}

impl From<mysql::Error> for Error {
    fn from(e: mysql::Error) -> Self {
        Error::Db(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
