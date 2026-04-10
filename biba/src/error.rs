//! Error types for TLS record / ClientHello parsing.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("invalid TLS record: {0}")]
    InvalidRecord(&'static str),
    #[error("invalid ClientHello: {0}")]
    InvalidClientHello(&'static str),
    #[error("unsupported extension {0} (enable blunt mimicry to keep opaque)")]
    UnsupportedExtension(u16),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unknown ClientHelloId")]
    UnknownClientHelloId,
}

pub type Result<T> = std::result::Result<T, Error>;
