//! Error types for trusted root operations

use thiserror::Error;

/// Errors that can occur during trusted root operations
#[derive(Debug, Error)]
pub enum Error {
    /// JSON parsing error
    #[error("failed to parse JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding error
    #[error("failed to decode base64: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Certificate parsing error
    #[error("failed to parse certificate: {0}")]
    Certificate(String),

    /// Invalid key format
    #[error("invalid key format: {0}")]
    InvalidKey(String),

    /// Missing required field
    #[error("missing required field: {0}")]
    MissingField(String),

    /// Unsupported media type
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),

    /// No matching key found
    #[error("no matching key found for ID: {0}")]
    KeyNotFound(String),

    /// No matching certificate found
    #[error("no matching certificate found")]
    CertificateNotFound,

    /// Time parsing error
    #[error("failed to parse time: {0}")]
    TimeParse(String),
}

/// Result type for trusted root operations
pub type Result<T> = std::result::Result<T, Error>;
