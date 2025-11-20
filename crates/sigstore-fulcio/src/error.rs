//! Error types for sigstore-fulcio

use thiserror::Error;

/// Errors that can occur in Fulcio operations
#[derive(Error, Debug)]
pub enum Error {
    /// HTTP request error
    #[error("HTTP error: {0}")]
    Http(String),

    /// API error
    #[error("API error: {0}")]
    Api(String),

    /// Certificate error
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result type for Fulcio operations
pub type Result<T> = std::result::Result<T, Error>;
