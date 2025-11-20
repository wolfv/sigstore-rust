//! Error types for sigstore-rekor

use thiserror::Error;

/// Errors that can occur in Rekor operations
#[derive(Error, Debug)]
pub enum Error {
    /// HTTP request error
    #[error("HTTP error: {0}")]
    Http(String),

    /// API error
    #[error("API error: {0}")]
    Api(String),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Merkle proof error
    #[error("Merkle proof error: {0}")]
    Merkle(#[from] sigstore_merkle::Error),
}

/// Result type for Rekor operations
pub type Result<T> = std::result::Result<T, Error>;
