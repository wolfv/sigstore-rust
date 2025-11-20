//! Error types for sigstore-types

use thiserror::Error;

/// Errors that can occur in sigstore-types
#[derive(Error, Debug)]
pub enum Error {
    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding error
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Invalid bundle version
    #[error("Invalid bundle version: {0}")]
    InvalidBundleVersion(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid media type
    #[error("Invalid media type: {0}")]
    InvalidMediaType(String),

    /// Invalid checkpoint format
    #[error("Invalid checkpoint format: {0}")]
    InvalidCheckpoint(String),

    /// Invalid hash algorithm
    #[error("Invalid hash algorithm: {0}")]
    InvalidHashAlgorithm(String),

    /// Invalid certificate
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Result type for sigstore-types operations
pub type Result<T> = std::result::Result<T, Error>;
