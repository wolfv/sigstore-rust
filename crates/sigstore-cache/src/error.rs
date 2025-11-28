//! Error types for the cache crate

/// Result type for cache operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during cache operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error (file operations, etc.)
    #[error("I/O error: {0}")]
    Io(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Cache entry has expired
    #[error("Cache entry has expired")]
    Expired,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serialization(err.to_string())
    }
}
