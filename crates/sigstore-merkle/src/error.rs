//! Error types for sigstore-merkle

use thiserror::Error;

/// Errors that can occur in Merkle tree operations
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid proof format
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid tree size
    #[error("Invalid tree size: {0}")]
    InvalidTreeSize(String),

    /// Invalid leaf index
    #[error("Invalid leaf index: {0}")]
    InvalidLeafIndex(String),

    /// Hash mismatch
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Base64 decoding error
    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// Result type for Merkle tree operations
pub type Result<T> = std::result::Result<T, Error>;
