//! Error types for sigstore

use thiserror::Error;

/// Errors that can occur in Sigstore operations
#[derive(Error, Debug)]
pub enum Error {
    /// Signing error
    #[error("Signing error: {0}")]
    Signing(String),

    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),

    /// Types error
    #[error("Types error: {0}")]
    Types(#[from] sigstore_types::Error),

    /// Crypto error
    #[error("Crypto error: {0}")]
    Crypto(#[from] sigstore_crypto::Error),

    /// Bundle error
    #[error("Bundle error: {0}")]
    Bundle(#[from] sigstore_bundle::Error),

    /// Rekor error
    #[error("Rekor error: {0}")]
    Rekor(#[from] sigstore_rekor::Error),

    /// Fulcio error
    #[error("Fulcio error: {0}")]
    Fulcio(#[from] sigstore_fulcio::Error),

    /// OIDC error
    #[error("OIDC error: {0}")]
    Oidc(#[from] sigstore_oidc::Error),
}

/// Result type for Sigstore operations
pub type Result<T> = std::result::Result<T, Error>;
