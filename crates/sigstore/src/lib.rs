//! High-level Sigstore signing and verification
//!
//! This is the main entry point for the Sigstore Rust implementation.
//! It provides a unified API for signing artifacts and verifying signatures.

pub mod error;
pub mod sign;
pub mod verify;

// Re-export core crates
pub use sigstore_bundle as bundle;
pub use sigstore_crypto as crypto;
pub use sigstore_fulcio as fulcio;
pub use sigstore_merkle as merkle;
pub use sigstore_oidc as oidc;
pub use sigstore_rekor as rekor;
pub use sigstore_tsa as tsa;
pub use sigstore_types as types;

pub use error::{Error, Result};
pub use sign::{sign_context, Signer, SigningConfig, SigningContext};
pub use verify::{
    verify, verify_with_trusted_root, VerificationPolicy, VerificationResult, Verifier,
};
