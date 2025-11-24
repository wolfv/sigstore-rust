//! Sigstore trusted root parsing and management
//!
//! This crate provides functionality to parse and manage Sigstore trusted root bundles.
//! The trusted root contains all the trust anchors needed for verification:
//! - Fulcio certificate authorities (for signing certificates)
//! - Rekor transparency log public keys (for log entry verification)
//! - Certificate Transparency log public keys (for CT verification)
//! - Timestamp authority certificates (for RFC 3161 timestamp verification)
//!
//! # Features
//!
//! - `tuf` - Enable TUF (The Update Framework) support for securely fetching
//!   trusted roots from Sigstore's TUF repository. This adds async methods
//!   like [`TrustedRoot::from_tuf()`] and [`TrustedRoot::from_tuf_staging()`].
//!
//! # Example
//!
//! ```no_run
//! use sigstore_trust_root::TrustedRoot;
//!
//! // Load embedded production trusted root
//! let root = TrustedRoot::production().unwrap();
//!
//! // Or load from a file
//! let root = TrustedRoot::from_file("trusted_root.json").unwrap();
//! ```
//!
//! With the `tuf` feature enabled:
//!
//! ```ignore
//! use sigstore_trust_root::TrustedRoot;
//!
//! // Fetch via TUF protocol (secure, up-to-date)
//! let root = TrustedRoot::from_tuf().await?;
//! ```

pub mod error;
pub mod trusted_root;

#[cfg(feature = "tuf")]
pub mod tuf;

pub use error::{Error, Result};
pub use trusted_root::{
    CertificateAuthority, CertificateTransparencyLog, TimestampAuthority, TransparencyLog,
    TrustedRoot, ValidityPeriod,
};

#[cfg(feature = "tuf")]
pub use tuf::TufConfig;
