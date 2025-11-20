//! Sigstore trusted root parsing and management
//!
//! This crate provides functionality to parse and manage Sigstore trusted root bundles.
//! The trusted root contains all the trust anchors needed for verification:
//! - Fulcio certificate authorities (for signing certificates)
//! - Rekor transparency log public keys (for log entry verification)
//! - Certificate Transparency log public keys (for CT verification)
//! - Timestamp authority certificates (for RFC 3161 timestamp verification)

pub mod error;
pub mod trusted_root;

pub use error::{Error, Result};
pub use trusted_root::{
    CertificateAuthority, CertificateTransparencyLog, TimestampAuthority, TransparencyLog,
    TrustedRoot, ValidityPeriod,
};
