//! Core types and data structures for Sigstore
//!
//! This crate provides the fundamental data structures used throughout the Sigstore
//! ecosystem, including bundle formats, transparency log entries, and trust roots.

pub mod bundle;
pub mod checkpoint;
pub mod dsse;
pub mod encoding;
pub mod error;
pub mod hash;

// Re-export base64_bytes for internal use
pub(crate) use hash::base64_bytes;

pub use bundle::{
    Bundle, BundleVersion, InclusionProof, MediaType, MessageSignature, SignatureContent,
    TransparencyLogEntry, VerificationMaterial,
};
pub use checkpoint::{Checkpoint, CheckpointSignature};
pub use dsse::{pae, DsseEnvelope, DsseSignature};
pub use encoding::{Base64, Hex, Sha256Hash};
pub use error::{Error, Result};
pub use hash::{HashAlgorithm, HashOutput, MessageImprint};
