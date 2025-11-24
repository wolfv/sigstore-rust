//! Cryptographic primitives for Sigstore
//!
//! This crate provides key generation, signing, and verification functionality
//! using aws-lc-rs as the cryptographic backend.

pub mod checkpoint;
pub mod error;
pub mod hash;
pub mod keyring;
pub mod signing;
pub mod verification;
pub mod x509;

pub use checkpoint::{compute_key_hint, LogCheckpoint, NoteSignature, SignedNote};
pub use error::{Error, Result};
pub use hash::{sha256, sha384, sha512, Sha256Hasher};
pub use keyring::Keyring;
pub use signing::{KeyPair, PublicKeyPem, Signature, SigningScheme};
pub use verification::{verify_signature, verify_signature_prehashed, VerificationKey};
pub use x509::{parse_certificate_info, CertificateInfo};
