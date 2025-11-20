//! Fulcio certificate authority client for Sigstore
//!
//! This crate provides a client for interacting with Fulcio, the Sigstore
//! certificate authority service.

pub mod client;
pub mod error;

pub use client::{Configuration, FulcioClient, SigningCertificate, TrustBundle};
pub use error::{Error, Result};
