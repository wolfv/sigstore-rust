//! Rekor transparency log client for Sigstore
//!
//! This crate provides a client for interacting with Rekor, the Sigstore
//! transparency log service.

pub mod client;
pub mod entry;
pub mod error;

pub use client::{get_public_log_info, RekorClient};
pub use entry::{DsseEntry, HashedRekord, LogEntry, LogInfo, SearchIndex};
pub use error::{Error, Result};
