//! Bundle format handling for Sigstore
//!
//! This crate handles creation, parsing, and validation of Sigstore bundles
//! (versions 0.1, 0.2, and 0.3).

pub mod builder;
pub mod error;
pub mod validation;

pub use builder::{BundleBuilder, TlogEntryBuilder};
pub use error::{Error, Result};
pub use validation::{validate_bundle, validate_bundle_with_options, ValidationOptions};
