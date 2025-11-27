# sigstore-trust-root

Sigstore trusted root management and parsing for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate handles parsing and management of Sigstore trusted root bundles. The trusted root contains all cryptographic trust anchors needed for verification: Fulcio CA certificates, Rekor public keys, CT log keys, and TSA certificates.

## Features

- **Trusted root parsing**: Load and parse `trusted_root.json` files
- **Embedded roots**: Built-in production and staging trust anchors
- **TUF support**: Optional secure fetching via The Update Framework (requires `tuf` feature)
- **Key extraction**: Extract public keys and certificates for verification
- **Validity periods**: Time-based key and certificate validity checking

## Trust Anchors

| Component | Purpose |
|-----------|---------|
| Certificate Authorities | Fulcio CA certificates for signing certificate validation |
| Transparency Logs | Rekor public keys for log entry verification |
| CT Logs | Certificate Transparency log keys for SCT verification |
| Timestamp Authorities | TSA certificates for RFC 3161 timestamp verification |

## Usage

```rust
use sigstore_trust_root::TrustedRoot;

// Use embedded production root
let root = TrustedRoot::production()?;

// Load from file
let root = TrustedRoot::from_file("trusted_root.json")?;

// With TUF feature: fetch securely
#[cfg(feature = "tuf")]
let root = TrustedRoot::from_tuf().await?;
```

## Cargo Features

- `tuf` - Enable TUF-based secure fetching of trusted roots

## Related Crates

Used by:

- [`sigstore-verify`](../sigstore-verify) - Provides trust anchors for verification
- [`sigstore-sign`](../sigstore-sign) - Provides service endpoints

## License

BSD-3-Clause
