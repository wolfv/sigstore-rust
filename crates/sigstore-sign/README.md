# sigstore-sign

Sigstore signature creation for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides high-level APIs for creating Sigstore signatures. It orchestrates the keyless signing flow: OIDC authentication, certificate issuance from Fulcio, signing, transparency log submission to Rekor, and optional timestamping.

## Features

- **Keyless signing**: Sign artifacts using OIDC identity (no long-lived keys)
- **Bundle creation**: Produces standard Sigstore bundles
- **Transparency logging**: Automatic submission to Rekor
- **Timestamping**: Optional RFC 3161 timestamps for long-term validity
- **Multiple content types**: Support for blobs and DSSE attestations

## Signing Flow

1. Authenticate with OIDC provider (or use ambient credentials)
2. Generate ephemeral key pair
3. Request certificate from Fulcio
4. Sign the artifact
5. Submit to Rekor transparency log
6. Optionally request timestamp from TSA
7. Package everything into a Sigstore bundle

## Usage

```rust
use sigstore_sign::{Signer, SigningConfig};

let config = SigningConfig::production();
let signer = Signer::new(config).await?;

// Sign a blob
let bundle = signer.sign(artifact_bytes).await?;

// Sign with a DSSE envelope
let bundle = signer.sign_dsse(payload_type, payload).await?;
```

## Configuration

```rust
use sigstore_sign::SigningConfig;

// Production (default)
let config = SigningConfig::production();

// Staging environment
let config = SigningConfig::staging();

// Custom configuration
let config = SigningConfig {
    fulcio_url: "https://fulcio.example.com".into(),
    rekor_url: "https://rekor.example.com".into(),
    // ...
};
```

## Related Crates

- [`sigstore-verify`](../sigstore-verify) - Verify signatures created by this crate

## License

BSD-3-Clause
