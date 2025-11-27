# sigstore-verify

Sigstore signature verification for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate provides high-level APIs for verifying Sigstore signatures. It handles the complete verification flow: bundle parsing, certificate chain validation, signature verification, transparency log verification, and identity policy enforcement.

## Features

- **Bundle verification**: Verify standard Sigstore bundles
- **Certificate validation**: X.509 chain validation against Fulcio CA
- **Transparency log verification**: Checkpoint signatures, inclusion proofs, SETs
- **Timestamp verification**: RFC 3161 timestamp validation
- **Identity policies**: Verify signer identity claims (issuer, subject, etc.)

## Verification Steps

1. Parse and validate bundle structure
2. Verify certificate chain against trusted root
3. Verify signature over artifact
4. Verify transparency log entry (checkpoint, inclusion proof, or SET)
5. Verify timestamps if present
6. Check identity against policy (optional)

## Usage

```rust
use sigstore_verify::{Verifier, VerificationPolicy};
use sigstore_trust_root::TrustedRoot;

let root = TrustedRoot::production()?;
let verifier = Verifier::new(&root);

// Basic verification
verifier.verify(&bundle, artifact_bytes)?;

// With identity policy
let policy = VerificationPolicy::new()
    .issuer("https://accounts.google.com")
    .subject("user@example.com");

verifier.verify_with_policy(&bundle, artifact_bytes, &policy)?;
```

## Verification Policies

```rust
use sigstore_verify::VerificationPolicy;

let policy = VerificationPolicy::new()
    // Exact match
    .issuer("https://token.actions.githubusercontent.com")
    // Regex pattern
    .subject_regex(r"^https://github\.com/myorg/.*$")?;
```

## Related Crates

- [`sigstore-sign`](../sigstore-sign) - Create signatures to verify with this crate

## License

BSD-3-Clause
