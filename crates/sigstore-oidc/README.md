# sigstore-oidc

OpenID Connect identity provider for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Overview

This crate handles OIDC (OpenID Connect) authentication for Sigstore's keyless signing flow. It supports obtaining identity tokens from various OIDC providers, which are then used to request short-lived signing certificates from Fulcio.

## Features

- **OAuth 2.0 device flow**: Interactive authentication via browser
- **Ambient credentials**: Automatic detection of CI/CD environment tokens
- **Token parsing**: OIDC token validation and claim extraction
- **Multiple providers**: Support for various identity providers

## Supported Environments

Ambient credential detection works in:

- GitHub Actions (`ACTIONS_ID_TOKEN_REQUEST_TOKEN`)
- GitLab CI (`SIGSTORE_ID_TOKEN`)
- Google Cloud (Workload Identity)
- Generic OIDC token files

## Usage

```rust
use sigstore_oidc::{get_identity_token, OAuthConfig};

// Try ambient credentials first, fall back to OAuth flow
let token = get_identity_token().await?;

// Or use explicit OAuth flow
let config = OAuthConfig::sigstore();
let token = config.get_token().await?;
```

## Related Crates

Used by:

- [`sigstore-sign`](../sigstore-sign) - Obtains identity tokens for keyless signing
- [`sigstore-fulcio`](../sigstore-fulcio) - Uses tokens to request certificates

## License

BSD-3-Clause
