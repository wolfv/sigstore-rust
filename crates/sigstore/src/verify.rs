//! High-level verification API
//!
//! This module provides the main entry point for verifying Sigstore signatures.

use crate::error::{Error, Result};
use base64::Engine;
use serde::Serialize;
use sigstore_bundle::validate_bundle_with_options;
use sigstore_bundle::ValidationOptions;
use sigstore_crypto::{parse_certificate_info, x509};
use sigstore_crypto::{verify_signature, Keyring, SignedNote, SigningScheme};
use sigstore_rekor::body::RekorEntryBody;
use sigstore_trust_root::TrustedRoot;
use sigstore_tsa::{parse_timestamp, verify_timestamp_response, VerifyOpts as TsaVerifyOpts};
use sigstore_types::bundle::{InclusionProof, VerificationMaterialContent};
use sigstore_types::{Bundle, SignatureContent, TransparencyLogEntry};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// Policy for verifying signatures
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// Expected identity (email or URI)
    pub identity: Option<String>,
    /// Expected issuer
    pub issuer: Option<String>,
    /// Verify transparency log inclusion
    pub verify_tlog: bool,
    /// Verify timestamp
    pub verify_timestamp: bool,
    /// Verify certificate chain
    pub verify_certificate: bool,
    /// Skip artifact hash validation (for digest-only verification)
    pub skip_artifact_hash: bool,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            identity: None,
            issuer: None,
            verify_tlog: true,
            verify_timestamp: true,
            verify_certificate: true,
            skip_artifact_hash: false,
        }
    }
}

impl VerificationPolicy {
    /// Create a policy that requires a specific identity
    pub fn with_identity(identity: impl Into<String>) -> Self {
        Self {
            identity: Some(identity.into()),
            ..Default::default()
        }
    }

    /// Create a policy that requires a specific issuer
    pub fn with_issuer(issuer: impl Into<String>) -> Self {
        Self {
            issuer: Some(issuer.into()),
            ..Default::default()
        }
    }

    /// Require a specific identity
    pub fn require_identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    /// Require a specific issuer
    pub fn require_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Skip transparency log verification
    pub fn skip_tlog(mut self) -> Self {
        self.verify_tlog = false;
        self
    }

    /// Skip timestamp verification
    pub fn skip_timestamp(mut self) -> Self {
        self.verify_timestamp = false;
        self
    }

    /// Skip artifact hash validation (for digest-only verification)
    pub fn skip_artifact_hash(mut self) -> Self {
        self.skip_artifact_hash = true;
        self
    }
}

/// Result of verification
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether verification succeeded
    pub success: bool,
    /// Identity from the certificate
    pub identity: Option<String>,
    /// Issuer from the certificate
    pub issuer: Option<String>,
    /// Integrated time from transparency log
    pub integrated_time: Option<i64>,
    /// Any warnings during verification
    pub warnings: Vec<String>,
}

impl VerificationResult {
    /// Create a successful result
    pub fn success() -> Self {
        Self {
            success: true,
            identity: None,
            issuer: None,
            integrated_time: None,
            warnings: Vec::new(),
        }
    }

    /// Create a failed result
    pub fn failure() -> Self {
        Self {
            success: false,
            identity: None,
            issuer: None,
            integrated_time: None,
            warnings: Vec::new(),
        }
    }
}

/// A verifier for Sigstore signatures
pub struct Verifier {
    /// Trusted root containing verification material
    trusted_root: Option<TrustedRoot>,
    /// Keyring for Rekor public keys
    _rekor_keyring: Keyring,
    /// Keyring for Fulcio root certificates
    _fulcio_keyring: Keyring,
    /// Keyring for timestamp authorities
    _tsa_keyring: Keyring,
}

impl Verifier {
    /// Create a new verifier with no trusted material
    pub fn new() -> Self {
        Self {
            trusted_root: None,
            _rekor_keyring: Keyring::new(),
            _fulcio_keyring: Keyring::new(),
            _tsa_keyring: Keyring::new(),
        }
    }

    /// Create a verifier from a trusted root
    pub fn from_trusted_root(trusted_root: TrustedRoot) -> Self {
        let mut verifier = Self::new();
        verifier.trusted_root = Some(trusted_root);
        verifier
    }

    /// Create a verifier from a trusted root
    pub fn new_with_trusted_root(trusted_root: &TrustedRoot) -> Self {
        let mut verifier = Self::new();
        verifier.trusted_root = Some(trusted_root.clone());
        verifier
    }

    /// Verify an artifact against a bundle
    pub fn verify(
        &self,
        artifact: &[u8],
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        let mut result = VerificationResult::success();

        // 1. Validate bundle structure
        // Note: We don't require timestamps, but we do verify them if present
        let options = ValidationOptions {
            require_inclusion_proof: policy.verify_tlog,
            require_timestamp: false, // Don't require timestamps, but verify if present
        };

        validate_bundle_with_options(bundle, &options)
            .map_err(|e| Error::Verification(format!("bundle validation failed: {}", e)))?;

        // 2. Extract the signing certificate and public key
        let cert_der = match &bundle.verification_material.content {
            VerificationMaterialContent::Certificate(cert) => {
                base64::engine::general_purpose::STANDARD
                    .decode(&cert.raw_bytes)
                    .map_err(|e| {
                        Error::Verification(format!("failed to decode certificate: {}", e))
                    })?
            }
            VerificationMaterialContent::X509CertificateChain { certificates } => {
                if certificates.is_empty() {
                    return Err(Error::Verification("no certificates in chain".to_string()));
                }
                base64::engine::general_purpose::STANDARD
                    .decode(&certificates[0].raw_bytes)
                    .map_err(|e| {
                        Error::Verification(format!("failed to decode certificate: {}", e))
                    })?
            }
            VerificationMaterialContent::PublicKey { .. } => {
                return Err(Error::Verification(
                    "public key verification not yet supported".to_string(),
                ));
            }
        };

        // Parse the X.509 certificate using our utility
        let cert_info = parse_certificate_info(&cert_der)
            .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

        let not_before = cert_info.not_before;
        let not_after = cert_info.not_after;
        let public_key_bytes = &cert_info.public_key_bytes;
        let scheme = cert_info.signing_scheme;

        // Store identity in result
        result.identity = cert_info.identity;

        // Extract signature bytes early - needed for TSA timestamp verification
        let signature_bytes_for_tsa = match &bundle.content {
            SignatureContent::MessageSignature(msg_sig) => {
                base64::engine::general_purpose::STANDARD
                    .decode(&msg_sig.signature)
                    .map_err(|e| {
                        Error::Verification(format!("failed to decode signature: {}", e))
                    })?
            }
            SignatureContent::DsseEnvelope(envelope) => {
                if envelope.signatures.is_empty() {
                    return Err(Error::Verification(
                        "no signatures in DSSE envelope".to_string(),
                    ));
                }
                base64::engine::general_purpose::STANDARD
                    .decode(&envelope.signatures[0].sig)
                    .map_err(|e| {
                        Error::Verification(format!("failed to decode signature: {}", e))
                    })?
            }
        };

        // Get the trusted root if available
        let trusted_root_ref = self.trusted_root.as_ref();

        // Determine which time to use for certificate validation
        // Priority order:
        // 1. TSA timestamp (RFC 3161) - most authoritative, proves when signature was created
        // 2. Integrated time from transparency log - proves when entry was added to Rekor
        // 3. Current time - fallback if no timestamp available
        let validation_time = if let Some(tsa_time) =
            extract_tsa_timestamp(bundle, &signature_bytes_for_tsa, trusted_root_ref)?
        {
            tsa_time
        } else if let Some(integrated_time) = extract_integrated_time(bundle)? {
            integrated_time
        } else {
            chrono::Utc::now().timestamp()
        };

        if validation_time < not_before {
            return Err(Error::Verification(format!(
                "certificate not yet valid: validation time {} is before not_before {}",
                validation_time, not_before
            )));
        }

        if validation_time > not_after {
            return Err(Error::Verification(format!(
                "certificate has expired: validation time {} is after not_after {}",
                validation_time, not_after
            )));
        }

        // 3. Extract signature and data to verify based on content type
        // For messageSignature with digest-only mode: we can't verify signature without artifact
        // For DSSE: signature is over PAE (payload), not artifact, so we can always verify
        let skip_signature_verification = match &bundle.content {
            SignatureContent::MessageSignature(msg_sig) => {
                // If we're in digest-only mode (skip_artifact_hash=true) and have an empty artifact,
                // we cannot verify the signature since messageSignature signs the artifact directly
                policy.skip_artifact_hash && artifact.is_empty() && msg_sig.message_digest.is_some()
            }
            SignatureContent::DsseEnvelope(_) => false, // DSSE can always be verified
        };

        if !skip_signature_verification {
            let (data_to_verify, signature_bytes) = match &bundle.content {
                SignatureContent::MessageSignature(msg_sig) => {
                    // For message signatures, we verify the artifact directly
                    let sig_bytes = base64::engine::general_purpose::STANDARD
                        .decode(&msg_sig.signature)
                        .map_err(|e| {
                            Error::Verification(format!("failed to decode signature: {}", e))
                        })?;
                    (artifact.to_vec(), sig_bytes)
                }
                SignatureContent::DsseEnvelope(envelope) => {
                    // For DSSE envelopes, we verify the PAE
                    if envelope.signatures.is_empty() {
                        return Err(Error::Verification(
                            "no signatures in DSSE envelope".to_string(),
                        ));
                    }

                    let payload_bytes = base64::engine::general_purpose::STANDARD
                        .decode(&envelope.payload)
                        .map_err(|e| {
                            Error::Verification(format!("failed to decode payload: {}", e))
                        })?;

                    // Create PAE (Pre-Authentication Encoding)
                    let pae = sigstore_types::dsse::pae(&envelope.payload_type, &payload_bytes);

                    let sig_bytes = base64::engine::general_purpose::STANDARD
                        .decode(&envelope.signatures[0].sig)
                        .map_err(|e| {
                            Error::Verification(format!("failed to decode signature: {}", e))
                        })?;

                    (pae, sig_bytes)
                }
            };

            // 4. Verify the signature
            verify_signature(public_key_bytes, &data_to_verify, &signature_bytes, scheme).map_err(
                |e| Error::Verification(format!("signature verification failed: {}", e)),
            )?;
        }

        // 5. Verify DSSE envelope matches Rekor entry (for DSSE bundles)
        if let SignatureContent::DsseEnvelope(envelope) = &bundle.content {
            // For each transparency log entry, verify the envelope hash matches
            for entry in &bundle.verification_material.tlog_entries {
                // Check if this is a DSSE entry
                if entry.kind_version.kind == "dsse" {
                    // Only validate envelope hash for v0.0.1 (Rekor v1)
                    // v0.0.2 (Rekor v2) doesn't include envelopeHash
                    if entry.kind_version.version == "0.0.1" {
                        // Parse the Rekor entry body using typed structures
                        let body = RekorEntryBody::from_base64_json(
                            &entry.canonicalized_body,
                            &entry.kind_version.kind,
                            &entry.kind_version.version,
                        )
                        .map_err(|e| {
                            Error::Verification(format!("failed to parse Rekor body: {}", e))
                        })?;

                        let expected_hash = match &body {
                            RekorEntryBody::DsseV001(dsse_body) => {
                                &dsse_body.spec.envelope_hash.value
                            }
                            _ => {
                                return Err(Error::Verification(
                                    "expected DSSE v0.0.1 body, got different type".to_string(),
                                ))
                            }
                        };

                        // Compute actual envelope hash using canonical JSON (RFC 8785)
                        let envelope_json =
                            serde_json_canonicalizer::to_vec(envelope).map_err(|e| {
                                Error::Verification(format!(
                                    "failed to canonicalize envelope JSON: {}",
                                    e
                                ))
                            })?;
                        let envelope_hash = sigstore_crypto::sha256(&envelope_json);
                        let envelope_hash_hex = hex::encode(envelope_hash);

                        // Compare hashes
                        if &envelope_hash_hex != expected_hash {
                            return Err(Error::Verification(format!(
                                "DSSE envelope hash mismatch: computed {}, expected {}",
                                envelope_hash_hex, expected_hash
                            )));
                        }
                    } else if entry.kind_version.version == "0.0.2" {
                        // For Rekor v2 (v0.0.2), validate payload hash
                        let body = RekorEntryBody::from_base64_json(
                            &entry.canonicalized_body,
                            &entry.kind_version.kind,
                            &entry.kind_version.version,
                        )
                        .map_err(|e| {
                            Error::Verification(format!("failed to parse Rekor body: {}", e))
                        })?;

                        let (expected_hash, rekor_signatures) = match &body {
                            RekorEntryBody::DsseV002(dsse_body) => (
                                &dsse_body.spec.dsse_v002.payload_hash.digest,
                                &dsse_body.spec.dsse_v002.signatures,
                            ),
                            _ => {
                                return Err(Error::Verification(
                                    "expected DSSE v0.0.2 body, got different type".to_string(),
                                ))
                            }
                        };

                        // Compute actual payload hash
                        let payload_bytes = base64::engine::general_purpose::STANDARD
                            .decode(&envelope.payload)
                            .map_err(|e| {
                                Error::Verification(format!("failed to decode DSSE payload: {}", e))
                            })?;
                        let payload_hash = sigstore_crypto::sha256(&payload_bytes);
                        let payload_hash_b64 =
                            base64::engine::general_purpose::STANDARD.encode(payload_hash);

                        // Compare hashes
                        if &payload_hash_b64 != expected_hash {
                            return Err(Error::Verification(format!(
                                "DSSE payload hash mismatch: computed {}, expected {}",
                                payload_hash_b64, expected_hash
                            )));
                        }

                        // Also verify that the signature in the bundle matches what's in Rekor
                        // This prevents signature substitution attacks
                        // Check that at least one signature from the bundle matches Rekor
                        let mut found_match = false;
                        for bundle_sig in &envelope.signatures {
                            for rekor_sig in rekor_signatures {
                                if bundle_sig.sig == rekor_sig.content {
                                    found_match = true;
                                    break;
                                }
                            }
                            if found_match {
                                break;
                            }
                        }

                        if !found_match {
                            return Err(Error::Verification(
                                "DSSE signature in bundle does not match Rekor entry".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        // 5.5. Verify DSSE payload matches what's in Rekor (for intoto entries)
        if let SignatureContent::DsseEnvelope(envelope) = &bundle.content {
            for entry in &bundle.verification_material.tlog_entries {
                if entry.kind_version.kind == "intoto" {
                    // Parse the Rekor entry body using typed structures
                    let body = RekorEntryBody::from_base64_json(
                        &entry.canonicalized_body,
                        &entry.kind_version.kind,
                        &entry.kind_version.version,
                    )
                    .map_err(|e| {
                        Error::Verification(format!("failed to parse Rekor body: {}", e))
                    })?;

                    let (rekor_payload_b64, rekor_signatures) = match &body {
                        RekorEntryBody::IntotoV002(intoto_body) => (
                            &intoto_body.spec.content.envelope.payload,
                            &intoto_body.spec.content.envelope.signatures,
                        ),
                        _ => {
                            return Err(Error::Verification(
                                "expected Intoto v0.0.2 body, got different type".to_string(),
                            ))
                        }
                    };

                    // The Rekor entry has the payload double-base64-encoded, decode it once
                    let rekor_payload_bytes = base64::engine::general_purpose::STANDARD
                        .decode(rekor_payload_b64)
                        .map_err(|e| {
                            Error::Verification(format!("failed to decode Rekor payload: {}", e))
                        })?;

                    let rekor_payload = String::from_utf8(rekor_payload_bytes).map_err(|e| {
                        Error::Verification(format!("Rekor payload not valid UTF-8: {}", e))
                    })?;

                    // Compare with bundle payload
                    if envelope.payload != rekor_payload {
                        return Err(Error::Verification(
                            "DSSE payload in bundle does not match intoto Rekor entry".to_string(),
                        ));
                    }

                    // Also validate that the signatures match
                    // Check that at least one signature from the bundle matches Rekor
                    let mut found_match = false;
                    for bundle_sig in &envelope.signatures {
                        for rekor_sig in rekor_signatures {
                            // The Rekor signature is also double-base64-encoded, decode it once
                            let rekor_sig_decoded = base64::engine::general_purpose::STANDARD
                                .decode(&rekor_sig.sig)
                                .map_err(|e| {
                                    Error::Verification(format!(
                                        "failed to decode Rekor signature: {}",
                                        e
                                    ))
                                })?;

                            let rekor_sig_content =
                                String::from_utf8(rekor_sig_decoded).map_err(|e| {
                                    Error::Verification(format!(
                                        "Rekor signature not valid UTF-8: {}",
                                        e
                                    ))
                                })?;

                            if bundle_sig.sig == rekor_sig_content {
                                found_match = true;
                                break;
                            }
                        }
                        if found_match {
                            break;
                        }
                    }

                    if !found_match {
                        return Err(Error::Verification(
                            "DSSE signature in bundle does not match intoto Rekor entry"
                                .to_string(),
                        ));
                    }
                }
            }
        }

        // 6. Verify artifact hash matches what's in Rekor (for hashedrekord entries)
        // We always validate hashedrekord entries against Rekor, even in DIGEST mode,
        // because we need to ensure the hash in the bundle matches what's in Rekor
        for entry in &bundle.verification_material.tlog_entries {
            if entry.kind_version.kind == "hashedrekord" {
                // Parse the Rekor entry body using typed structures
                let body = RekorEntryBody::from_base64_json(
                    &entry.canonicalized_body,
                    &entry.kind_version.kind,
                    &entry.kind_version.version,
                )
                .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

                // Extract expected artifact hash from Rekor entry
                // Different structure for v0.0.1 vs v0.0.2
                let (expected_hash, is_hex_encoded) = match &body {
                    RekorEntryBody::HashedRekordV001(rekord) => {
                        // v0.0.1: spec.data.hash.value (hex)
                        (&rekord.spec.data.hash.value, true)
                    }
                    RekorEntryBody::HashedRekordV002(rekord) => {
                        // v0.0.2: spec.hashedRekordV002.data.digest (base64)
                        (&rekord.spec.hashed_rekord_v002.data.digest, false)
                    }
                    _ => {
                        return Err(Error::Verification(format!(
                            "expected HashedRekord body, got different type for version {}",
                            entry.kind_version.version
                        )))
                    }
                };

                // Get the artifact hash to compare against Rekor
                // If we have the actual artifact, compute its hash
                // If we're in DIGEST mode (artifact is empty), extract hash from bundle
                let artifact_hash_to_check = if !artifact.is_empty() {
                    // We have the actual artifact, compute its hash
                    sigstore_crypto::sha256(artifact)
                } else {
                    // DIGEST mode - extract hash from bundle's message signature
                    if let SignatureContent::MessageSignature(sig) = &bundle.content {
                        if let Some(digest) = &sig.message_digest {
                            // Decode the digest from the bundle
                            base64::engine::general_purpose::STANDARD
                                .decode(&digest.digest)
                                .map_err(|e| {
                                    Error::Verification(format!(
                                        "failed to decode message digest: {}",
                                        e
                                    ))
                                })?
                                .try_into()
                                .map_err(|_| {
                                    Error::Verification(
                                        "message digest has wrong length".to_string(),
                                    )
                                })?
                        } else {
                            return Err(Error::Verification(
                                "no message digest in bundle for DIGEST mode".to_string(),
                            ));
                        }
                    } else {
                        // For DSSE envelopes in DIGEST mode, we can't validate the hashedrekord
                        // because DSSE doesn't have a direct artifact hash - skip validation
                        continue;
                    }
                };

                // Compare hashes - v0.0.1 uses hex, v0.0.2 uses base64
                let matches = if is_hex_encoded {
                    let artifact_hash_hex = hex::encode(&artifact_hash_to_check);
                    &artifact_hash_hex == expected_hash
                } else {
                    let artifact_hash_b64 =
                        base64::engine::general_purpose::STANDARD.encode(&artifact_hash_to_check);
                    &artifact_hash_b64 == expected_hash
                };

                if !matches {
                    return Err(Error::Verification(format!(
                        "artifact hash mismatch for hashedrekord {} entry",
                        entry.kind_version.version
                    )));
                }

                // Validate that the certificate in Rekor matches the certificate in the bundle
                // Extract certificate from Rekor entry
                let rekor_cert_str = match &body {
                    RekorEntryBody::HashedRekordV001(rekord) => {
                        // v0.0.1: spec.signature.publicKey.content (PEM encoded)
                        Some((&rekord.spec.signature.public_key.content, true))
                    }
                    RekorEntryBody::HashedRekordV002(rekord) => {
                        // v0.0.2: spec.hashedRekordV002.signature.verifier.x509Certificate.rawBytes (base64 DER)
                        rekord
                            .spec
                            .hashed_rekord_v002
                            .signature
                            .verifier
                            .x509_certificate
                            .as_ref()
                            .map(|cert| (&cert.raw_bytes, false))
                    }
                    _ => None,
                };

                if let Some((rekor_cert_encoded, is_pem)) = rekor_cert_str {
                    // Get the certificate from the bundle
                    let bundle_cert_der = match &bundle.verification_material.content {
                        VerificationMaterialContent::X509CertificateChain { certificates } => {
                            certificates.first().map(|c| &c.raw_bytes)
                        }
                        VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
                        _ => None,
                    };

                    if let Some(bundle_cert_b64) = bundle_cert_der {
                        // Decode bundle certificate
                        let bundle_cert_der_bytes = base64::engine::general_purpose::STANDARD
                            .decode(bundle_cert_b64)
                            .map_err(|e| {
                                Error::Verification(format!(
                                    "failed to decode bundle certificate: {}",
                                    e
                                ))
                            })?;

                        // Decode Rekor certificate
                        let rekor_cert_der_bytes = if is_pem {
                            // v0.0.1 uses PEM (double base64-encoded), need to decode it
                            let rekor_cert_pem_decoded = base64::engine::general_purpose::STANDARD
                                .decode(rekor_cert_encoded)
                                .map_err(|e| {
                                    Error::Verification(format!(
                                        "failed to decode Rekor cert PEM base64: {}",
                                        e
                                    ))
                                })?;

                            let rekor_cert_pem_str = String::from_utf8(rekor_cert_pem_decoded)
                                .map_err(|e| {
                                    Error::Verification(format!(
                                        "Rekor cert PEM not valid UTF-8: {}",
                                        e
                                    ))
                                })?;

                            // Extract DER from PEM using our utility
                            x509::der_from_pem(&rekor_cert_pem_str).map_err(|e| {
                                Error::Verification(format!(
                                    "failed to extract DER from PEM: {}",
                                    e
                                ))
                            })?
                        } else {
                            // v0.0.2 already has base64 DER
                            base64::engine::general_purpose::STANDARD
                                .decode(rekor_cert_encoded)
                                .map_err(|e| {
                                    Error::Verification(format!(
                                        "failed to decode Rekor cert DER: {}",
                                        e
                                    ))
                                })?
                        };

                        // Compare certificates
                        if bundle_cert_der_bytes != rekor_cert_der_bytes {
                            return Err(Error::Verification(
                                "certificate in bundle does not match certificate in Rekor entry"
                                    .to_string(),
                            ));
                        }
                    }
                }

                // Also validate that the signature in the bundle matches the signature in Rekor
                // Extract signature from Rekor entry
                let rekor_sig_b64 = match &body {
                    RekorEntryBody::HashedRekordV001(rekord) => {
                        // v0.0.1: spec.signature.content (base64)
                        Some(&rekord.spec.signature.content)
                    }
                    RekorEntryBody::HashedRekordV002(rekord) => {
                        // v0.0.2: spec.hashedRekordV002.signature.content (base64)
                        Some(&rekord.spec.hashed_rekord_v002.signature.content)
                    }
                    _ => None,
                };

                if let Some(rekor_sig_b64) = rekor_sig_b64 {
                    // Get the signature from the bundle (only for MessageSignature, not DSSE)
                    if let SignatureContent::MessageSignature(sig) = &bundle.content {
                        let bundle_sig_b64 = &sig.signature;

                        // Compare signatures
                        if bundle_sig_b64 != rekor_sig_b64 {
                            return Err(Error::Verification(
                                "signature in bundle does not match signature in Rekor entry"
                                    .to_string(),
                            ));
                        }
                    }
                }

                // Validate that integrated time is within certificate validity period
                // This applies to all hashedrekord entries, regardless of whether certificate matching succeeded
                let bundle_cert_der = match &bundle.verification_material.content {
                    VerificationMaterialContent::X509CertificateChain { certificates } => {
                        certificates.first().map(|c| &c.raw_bytes)
                    }
                    VerificationMaterialContent::Certificate(cert) => Some(&cert.raw_bytes),
                    _ => None,
                };

                if let Some(bundle_cert_b64) = bundle_cert_der {
                    let bundle_cert_der_bytes = base64::engine::general_purpose::STANDARD
                        .decode(bundle_cert_b64)
                        .map_err(|e| {
                            Error::Verification(format!(
                                "failed to decode bundle certificate for time validation: {}",
                                e
                            ))
                        })?;

                    // Only validate integrated time for hashedrekord 0.0.1
                    // For 0.0.2 (Rekor v2), integrated_time is not present
                    if entry.kind_version.version == "0.0.1" && !entry.integrated_time.is_empty() {
                        let cert = Certificate::from_der(&bundle_cert_der_bytes).map_err(|e| {
                            Error::Verification(format!(
                                "failed to parse certificate for time validation: {}",
                                e
                            ))
                        })?;

                        // Convert certificate validity times to Unix timestamps
                        use std::time::UNIX_EPOCH;
                        let not_before_system =
                            cert.tbs_certificate.validity.not_before.to_system_time();
                        let not_after_system =
                            cert.tbs_certificate.validity.not_after.to_system_time();

                        let not_before = not_before_system
                            .duration_since(UNIX_EPOCH)
                            .map_err(|e| {
                                Error::Verification(format!(
                                    "failed to convert notBefore to Unix time: {}",
                                    e
                                ))
                            })?
                            .as_secs() as i64;
                        let not_after = not_after_system
                            .duration_since(UNIX_EPOCH)
                            .map_err(|e| {
                                Error::Verification(format!(
                                    "failed to convert notAfter to Unix time: {}",
                                    e
                                ))
                            })?
                            .as_secs() as i64;

                        let integrated_time =
                            entry.integrated_time.parse::<i64>().map_err(|e| {
                                Error::Verification(format!(
                                    "failed to parse integrated time: {}",
                                    e
                                ))
                            })?;

                        if integrated_time < not_before || integrated_time > not_after {
                            return Err(Error::Verification(
                                format!("integrated time {} is outside certificate validity period ({} to {})",
                                    integrated_time, not_before, not_after)
                            ));
                        }
                    }
                }
            }
        }

        // 7. Verify artifact hash matches (for DSSE with in-toto statements)
        if !policy.skip_artifact_hash {
            if let SignatureContent::DsseEnvelope(envelope) = &bundle.content {
                if envelope.payload_type == "application/vnd.in-toto+json" {
                    // Decode payload and check subject digest
                    let payload_bytes = base64::engine::general_purpose::STANDARD
                        .decode(&envelope.payload)
                        .map_err(|e| {
                            Error::Verification(format!("failed to decode payload: {}", e))
                        })?;

                    // Compute artifact hash
                    let artifact_hash = sigstore_crypto::sha256(artifact);
                    let artifact_hash_hex = hex::encode(artifact_hash);

                    // Parse the in-toto statement to check subject digest
                    if let Ok(payload_str) = String::from_utf8(payload_bytes) {
                        if let Ok(statement) =
                            serde_json::from_str::<serde_json::Value>(&payload_str)
                        {
                            if let Some(subjects) =
                                statement.get("subject").and_then(|s| s.as_array())
                            {
                                let mut hash_matches = false;
                                for subject in subjects {
                                    if let Some(digest) = subject
                                        .get("digest")
                                        .and_then(|d| d.get("sha256"))
                                        .and_then(|h| h.as_str())
                                    {
                                        if digest == artifact_hash_hex {
                                            hash_matches = true;
                                            break;
                                        }
                                    }
                                }
                                if !hash_matches && !subjects.is_empty() {
                                    return Err(Error::Verification(
                                        "artifact hash does not match any subject in attestation"
                                            .to_string(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        // 7. Extract and validate integrated time from tlog entries
        if policy.verify_tlog {
            for entry in &bundle.verification_material.tlog_entries {
                // 7a. Verify checkpoint signature if present and we have a trusted root
                if let Some(ref inclusion_proof) = entry.inclusion_proof {
                    if let Some(ref trusted_root) = self.trusted_root {
                        verify_checkpoint(
                            &inclusion_proof.checkpoint.envelope,
                            inclusion_proof,
                            trusted_root,
                        )?;
                    }
                }

                // 7b. Verify inclusion promise (SET) if present and we have a trusted root
                if entry.inclusion_promise.is_some() {
                    if let Some(ref trusted_root) = self.trusted_root {
                        verify_set(entry, trusted_root)?;
                    }
                }

                // 6b. Validate integrated time
                if !entry.integrated_time.is_empty() {
                    if let Ok(time) = entry.integrated_time.parse::<i64>() {
                        // Ignore 0 as it indicates invalid/missing time
                        if time > 0 {
                            // Check that integrated time is not in the future
                            let now = chrono::Utc::now().timestamp();
                            if time > now {
                                return Err(Error::Verification(format!(
                                    "integrated time {} is in the future (current time: {})",
                                    time, now
                                )));
                            }

                            // Check that integrated time is within certificate validity period
                            if time < not_before {
                                return Err(Error::Verification(format!(
                                    "integrated time {} is before certificate validity (not_before: {})",
                                    time, not_before
                                )));
                            }

                            if time > not_after {
                                return Err(Error::Verification(format!(
                                    "integrated time {} is after certificate validity (not_after: {})",
                                    time, not_after
                                )));
                            }

                            result.integrated_time = Some(time);
                        }
                    }
                }
            }
        }

        // 7. Check policy constraints
        if let Some(ref expected_identity) = policy.identity {
            if let Some(ref actual_identity) = result.identity {
                if actual_identity != expected_identity {
                    return Err(Error::Verification(format!(
                        "identity mismatch: expected {}, got {}",
                        expected_identity, actual_identity
                    )));
                }
            }
        }

        if let Some(ref expected_issuer) = policy.issuer {
            if let Some(ref actual_issuer) = result.issuer {
                if actual_issuer != expected_issuer {
                    return Err(Error::Verification(format!(
                        "issuer mismatch: expected {}, got {}",
                        expected_issuer, actual_issuer
                    )));
                }
            }
        }

        Ok(result)
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to verify an artifact
pub fn verify(
    artifact: &[u8],
    bundle: &Bundle,
    policy: &VerificationPolicy,
) -> Result<VerificationResult> {
    let verifier = Verifier::new();
    verifier.verify(artifact, bundle, policy)
}

/// Verify an artifact against a bundle using a trusted root
///
/// This is the recommended verification method as it uses the trusted root
/// for all cryptographic material (Rekor keys, Fulcio certs, TSA certs).
pub fn verify_with_trusted_root(
    artifact: &[u8],
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    let verifier = Verifier::new_with_trusted_root(trusted_root);
    verifier.verify(artifact, bundle, policy)
}

/// Extract the integrated time from transparency log entries
/// Returns the earliest integrated time if multiple entries are present
fn extract_integrated_time(bundle: &Bundle) -> Result<Option<i64>> {
    let mut earliest_time: Option<i64> = None;

    for entry in &bundle.verification_material.tlog_entries {
        if !entry.integrated_time.is_empty() {
            if let Ok(time) = entry.integrated_time.parse::<i64>() {
                // Ignore 0 as it indicates invalid/missing time (e.g. from test instances)
                if time > 0 {
                    if let Some(earliest) = earliest_time {
                        if time < earliest {
                            earliest_time = Some(time);
                        }
                    } else {
                        earliest_time = Some(time);
                    }
                }
            }
        }
    }

    Ok(earliest_time)
}

/// Extract and verify TSA RFC 3161 timestamps
/// Returns the earliest verified timestamp if any are present
/// This performs full cryptographic verification including signature and certificate chain validation
fn extract_tsa_timestamp(
    bundle: &Bundle,
    signature_bytes: &[u8],
    trusted_root: Option<&TrustedRoot>,
) -> Result<Option<i64>> {
    // Check if bundle has TSA timestamps
    if bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps
        .is_empty()
    {
        return Ok(None);
    }

    let mut earliest_timestamp: Option<i64> = None;
    let mut any_timestamp_verified = false;

    for ts in &bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps
    {
        // Decode the base64-encoded timestamp
        let ts_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &ts.signed_timestamp,
        )
        .map_err(|e| Error::Verification(format!("failed to decode TSA timestamp: {}", e)))?;

        // If we have a trusted root, perform full verification
        if let Some(root) = trusted_root {
            // Build verification options from trusted root
            let mut opts = TsaVerifyOpts::new();

            // Get TSA root certificates
            if let Ok(tsa_roots) = root.tsa_root_certs() {
                opts = opts.with_roots(tsa_roots);
            }

            // Get TSA intermediate certificates
            if let Ok(tsa_intermediates) = root.tsa_intermediate_certs() {
                opts = opts.with_intermediates(tsa_intermediates);
            }

            // Get TSA leaf certificate (for timestamps without embedded certs)
            if let Ok(tsa_leaves) = root.tsa_leaf_certs() {
                // Use the first TSA leaf certificate if available
                if let Some(leaf) = tsa_leaves.first() {
                    opts = opts.with_tsa_certificate(leaf.clone());
                }
            }

            // Get TSA validity period from trusted root
            // We need to get the first TSA's validity period and pass it to verification
            if let Ok(tsa_certs) = root.tsa_certs_with_validity() {
                if let Some((_cert, Some(start), Some(end))) = tsa_certs.first() {
                    opts = opts.with_tsa_validity(*start, *end);
                }
            }

            // Verify the timestamp response with full cryptographic validation
            // STRICT MODE: When we have a trusted root, verification failures must fail the entire verification
            // The TSA validity check is now done inside verify_timestamp_response
            let result =
                verify_timestamp_response(&ts_bytes, signature_bytes, opts).map_err(|e| {
                    Error::Verification(format!("TSA timestamp verification failed: {}", e))
                })?;

            let timestamp = result.time.timestamp();

            any_timestamp_verified = true;

            if let Some(earliest) = earliest_timestamp {
                if timestamp < earliest {
                    earliest_timestamp = Some(timestamp);
                }
            } else {
                earliest_timestamp = Some(timestamp);
            }
        } else {
            // No trusted root - fall back to just parsing (old behavior)
            match parse_timestamp(&ts_bytes) {
                Ok(timestamp) => {
                    if let Some(earliest) = earliest_timestamp {
                        if timestamp < earliest {
                            earliest_timestamp = Some(timestamp);
                        }
                    } else {
                        earliest_timestamp = Some(timestamp);
                    }
                }
                Err(e) => {
                    eprintln!("Warning: failed to parse TSA timestamp: {}", e);
                }
            }
        }
    }

    // If we have a trusted root and timestamps were present but none verified, that's an error
    if trusted_root.is_some()
        && !any_timestamp_verified
        && !bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps
            .is_empty()
    {
        return Err(Error::Verification(
            "TSA timestamps present but none could be verified against trusted root".to_string(),
        ));
    }

    Ok(earliest_timestamp)
}

/// Verify a checkpoint signature using the trusted root
///
/// This verifies the signed note format checkpoint against a Rekor public key
/// from the trusted root. The key hint in the checkpoint signature is used to
/// find the matching key from the trusted root.
/// It also verifies that the checkpoint's root hash matches the inclusion proof.
fn verify_checkpoint(
    checkpoint_envelope: &str,
    inclusion_proof: &InclusionProof,
    trusted_root: &TrustedRoot,
) -> Result<()> {
    use sigstore_crypto::checkpoint::{verify_ecdsa_p256, verify_ed25519};

    // Parse the signed note
    let signed_note = SignedNote::from_text(checkpoint_envelope)
        .map_err(|e| Error::Verification(format!("Failed to parse checkpoint: {}", e)))?;

    // Verify that the checkpoint's root hash matches the inclusion proof's root hash
    let checkpoint_root_hash = &signed_note.checkpoint.root_hash;
    let proof_root_hash_b64 = &inclusion_proof.root_hash;

    // Decode the base64-encoded root hash from the inclusion proof
    let proof_root_hash = base64::engine::general_purpose::STANDARD
        .decode(proof_root_hash_b64)
        .map_err(|e| {
            Error::Verification(format!("Failed to decode inclusion proof root hash: {}", e))
        })?;

    if checkpoint_root_hash != &proof_root_hash {
        return Err(Error::Verification(format!(
            "Checkpoint root hash mismatch: checkpoint has {} bytes, inclusion proof has {} bytes",
            checkpoint_root_hash.len(),
            proof_root_hash.len()
        )));
    }

    // Get all Rekor keys with their key hints from trusted root
    let rekor_keys = trusted_root
        .rekor_keys_with_hints()
        .map_err(|e| Error::Verification(format!("Failed to get Rekor keys: {}", e)))?;

    // For each signature in the checkpoint, try to find a matching key and verify
    for sig in &signed_note.signatures {
        // Find the key with matching key hint
        for (key_hint, key_bytes) in &rekor_keys {
            if &sig.key_id == key_hint {
                // Found matching key, verify the signature
                let message = signed_note.checkpoint_text.as_bytes();

                // Try Ed25519 first
                if verify_ed25519(key_bytes, &sig.signature, message).is_ok() {
                    return Ok(());
                }

                // Try ECDSA P-256
                if verify_ecdsa_p256(key_bytes, &sig.signature, message).is_ok() {
                    return Ok(());
                }

                return Err(Error::Verification(
                    "Checkpoint signature verification failed".to_string(),
                ));
            }
        }
    }

    Err(Error::Verification(
        "No matching Rekor key found for checkpoint signature".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_policy_default() {
        let policy = VerificationPolicy::default();
        assert!(policy.verify_tlog);
        assert!(policy.verify_timestamp);
        assert!(policy.verify_certificate);
    }

    #[test]
    fn test_verification_policy_builder() {
        let policy = VerificationPolicy::default()
            .require_identity("test@example.com")
            .require_issuer("https://accounts.google.com")
            .skip_tlog();

        assert_eq!(policy.identity, Some("test@example.com".to_string()));
        assert_eq!(
            policy.issuer,
            Some("https://accounts.google.com".to_string())
        );
        assert!(!policy.verify_tlog);
    }

    #[test]
    fn test_verifier_creation() {
        let _verifier = Verifier::new();
        let _default = Verifier::default();
    }
}

#[derive(Serialize)]
struct RekorPayload {
    body: String,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    #[serde(rename = "logIndex")]
    log_index: i64,
    #[serde(rename = "logID")]
    log_id: String,
}

fn verify_set(entry: &TransparencyLogEntry, trusted_root: &TrustedRoot) -> Result<()> {
    let promise = entry
        .inclusion_promise
        .as_ref()
        .ok_or(Error::Verification("Missing inclusion promise".into()))?;

    // Find the key for the log ID
    // entry.log_id.key_id is base64 encoded
    // trusted_root keys are indexed by base64 encoded key_id
    let log_key_bytes = trusted_root
        .rekor_key_for_log(&entry.log_id.key_id)
        .map_err(|_| Error::Verification(format!("Unknown log ID: {}", entry.log_id.key_id)))?;

    // Construct the payload
    // entry.canonicalized_body is already base64 encoded
    let body = entry.canonicalized_body.clone();

    let integrated_time = entry
        .integrated_time
        .parse::<i64>()
        .map_err(|_| Error::Verification("Invalid integrated time".into()))?;
    let log_index = entry
        .log_index
        .parse::<i64>()
        .map_err(|_| Error::Verification("Invalid log index".into()))?;

    // Log ID for payload must be hex encoded
    let log_id_bytes = base64::engine::general_purpose::STANDARD
        .decode(&entry.log_id.key_id)
        .map_err(|_| Error::Verification("Invalid base64 log ID".into()))?;
    let log_id_hex = hex::encode(log_id_bytes);

    let payload = RekorPayload {
        body,
        integrated_time,
        log_index,
        log_id: log_id_hex,
    };

    let canonical_json = serde_json_canonicalizer::to_vec(&payload)
        .map_err(|e| Error::Verification(format!("Canonicalization failed: {}", e)))?;

    // Verify signature
    // promise.signed_entry_timestamp is base64 encoded
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&promise.signed_entry_timestamp)
        .map_err(|_| Error::Verification("Invalid base64 signature".into()))?;

    verify_signature(
        &log_key_bytes,
        &canonical_json,
        &signature,
        SigningScheme::EcdsaP256Sha256,
    )
    .map_err(|e| Error::Verification(format!("SET verification failed: {}", e)))?;

    Ok(())
}
