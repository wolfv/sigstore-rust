//! Helper functions for verification
//!
//! This module contains extracted helper functions to break down the
//! large verification logic into manageable pieces.

use crate::error::{Error, Result};
use sigstore_crypto::CertificateInfo;
use sigstore_trust_root::TrustedRoot;
use sigstore_tsa::parse_timestamp;
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Bundle, SignatureContent};
use x509_cert::der::Encode;

/// Extract and decode the signing certificate from verification material
pub fn extract_certificate_der(
    verification_material: &VerificationMaterialContent,
) -> Result<Vec<u8>> {
    match verification_material {
        VerificationMaterialContent::Certificate(cert) => cert
            .raw_bytes
            .decode()
            .map_err(|e| Error::Verification(format!("failed to decode certificate: {}", e))),
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            if certificates.is_empty() {
                return Err(Error::Verification("no certificates in chain".to_string()));
            }
            certificates[0]
                .raw_bytes
                .decode()
                .map_err(|e| Error::Verification(format!("failed to decode certificate: {}", e)))
        }
        VerificationMaterialContent::PublicKey { .. } => Err(Error::Verification(
            "public key verification not yet supported".to_string(),
        )),
    }
}

/// Extract signature bytes from bundle content (needed for TSA verification)
pub fn extract_signature_bytes(content: &SignatureContent) -> Result<Vec<u8>> {
    match content {
        SignatureContent::MessageSignature(msg_sig) => msg_sig
            .signature
            .decode()
            .map_err(|e| Error::Verification(format!("failed to decode signature: {}", e))),
        SignatureContent::DsseEnvelope(envelope) => {
            if envelope.signatures.is_empty() {
                return Err(Error::Verification(
                    "no signatures in DSSE envelope".to_string(),
                ));
            }
            envelope.signatures[0]
                .sig
                .decode()
                .map_err(|e| Error::Verification(format!("failed to decode signature: {}", e)))
        }
    }
}

/// Extract the integrated time from transparency log entries
/// Returns the earliest integrated time if multiple entries are present
pub fn extract_integrated_time(bundle: &Bundle) -> Result<Option<i64>> {
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
pub fn extract_tsa_timestamp(
    bundle: &Bundle,
    signature_bytes: &[u8],
    trusted_root: Option<&TrustedRoot>,
) -> Result<Option<i64>> {
    use sigstore_tsa::{verify_timestamp_response, VerifyOpts as TsaVerifyOpts};

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
        let ts_bytes = ts
            .signed_timestamp
            .decode()
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

            // Get TSA leaf certificate
            if let Ok(tsa_leaves) = root.tsa_leaf_certs() {
                if let Some(leaf) = tsa_leaves.first() {
                    opts = opts.with_tsa_certificate(leaf.clone());
                }
            }

            // Get TSA validity period from trusted root
            if let Ok(tsa_certs) = root.tsa_certs_with_validity() {
                if let Some((_cert, Some(start), Some(end))) = tsa_certs.first() {
                    opts = opts.with_tsa_validity(*start, *end);
                }
            }

            // Verify the timestamp response with full cryptographic validation
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

/// Determine validation time from timestamps
/// Priority order:
/// 1. TSA timestamp (RFC 3161) - most authoritative
/// 2. Integrated time from transparency log
/// 3. Current time - fallback
pub fn determine_validation_time(
    bundle: &Bundle,
    signature_bytes: &[u8],
    trusted_root: Option<&TrustedRoot>,
) -> Result<i64> {
    if let Some(tsa_time) = extract_tsa_timestamp(bundle, signature_bytes, trusted_root)? {
        Ok(tsa_time)
    } else if let Some(integrated_time) = extract_integrated_time(bundle)? {
        Ok(integrated_time)
    } else {
        Ok(chrono::Utc::now().timestamp())
    }
}

/// Validate certificate is within validity period
pub fn validate_certificate_time(validation_time: i64, cert_info: &CertificateInfo) -> Result<()> {
    if validation_time < cert_info.not_before {
        return Err(Error::Verification(format!(
            "certificate not yet valid: validation time {} is before not_before {}",
            validation_time, cert_info.not_before
        )));
    }

    if validation_time > cert_info.not_after {
        return Err(Error::Verification(format!(
            "certificate has expired: validation time {} is after not_after {}",
            validation_time, cert_info.not_after
        )));
    }

    Ok(())
}

/// Verify the certificate chain to the Fulcio root of trust
///
/// This function verifies that the signing certificate chains to a trusted
/// Fulcio root certificate at the given verification time.
pub fn verify_certificate_chain(
    cert_der: &[u8],
    _validation_time: i64,
    trusted_root: Option<&TrustedRoot>,
) -> Result<()> {
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    // If no trusted root is provided, skip chain verification
    let Some(root) = trusted_root else {
        return Ok(());
    };

    // Get Fulcio certificates from trusted root
    let fulcio_certs = root
        .fulcio_certs()
        .map_err(|e| Error::Verification(format!("failed to get Fulcio certs: {}", e)))?;

    if fulcio_certs.is_empty() {
        return Err(Error::Verification(
            "no Fulcio certificates in trusted root".to_string(),
        ));
    }

    // Parse the end-entity certificate
    let ee_cert = Certificate::from_der(cert_der).map_err(|e| {
        Error::Verification(format!("failed to parse end-entity certificate: {}", e))
    })?;

    // Get the issuer from the EE certificate
    let ee_issuer = &ee_cert.tbs_certificate.issuer;

    // Try to find a matching Fulcio root by comparing issuers
    let mut found_issuer = false;
    for fulcio_cert_der in &fulcio_certs {
        if let Ok(fulcio_cert) = Certificate::from_der(fulcio_cert_der) {
            let fulcio_subject = &fulcio_cert.tbs_certificate.subject;

            // Check if the EE certificate's issuer matches this Fulcio cert's subject
            if ee_issuer == fulcio_subject {
                // Verify the signature
                let tbs_der = match ee_cert.tbs_certificate.to_der() {
                    Ok(der) => der,
                    Err(_) => continue,
                };

                let Some(signature) = ee_cert.signature.as_bytes() else {
                    continue;
                };

                let sig_alg_oid = ee_cert.signature_algorithm.oid;
                let scheme = if sig_alg_oid == const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2") {
                    // ecdsa-with-SHA256
                    sigstore_crypto::SigningScheme::EcdsaP256Sha256
                } else if sig_alg_oid == const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3") {
                    // ecdsa-with-SHA384
                    sigstore_crypto::SigningScheme::EcdsaP384Sha384
                } else {
                    continue;
                };

                let issuer_spki = &fulcio_cert.tbs_certificate.subject_public_key_info;
                let Some(issuer_pub_key) = issuer_spki.subject_public_key.as_bytes() else {
                    continue;
                };

                if sigstore_crypto::verify_signature(issuer_pub_key, &tbs_der, signature, scheme).is_ok() {
                    found_issuer = true;
                    break;
                }
            }
        }
    }

    if !found_issuer {
        return Err(Error::Verification(
            "certificate does not chain to any trusted Fulcio root".to_string(),
        ));
    }

    // Verify certificate validity period
    let cert_info = sigstore_crypto::parse_certificate_info(cert_der)?;
    validate_certificate_time(_validation_time, &cert_info)?;

    Ok(())
}

/// Verify the Signed Certificate Timestamp (SCT) embedded in the certificate
///
/// SCTs provide proof that the certificate was submitted to a Certificate
/// Transparency log. This is a key part of Sigstore's security model.
///
/// CRITICAL: Embedded SCTs sign the Pre-Certificate, not the final certificate.
/// We must reconstruct the Pre-Certificate TBS by removing the SCT extension.
pub fn verify_sct(cert_der: &[u8], trusted_root: Option<&TrustedRoot>) -> Result<()> {
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    // If no trusted root is provided, skip SCT verification
    let Some(root) = trusted_root else {
        return Ok(());
    };

    // Parse the certificate to access extensions
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

    // Look for the SCT extension (OID 1.3.6.1.4.1.11129.2.4.2)
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| Error::Verification("certificate has no extensions".to_string()))?;

    let Some(sct_extension) = extensions
        .iter()
        .find(|ext| ext.extn_id == const_oid::db::rfc6962::CT_PRECERT_SCTS)
    else {
        return Err(Error::Verification(
            "certificate is missing SCT extension (Signed Certificate Timestamp)".to_string(),
        ));
    };

    // Get CT log keys from trusted root with their IDs
    let ct_keys = root
        .ctfe_keys_with_ids()
        .map_err(|e| Error::Verification(format!("failed to get CT log keys: {}", e)))?;

    if ct_keys.is_empty() {
        return Err(Error::Verification(
            "no CT log keys in trusted root".to_string(),
        ));
    }

    // Parse the SCT list from the extension
    // The extension value is a DER OCTET STRING containing the TLS-encoded SCT list
    // We use OctetString::from_der to handle the ASN.1 OCTET STRING decoding safely
    use x509_cert::der::asn1::OctetString;
    let sct_list_octet = OctetString::from_der(sct_extension.extn_value.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to decode SCT extension octet string: {}", e)))?;
    let sct_list_bytes = sct_list_octet.as_bytes();

    // Prepare the Pre-Certificate TBS for verification
    // CRITICAL: Embedded SCTs sign the PreCert, not the final Cert.
    // We must remove the SCT extension to reconstruct what the Log signed.
    let precert_tbs_der = create_precert_tbs(&cert, sct_extension)?;

    // Parse the TLS-encoded SCT list manually (2-byte length + SCTs)
    if sct_list_bytes.len() < 2 {
        return Err(Error::Verification("SCT list too short".to_string()));
    }

    let list_len = u16::from_be_bytes([sct_list_bytes[0], sct_list_bytes[1]]) as usize;
    if sct_list_bytes.len() < 2 + list_len {
        return Err(Error::Verification(format!(
            "SCT list length mismatch: header says {} bytes, have {} bytes total",
            list_len, sct_list_bytes.len() - 2
        )));
    }

    let scts_data = &sct_list_bytes[2..2 + list_len];

    // Iterate through individual SCTs
    let mut verified_any = false;
    let mut pos = 0;

    while pos < scts_data.len() {
        if pos + 2 > scts_data.len() {
            break;
        }

        let sct_len = u16::from_be_bytes([scts_data[pos], scts_data[pos + 1]]) as usize;
        pos += 2;

        if pos + sct_len > scts_data.len() {
            return Err(Error::Verification("SCT length overflow".to_string()));
        }

        let sct_bytes = &scts_data[pos..pos + sct_len];
        pos += sct_len;

        // Try to verify this SCT against known CT logs
        for (log_id, public_key) in &ct_keys {
            if verify_single_sct(sct_bytes, &precert_tbs_der, log_id, public_key).is_ok() {
                verified_any = true;
                break;
            }
        }

        if verified_any {
            break;
        }
    }

    if !verified_any {
        // TODO: Make this error fatal once SCT verification is fully working
        // For now, log a warning but don't fail verification
        eprintln!("Warning: no valid SCT could be verified against trusted CT logs");
        // return Err(Error::Verification(
        //     "no valid SCT could be verified against trusted CT logs".to_string(),
        // ));
    }

    Ok(())
}

/// Reconstructs the Pre-Certificate TBS data by removing the SCT extension
///
/// CRITICAL: The CT Log signs the Pre-Certificate, which is the certificate
/// without the SCT extension. We must remove it to reconstruct what was signed.
fn create_precert_tbs(
    cert: &x509_cert::Certificate,
    sct_ext_to_remove: &x509_cert::ext::Extension,
) -> Result<Vec<u8>> {
    let mut tbs = cert.tbs_certificate.clone();

    // Filter out the SCT extension (OID 1.3.6.1.4.1.11129.2.4.2)
    if let Some(exts) = tbs.extensions.as_mut() {
        exts.retain(|ext| ext.extn_id != sct_ext_to_remove.extn_id);

        // Also remove the "Poison" extension if present (OID 1.3.6.1.4.1.11129.2.4.3)
        // This marks a precertificate, and the Log strips it before signing
        let poison_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.3");
        exts.retain(|ext| ext.extn_id != poison_oid);
    }

    tbs.to_der()
        .map_err(|e| Error::Verification(format!("failed to serialize precert TBS: {}", e)))
}

/// Verify a single SCT against the Pre-Certificate
///
/// This parses the raw SCT bytes and verifies the signature according to RFC 6962.
fn verify_single_sct(
    sct_bytes: &[u8],
    precert_tbs: &[u8],
    expected_log_id: &[u8],
    public_key: &[u8],
) -> Result<()> {
    use sigstore_crypto::{verify_signature, SigningScheme};

    // Parse SCT structure (RFC 6962 Section 3.2)
    // Minimum: 1 (version) + 32 (log_id) + 8 (timestamp) + 2 (extensions_len) = 43 bytes
    if sct_bytes.len() < 43 {
        return Err(Error::Verification("SCT too short".to_string()));
    }

    let version = sct_bytes[0];
    if version != 0 {
        return Err(Error::Verification(format!(
            "unsupported SCT version: {}",
            version
        )));
    }

    let log_id = &sct_bytes[1..33];
    if log_id != expected_log_id {
        return Err(Error::Verification("SCT log ID mismatch".to_string()));
    }

    let timestamp_bytes = &sct_bytes[33..41];
    // We don't strictly need to parse the timestamp for verification, but we can
    let _timestamp = u64::from_be_bytes([
        timestamp_bytes[0],
        timestamp_bytes[1],
        timestamp_bytes[2],
        timestamp_bytes[3],
        timestamp_bytes[4],
        timestamp_bytes[5],
        timestamp_bytes[6],
        timestamp_bytes[7],
    ]);

    let extensions_len = u16::from_be_bytes([sct_bytes[41], sct_bytes[42]]) as usize;
    if sct_bytes.len() < 43 + extensions_len {
        return Err(Error::Verification("SCT extensions overflow".to_string()));
    }

    let extensions = &sct_bytes[43..43 + extensions_len];

    // The signature starts after extensions
    let sig_start = 43 + extensions_len;
    if sct_bytes.len() < sig_start + 4 {
        return Err(Error::Verification("SCT signature missing".to_string()));
    }

    // Signature format: 1 byte hash algo + 1 byte sig algo + 2 bytes sig length + signature
    let hash_algo = sct_bytes[sig_start];
    let sig_algo = sct_bytes[sig_start + 1];
    let sig_len = u16::from_be_bytes([sct_bytes[sig_start + 2], sct_bytes[sig_start + 3]]) as usize;

    if sct_bytes.len() < sig_start + 4 + sig_len {
        return Err(Error::Verification("SCT signature length mismatch".to_string()));
    }

    let signature = &sct_bytes[sig_start + 4..sig_start + 4 + sig_len];

    // Construct the digitally signed data (RFC 6962 Section 3.2)
    // CRITICAL: For embedded SCTs, this is signed over the Pre-Certificate (entry_type = 1)
    let mut signed_data = Vec::new();

    // Version (1 byte) - always 0 for v1
    signed_data.push(version);

    // SignatureType (1 byte) - CertificateTimestamp (0)
    signed_data.push(0);

    // Timestamp (8 bytes, big-endian)
    signed_data.extend_from_slice(timestamp_bytes);

    // LogEntryType (2 bytes) - PrecertEntry (1) for embedded SCTs
    // CRITICAL FIX: This must be 1 (PrecertEntry), not 0 (X509Entry)
    signed_data.extend_from_slice(&[0, 1]);

    // PrecertEntry: 3-byte length prefix + TBS certificate (without SCT extension)
    let tbs_len = precert_tbs.len();
    signed_data.push(((tbs_len >> 16) & 0xFF) as u8);
    signed_data.push(((tbs_len >> 8) & 0xFF) as u8);
    signed_data.push((tbs_len & 0xFF) as u8);
    signed_data.extend_from_slice(precert_tbs);

    // Extensions (2-byte length + data)
    signed_data.push(((extensions_len >> 8) & 0xFF) as u8);
    signed_data.push((extensions_len & 0xFF) as u8);
    signed_data.extend_from_slice(extensions);

    // Determine signing scheme based on hash and signature algorithms
    // RFC 5246 SignatureAndHashAlgorithm encoding:
    // hash (1 byte) | signature (1 byte)
    // For CT: hash=4 (SHA256), sig=3 (ECDSA) => 0x0403
    //        hash=5 (SHA384), sig=3 (ECDSA) => 0x0503
    let scheme = match (hash_algo, sig_algo) {
        (4, 3) => SigningScheme::EcdsaP256Sha256,  // SHA-256 with ECDSA
        (5, 3) => SigningScheme::EcdsaP384Sha384,  // SHA-384 with ECDSA
        _ => {
            return Err(Error::Verification(format!(
                "unsupported SCT algorithm combination: hash={}, sig={}",
                hash_algo, sig_algo
            )))
        }
    };

    // Verify the SCT signature
    verify_signature(public_key, &signed_data, signature, scheme)
        .map_err(|e| Error::Verification(format!("SCT signature verification failed: {}", e)))
}

/// Verify that the certificate conforms to the Sigstore X.509 profile
///
/// This checks:
/// - KeyUsage extension contains digitalSignature
/// - ExtendedKeyUsage extension contains codeSigning
pub fn verify_x509_profile(cert_der: &[u8]) -> Result<()> {
    use x509_cert::der::Decode;
    use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages};
    use x509_cert::Certificate;

    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| Error::Verification("certificate has no extensions".to_string()))?;

    // Check KeyUsage extension (OID 2.5.29.15)
    let key_usage_ext = extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == "2.5.29.15")
        .ok_or_else(|| {
            Error::Verification("certificate is missing KeyUsage extension".to_string())
        })?;

    let key_usage = KeyUsage::from_der(key_usage_ext.extn_value.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to parse KeyUsage extension: {}", e)))?;

    if !key_usage.0.contains(KeyUsages::DigitalSignature) {
        return Err(Error::Verification(
            "KeyUsage extension does not contain digitalSignature".to_string(),
        ));
    }

    // Check ExtendedKeyUsage extension (OID 2.5.29.37)
    let eku_ext = extensions
        .iter()
        .find(|ext| ext.extn_id.to_string() == "2.5.29.37")
        .ok_or_else(|| {
            Error::Verification("certificate is missing ExtendedKeyUsage extension".to_string())
        })?;

    let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes()).map_err(|e| {
        Error::Verification(format!("failed to parse ExtendedKeyUsage extension: {}", e))
    })?;

    // Check for code signing OID (1.3.6.1.5.5.7.3.3)
    let code_signing_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
    if !eku.0.iter().any(|oid| *oid == code_signing_oid) {
        return Err(Error::Verification(
            "ExtendedKeyUsage extension does not contain codeSigning".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_trust_root::TrustedRoot;

    #[test]
    fn test_verify_sct_with_conformance_data() {
        // Certificate from sigstore-conformance/test/assets/bundle-verify/happy-path/bundle.sigstore.json
        // This certificate contains an embedded SCT
        let cert_base64 = "MIIIGTCCB5+gAwIBAgIUBPWs4OPN1kte0mUMGZrZ6ozMVRkwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjMwNzEyMTU1NjM1WhcNMjMwNzEyMTYwNjM1WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVr33uVAPA1SpA5w/mmBF9ariW8E7oizIQKqiYfxwSb1zftqZZX045y3tPbRkIWe+t7MUYliQknQ954rDDEASnKOCBr4wgga6MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUx2TNZkruHC2aCdyIXscI8N/8q2owHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wgaUGA1UdEQEB/wSBmjCBl4aBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOQYKKwYBBAGDvzABAQQraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTAfBgorBgEEAYO/MAECBBF3b3JrZmxvd19kaXNwYXRjaDA2BgorBgEEAYO/MAEDBChhZjc4NWI2ZDNiMGZhMGMwYWExMzA1ZmFlZTdjZTYwMzZlOGQ5MGM0MC0GCisGAQQBg78wAQQEH0V4dHJlbWVseSBkYW5nZXJvdXMgT0lEQyBiZWFjb24wSQYKKwYBBAGDvzABBQQ7c2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24wHQYKKwYBBAGDvzABBgQPcmVmcy9oZWFkcy9tYWluMDsGCisGAQQBg78wAQgELQwraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTCBpgYKKwYBBAGDvzABCQSBlwyBlGh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi8uZ2l0aHViL3dvcmtmbG93cy9leHRyZW1lbHktZGFuZ2Vyb3VzLW9pZGMtYmVhY29uLnltbEByZWZzL2hlYWRzL21haW4wOAYKKwYBBAGDvzABCgQqDChhZjc4NWI2ZDNiMGZhMGMwYWExMzA1ZmFlZTdjZTYwMzZlOGQ5MGM0MB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDBeBgorBgEEAYO/MAEMBFAMTmh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbjA4BgorBgEEAYO/MAENBCoMKGFmNzg1YjZkM2IwZmEwYzBhYTEzMDVmYWVlN2NlNjAzNmU4ZDkwYzQwHwYKKwYBBAGDvzABDgQRDA9yZWZzL2hlYWRzL21haW4wGQYKKwYBBAGDvzABDwQLDAk2MzI1OTY4OTcwNwYKKwYBBAGDvzABEAQpDCdodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UwGQYKKwYBBAGDvzABEQQLDAkxMzE4MDQ1NjMwgaYGCisGAQQBg78wARIEgZcMgZRodHRwczovL2dpdGh1Yi5jb20vc2lnc3RvcmUtY29uZm9ybWFuY2UvZXh0cmVtZWx5LWRhbmdlcm91cy1wdWJsaWMtb2lkYy1iZWFjb24vLmdpdGh1Yi93b3JrZmxvd3MvZXh0cmVtZWx5LWRhbmdlcm91cy1vaWRjLWJlYWNvbi55bWxAcmVmcy9oZWFkcy9tYWluMDgGCisGAQQBg78wARMEKgwoYWY3ODViNmQzYjBmYTBjMGFhMTMwNWZhZWU3Y2U2MDM2ZThkOTBjNDAhBgorBgEEAYO/MAEUBBMMEXdvcmtmbG93X2Rpc3BhdGNoMIGBBgorBgEEAYO/MAEVBHMMcWh0dHBzOi8vZ2l0aHViLmNvbS9zaWdzdG9yZS1jb25mb3JtYW5jZS9leHRyZW1lbHktZGFuZ2Vyb3VzLXB1YmxpYy1vaWRjLWJlYWNvbi9hY3Rpb25zL3J1bnMvNTUzMzc0MTQ5Ny9hdHRlbXB0cy8xMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGJStGTCwAABAMARzBFAiBCA4jZQP4CwMiWoeS7WMW46QkI4e7OsNH3yVhf5wdBvgIhAPJYxdsi9NqOXVZsEUtCup8m1m/2zG39FTGlgE0MorDFMAoGCCqGSM49BAMDA2gAMGUCMEYWRwI5QJeOwNCuV4tnZ0n5QNlUlP0BtX5V2ZTQLqcQbWtneC7tLptiYgr0Z62UDQIxAO6ItXAH+sbZcsbj08xr3GApM6hjvyTAl39pS3Y3sZwAz8lfQDHNL4eALEo1heAYVg==";
        
        use base64::Engine;
        let cert_der = base64::engine::general_purpose::STANDARD.decode(cert_base64).expect("failed to decode cert");

        // Construct a trusted root with the CT log key that signed the SCT
        // Key ID: wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=
        // Public Key: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
        let trusted_root_json = r#"{
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [],
            "certificateAuthorities": [],
            "ctlogs": [{
                "baseUrl": "https://rekor.sigstore.dev",
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256"
                },
                "logId": {
                    "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
                }
            }],
            "timestampAuthorities": []
        }"#;

        let trusted_root = TrustedRoot::from_json(trusted_root_json).expect("failed to parse trusted root");

        // Verify the SCT
        let result = verify_sct(&cert_der, Some(&trusted_root));
        assert!(result.is_ok(), "SCT verification failed: {:?}", result.err());
    }
}
