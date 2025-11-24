//! X.509 certificate utilities for Sigstore
//!
//! This module provides utilities for parsing and extracting information
//! from X.509 certificates used in Sigstore bundles.

use crate::error::{Error, Result};
use crate::SigningScheme;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

// OID constants for algorithm identification
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1};
use const_oid::ObjectIdentifier;

/// id-Ed25519: 1.3.101.112
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// rsaEncryption: 1.2.840.113549.1.1.1
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Fulcio issuer OID: 1.3.6.1.4.1.57264.1.1
/// This extension contains the OIDC issuer URL
const FULCIO_ISSUER_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");

/// Information extracted from a certificate
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Identity from SAN extension (email or URI)
    pub identity: Option<String>,
    /// Issuer from certificate (OIDC issuer URL from Fulcio extension)
    pub issuer: Option<String>,
    /// Not valid before (Unix timestamp)
    pub not_before: i64,
    /// Not valid after (Unix timestamp)
    pub not_after: i64,
    /// Public key bytes (raw bytes from SubjectPublicKeyInfo)
    pub public_key_bytes: Vec<u8>,
    /// Signing scheme derived from the public key algorithm
    pub signing_scheme: SigningScheme,
}

/// Parse certificate information from DER-encoded certificate
pub fn parse_certificate_info(cert_der: &[u8]) -> Result<CertificateInfo> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::InvalidCertificate(format!("failed to parse certificate: {}", e)))?;

    // Extract validity times
    let not_before = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs() as i64;
    let not_after = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64;

    // Extract public key in SPKI (SubjectPublicKeyInfo) DER format
    // This is required by aws-lc-rs UnparsedPublicKey, which expects the full SPKI,
    // not just the raw key bytes
    let public_key_info = &cert.tbs_certificate.subject_public_key_info;
    let public_key_bytes = public_key_info
        .to_der()
        .map_err(|e| Error::InvalidCertificate(format!("failed to encode SPKI: {}", e)))?;

    // Determine signing scheme from algorithm OID and parameters
    let signing_scheme = determine_signing_scheme(public_key_info)?;

    // Extract identity from SAN extension
    let identity = extract_san_identity(&cert)?;

    // Extract issuer from Fulcio extension
    let issuer = extract_fulcio_issuer(&cert)?;

    Ok(CertificateInfo {
        identity,
        issuer,
        not_before,
        not_after,
        public_key_bytes,
        signing_scheme,
    })
}

/// Determine the signing scheme from SubjectPublicKeyInfo
fn determine_signing_scheme(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) -> Result<SigningScheme> {
    let alg_oid = spki.algorithm.oid;

    if alg_oid == ID_EC_PUBLIC_KEY {
        // EC key - need to check curve parameter
        if let Some(params) = &spki.algorithm.parameters {
            // params.value() returns the raw OID bytes (without tag/length)
            // Use from_bytes which expects raw OID content bytes
            let curve_oid = ObjectIdentifier::from_bytes(params.value()).map_err(|e| {
                Error::InvalidCertificate(format!("failed to parse EC curve OID: {}", e))
            })?;

            if curve_oid == SECP_256_R_1 {
                return Ok(SigningScheme::EcdsaP256Sha256);
            } else if curve_oid == SECP_384_R_1 {
                return Ok(SigningScheme::EcdsaP384Sha384);
            } else {
                // Unknown EC curve - default to P-256 for compatibility
                tracing::warn!("Unknown EC curve OID: {}, defaulting to P-256", curve_oid);
                return Ok(SigningScheme::EcdsaP256Sha256);
            }
        } else {
            // EC key missing curve parameters - default to P-256 for compatibility
            tracing::warn!("EC key missing curve parameters, defaulting to P-256");
            return Ok(SigningScheme::EcdsaP256Sha256);
        }
    } else if alg_oid == RSA_ENCRYPTION {
        // RSA key - default to RSA PKCS#1 SHA-256
        // We can't determine padding from the certificate alone
        return Ok(SigningScheme::RsaPkcs1Sha256);
    } else if alg_oid == ID_ED25519 {
        return Ok(SigningScheme::Ed25519);
    }

    // Unknown algorithm - default to P-256 for compatibility
    tracing::warn!(
        "Unknown public key algorithm OID: {}, defaulting to P-256",
        alg_oid
    );
    Ok(SigningScheme::EcdsaP256Sha256)
}

/// Extract identity from Subject Alternative Name (SAN) extension
///
/// This extracts the email address or URI from the SAN extension using
/// x509-cert's proper ASN.1 parsing (handles all length encodings correctly).
pub fn extract_san_identity(cert: &Certificate) -> Result<Option<String>> {
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    // Try to get the SAN extension using the typed getter
    // Returns Option<(critical: bool, extension: T)>
    let san_opt: Option<(bool, SubjectAltName)> = cert
        .tbs_certificate
        .get()
        .map_err(|e| Error::InvalidCertificate(format!("failed to get SAN extension: {}", e)))?;

    let Some((_critical, san)) = san_opt else {
        return Ok(None);
    };

    // Iterate through GeneralNames and extract email or URI
    for name in san.0.iter() {
        match name {
            GeneralName::Rfc822Name(email) => {
                return Ok(Some(email.to_string()));
            }
            GeneralName::UniformResourceIdentifier(uri) => {
                return Ok(Some(uri.to_string()));
            }
            _ => continue,
        }
    }

    Ok(None)
}

/// Extract the OIDC issuer from Fulcio certificate extension
///
/// Fulcio certificates contain the OIDC issuer URL in extension OID 1.3.6.1.4.1.57264.1.1
pub fn extract_fulcio_issuer(cert: &Certificate) -> Result<Option<String>> {
    let extensions = match &cert.tbs_certificate.extensions {
        Some(exts) => exts,
        None => return Ok(None),
    };

    for ext in extensions.iter() {
        if ext.extn_id == FULCIO_ISSUER_OID {
            // The extension value is a UTF8String wrapped in OCTET STRING
            let value_bytes = ext.extn_value.as_bytes();

            // Try to decode as UTF8String (the value is DER-encoded)
            if let Ok(utf8_str) = der::asn1::Utf8StringRef::from_der(value_bytes) {
                return Ok(Some(utf8_str.to_string()));
            }

            // Fallback: try to interpret the raw bytes as UTF-8
            if let Ok(s) = std::str::from_utf8(value_bytes) {
                return Ok(Some(s.to_string()));
            }
        }
    }

    Ok(None)
}

/// Convert PEM-encoded certificate to DER
///
/// Uses the `pem` crate for robust parsing that handles all valid PEM formats.
pub fn der_from_pem(pem_str: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem_str)
        .map_err(|e| Error::InvalidCertificate(format!("failed to parse PEM: {}", e)))?;

    if parsed.tag() != "CERTIFICATE" {
        return Err(Error::InvalidCertificate(format!(
            "expected CERTIFICATE PEM block, got {}",
            parsed.tag()
        )));
    }

    Ok(parsed.contents().to_vec())
}

/// Convert any PEM-encoded data to DER (doesn't check the tag)
pub fn der_from_pem_any(pem_str: &str) -> Result<Vec<u8>> {
    let parsed =
        pem::parse(pem_str).map_err(|e| Error::Pem(format!("failed to parse PEM: {}", e)))?;

    Ok(parsed.contents().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_from_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----";
        let result = der_from_pem(pem);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"abcd");
    }

    #[test]
    fn test_der_from_pem_wrong_type() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----";
        let result = der_from_pem(pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_from_pem_invalid() {
        let pem = "not a pem";
        let result = der_from_pem(pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_from_pem_any() {
        let pem = "-----BEGIN PUBLIC KEY-----\nYWJjZA==\n-----END PUBLIC KEY-----";
        let result = der_from_pem_any(pem);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"abcd");
    }
}
