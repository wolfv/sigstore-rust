//! Type-safe wrappers for encoded cryptographic data
//!
//! This module provides newtype wrappers that make it clear what encoding
//! format data is in, preventing confusion between DER, PEM, and raw bytes.

use crate::error::{Error, Result};

/// DER-encoded bytes (Distinguished Encoding Rules)
///
/// This is the binary ASN.1 encoding used for certificates, keys, and signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerBytes(Vec<u8>);

impl DerBytes {
    /// Create a new DER-encoded bytes wrapper
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to owned bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Get the length of the encoded data
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the encoded data is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for DerBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for DerBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl AsRef<[u8]> for DerBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A DER-encoded X.509 certificate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDer(DerBytes);

impl CertificateDer {
    /// Create from DER bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(DerBytes::new(bytes))
    }

    /// Create from PEM-encoded certificate
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let parsed = pem::parse(pem_str)
            .map_err(|e| Error::InvalidCertificate(format!("failed to parse PEM: {}", e)))?;

        if parsed.tag() != "CERTIFICATE" {
            return Err(Error::InvalidCertificate(format!(
                "expected CERTIFICATE PEM block, got {}",
                parsed.tag()
            )));
        }

        Ok(Self::new(parsed.contents().to_vec()))
    }

    /// Get the underlying DER bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Convert to owned DER bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

impl From<Vec<u8>> for CertificateDer {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for CertificateDer {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A DER-encoded SubjectPublicKeyInfo (SPKI)
///
/// This is the standard format for public keys that includes the algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeySpki(DerBytes);

impl PublicKeySpki {
    /// Create from DER bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(DerBytes::new(bytes))
    }

    /// Create from PEM-encoded public key
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let parsed = pem::parse(pem_str)
            .map_err(|e| Error::InvalidKey(format!("failed to parse PEM: {}", e)))?;

        if parsed.tag() != "PUBLIC KEY" {
            return Err(Error::InvalidKey(format!(
                "expected PUBLIC KEY PEM block, got {}",
                parsed.tag()
            )));
        }

        Ok(Self::new(parsed.contents().to_vec()))
    }

    /// Get the underlying DER bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Convert to owned DER bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    /// Extract the raw public key bytes (without the algorithm identifier)
    ///
    /// This parses the SPKI structure and returns just the key material.
    pub fn raw_key_bytes(&self) -> Result<Vec<u8>> {
        use spki::SubjectPublicKeyInfoRef;

        let spki = SubjectPublicKeyInfoRef::try_from(self.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("failed to parse SPKI: {}", e)))?;

        Ok(spki.subject_public_key.raw_bytes().to_vec())
    }

    /// Get the algorithm OID from the SPKI
    pub fn algorithm_oid(&self) -> Result<const_oid::ObjectIdentifier> {
        use spki::SubjectPublicKeyInfoRef;

        let spki = SubjectPublicKeyInfoRef::try_from(self.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("failed to parse SPKI: {}", e)))?;

        Ok(spki.algorithm.oid)
    }
}

impl From<Vec<u8>> for PublicKeySpki {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for PublicKeySpki {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Raw signature bytes (not DER-encoded)
///
/// For ECDSA signatures, this may be either raw (r||s) or DER-encoded depending
/// on the context. Use `SignatureDer` when the signature is definitely DER-encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBytes(Vec<u8>);

impl SignatureBytes {
    /// Create new signature bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to owned bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for SignatureBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A 4-byte key hint/ID used in checkpoint signatures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHint([u8; 4]);

impl KeyHint {
    /// Create a new key hint from bytes
    pub fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Compute key hint from a public key (first 4 bytes of SHA-256)
    pub fn from_public_key(public_key_der: &[u8]) -> Self {
        let hash = crate::hash::sha256(public_key_der);
        Self([hash[0], hash[1], hash[2], hash[3]])
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

impl From<[u8; 4]> for KeyHint {
    fn from(bytes: [u8; 4]) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8; 4]> for KeyHint {
    fn as_ref(&self) -> &[u8; 4] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_from_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----";
        let cert = CertificateDer::from_pem(pem).unwrap();
        assert_eq!(cert.as_bytes(), b"abcd");
    }

    #[test]
    fn test_certificate_from_pem_wrong_type() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----";
        let result = CertificateDer::from_pem(pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_hint_from_public_key() {
        let key = b"test public key";
        let hint = KeyHint::from_public_key(key);
        assert_eq!(hint.as_bytes().len(), 4);
    }
}
