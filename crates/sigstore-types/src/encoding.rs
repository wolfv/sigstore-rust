//! Type-safe encoding wrappers
//!
//! This module provides newtype wrappers around encoded data to prevent
//! encoding confusion and provide compile-time safety.

use crate::error::{Error, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Base64-encoded data
///
/// This type represents data that is base64-encoded (standard alphabet).
/// It provides safe conversion to/from raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Base64(String);

impl Base64 {
    /// Create a new Base64 wrapper from a string
    ///
    /// Note: This does not validate the base64 encoding.
    /// Use `decode()` to validate and extract bytes.
    pub fn new(s: String) -> Self {
        Base64(s)
    }

    /// Create a Base64 wrapper from raw bytes
    pub fn encode(bytes: &[u8]) -> Self {
        Base64(base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    /// Decode the base64 string to bytes
    pub fn decode(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.0)
            .map_err(|e| Error::InvalidEncoding(format!("invalid base64: {}", e)))
    }

    /// Get the underlying string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the underlying String
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for Base64 {
    fn from(s: String) -> Self {
        Base64(s)
    }
}

impl AsRef<str> for Base64 {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for Base64 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for Base64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<str> for Base64 {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<String> for Base64 {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl PartialEq<Base64> for String {
    fn eq(&self, other: &Base64) -> bool {
        self == &other.0
    }
}

impl PartialEq<Base64> for &str {
    fn eq(&self, other: &Base64) -> bool {
        *self == other.0
    }
}

/// Hex-encoded data
///
/// This type represents data that is hex-encoded (lowercase).
/// It provides safe conversion to/from raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hex(String);

impl Hex {
    /// Create a new Hex wrapper from a string
    ///
    /// Note: This does not validate the hex encoding.
    /// Use `decode()` to validate and extract bytes.
    pub fn new(s: String) -> Self {
        Hex(s)
    }

    /// Create a Hex wrapper from raw bytes
    pub fn encode(bytes: &[u8]) -> Self {
        Hex(hex::encode(bytes))
    }

    /// Decode the hex string to bytes
    pub fn decode(&self) -> Result<Vec<u8>> {
        hex::decode(&self.0).map_err(|e| Error::InvalidEncoding(format!("invalid hex: {}", e)))
    }

    /// Get the underlying string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into the underlying String
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<String> for Hex {
    fn from(s: String) -> Self {
        Hex(s)
    }
}

impl AsRef<str> for Hex {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// SHA-256 hash digest (32 bytes)
///
/// This type represents a SHA-256 hash with compile-time size guarantees.
/// It can be constructed from hex or base64 strings and converted back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Hash([u8; 32]);

impl Sha256Hash {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Sha256Hash(bytes)
    }

    /// Try to create from a byte slice
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidEncoding(format!(
                "SHA-256 hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Sha256Hash(arr))
    }

    /// Parse from hex-encoded string
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes =
            hex::decode(s).map_err(|e| Error::InvalidEncoding(format!("invalid hex: {}", e)))?;
        Self::try_from_slice(&bytes)
    }

    /// Parse from base64-encoded string
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| Error::InvalidEncoding(format!("invalid base64: {}", e)))?;
        Self::try_from_slice(&bytes)
    }

    /// Encode as hex string (lowercase)
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Encode as base64 string
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Sha256Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Sha256Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Sha256Hash(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"hello world";
        let encoded = Base64::encode(data);
        let decoded = encoded.decode().unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"hello world";
        let encoded = Hex::encode(data);
        let decoded = encoded.decode().unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_sha256_hex() {
        let hash_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let hash = Sha256Hash::from_hex(hash_hex).unwrap();
        assert_eq!(hash.to_hex(), hash_hex);
    }

    #[test]
    fn test_sha256_base64() {
        let hash_bytes = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        let hash = Sha256Hash::from_bytes(hash_bytes);
        let base64 = hash.to_base64();
        let decoded = Sha256Hash::from_base64(&base64).unwrap();
        assert_eq!(hash, decoded);
    }

    #[test]
    fn test_sha256_conversion() {
        let hash_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let from_hex = Sha256Hash::from_hex(hash_hex).unwrap();
        let from_base64 = Sha256Hash::from_base64(&from_hex.to_base64()).unwrap();
        assert_eq!(from_hex, from_base64);
    }
}
