//! Dead Simple Signing Envelope (DSSE) types
//!
//! DSSE is a signature envelope format used for signing arbitrary payloads.
//! Specification: https://github.com/secure-systems-lab/dsse

use crate::encoding::{Base64Payload, Base64Signature};
use serde::{Deserialize, Serialize};

/// A DSSE envelope containing a signed payload
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    /// Type URI of the payload
    pub payload_type: String,
    /// Base64-encoded payload
    pub payload: Base64Payload,
    /// Signatures over the PAE (Pre-Authentication Encoding)
    pub signatures: Vec<DsseSignature>,
}

/// A signature in a DSSE envelope
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseSignature {
    /// Key ID (optional hint for key lookup)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyid: String,
    /// Base64-encoded signature
    pub sig: Base64Signature,
}

impl DsseEnvelope {
    /// Create a new DSSE envelope
    pub fn new(payload_type: String, payload: Base64Payload, signatures: Vec<DsseSignature>) -> Self {
        Self {
            payload_type,
            payload,
            signatures,
        }
    }

    /// Get the Pre-Authentication Encoding (PAE) string
    ///
    /// PAE is the string that gets signed in DSSE:
    /// `DSSEv1 <payload_type_len> <payload_type> <payload_len> <payload>`
    pub fn pae(&self) -> Vec<u8> {
        pae(&self.payload_type, self.payload.as_ref())
    }

    /// Decode the payload from base64
    pub fn decode_payload(&self) -> Result<Vec<u8>, base64::DecodeError> {
        self.payload.decode().map_err(|e| match e {
            crate::error::Error::Base64(e) => e,
            _ => base64::DecodeError::InvalidByte(0, 0),
        })
    }
}

/// Compute the Pre-Authentication Encoding (PAE)
///
/// Format: `DSSEv1 <len(type)> <type> <len(body)> <body>`
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    // "DSSEv1" + space
    result.extend_from_slice(b"DSSEv1 ");

    // payload_type length + space
    result.extend_from_slice(format!("{} ", payload_type.len()).as_bytes());

    // payload_type + space
    result.extend_from_slice(payload_type.as_bytes());
    result.push(b' ');

    // payload length + space
    result.extend_from_slice(format!("{} ", payload.len()).as_bytes());

    // payload
    result.extend_from_slice(payload);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pae() {
        // Test vector from DSSE spec
        let pae_result = pae("application/example", b"hello world");
        let expected = b"DSSEv1 19 application/example 11 hello world";
        assert_eq!(pae_result, expected);
    }

    #[test]
    fn test_dsse_envelope_serde() {
        let envelope = DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload: "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEifQ==".to_string().into(),
            signatures: vec![DsseSignature {
                keyid: "".to_string(),
                sig: "MEQCIHjhpw==".to_string().into(),
            }],
        };

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: DsseEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, parsed);
    }
}
