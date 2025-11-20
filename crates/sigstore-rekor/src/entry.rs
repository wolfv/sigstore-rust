//! Rekor log entry types

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A log entry from Rekor
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// UUID of the entry (the key in the response map)
    #[serde(skip)]
    pub uuid: String,
    /// Body of the entry (base64 encoded)
    pub body: String,
    /// Integrated time (Unix timestamp)
    pub integrated_time: i64,
    /// Log ID (SHA-256 of the public key)
    pub log_i_d: String,
    /// Log index
    pub log_index: i64,
    /// Verification data
    #[serde(default)]
    pub verification: Option<Verification>,
}

/// Verification data for a log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    /// Inclusion proof
    #[serde(default)]
    pub inclusion_proof: Option<InclusionProof>,
    /// Signed entry timestamp (SET)
    #[serde(default)]
    pub signed_entry_timestamp: Option<String>,
}

/// Inclusion proof for a log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    /// Checkpoint (signed tree head)
    pub checkpoint: String,
    /// Hashes in the proof path
    pub hashes: Vec<String>,
    /// Log index
    pub log_index: i64,
    /// Root hash
    pub root_hash: String,
    /// Tree size
    pub tree_size: i64,
}

/// Log info response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogInfo {
    /// Root hash of the tree
    pub root_hash: String,
    /// Signed tree head (checkpoint)
    pub signed_tree_head: String,
    /// Tree ID
    pub tree_i_d: String,
    /// Tree size
    pub tree_size: i64,
    /// Inactive shards
    #[serde(default)]
    pub inactive_shards: Vec<InactiveShard>,
}

/// Inactive shard info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InactiveShard {
    /// Root hash
    pub root_hash: String,
    /// Signed tree head
    pub signed_tree_head: String,
    /// Tree ID
    pub tree_i_d: String,
    /// Tree size
    pub tree_size: i64,
}

/// HashedRekord entry for creating new log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekord {
    /// API version
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Entry kind
    pub kind: String,
    /// Spec containing the actual data
    pub spec: HashedRekordSpec,
}

/// HashedRekord specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordSpec {
    /// Data containing the hash
    pub data: HashedRekordData,
    /// Signature
    pub signature: HashedRekordSignature,
}

/// Data portion of HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordData {
    /// Hash of the artifact
    pub hash: HashedRekordHash,
}

/// Hash in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordHash {
    /// Hash algorithm
    pub algorithm: String,
    /// Hash value (hex encoded)
    pub value: String,
}

/// Signature in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordSignature {
    /// Signature content (base64 encoded)
    pub content: String,
    /// Public key
    #[serde(rename = "publicKey")]
    pub public_key: HashedRekordPublicKey,
}

/// Public key in HashedRekord
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashedRekordPublicKey {
    /// PEM-encoded public key or certificate
    pub content: String,
}

impl HashedRekord {
    /// Create a new HashedRekord entry
    ///
    /// # Arguments
    /// * `artifact_hash` - Hex-encoded SHA256 hash of the artifact
    /// * `signature_base64` - Base64-encoded signature
    /// * `public_key_pem` - PEM-encoded public key or certificate (will be base64-encoded for API)
    pub fn new(artifact_hash: &str, signature_base64: &str, public_key_pem: &str) -> Self {
        // Rekor API expects the PEM to be base64-encoded
        let public_key_base64 = base64::engine::general_purpose::STANDARD.encode(public_key_pem);

        Self {
            api_version: "0.0.1".to_string(),
            kind: "hashedrekord".to_string(),
            spec: HashedRekordSpec {
                data: HashedRekordData {
                    hash: HashedRekordHash {
                        algorithm: "sha256".to_string(),
                        value: artifact_hash.to_string(),
                    },
                },
                signature: HashedRekordSignature {
                    content: signature_base64.to_string(),
                    public_key: HashedRekordPublicKey {
                        content: public_key_base64,
                    },
                },
            },
        }
    }
}

/// DSSE entry for creating new log entries with envelopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseEntry {
    /// API version
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Entry kind
    pub kind: String,
    /// Spec containing the actual data
    pub spec: DsseSpec,
}

/// DSSE specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSpec {
    /// The DSSE envelope
    #[serde(rename = "proposedContent")]
    pub proposed_content: DsseProposedContent,
}

/// DSSE proposed content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseProposedContent {
    /// The envelope containing the signed payload
    pub envelope: String,
    /// Verifiers (certificates or public keys)
    pub verifiers: Vec<String>,
}

impl DsseEntry {
    /// Create a new DSSE entry
    ///
    /// # Arguments
    /// * `envelope_json` - JSON-encoded DSSE envelope (passed as-is, not base64-encoded)
    /// * `certificate_pem` - PEM-encoded certificate (will be base64-encoded for API)
    pub fn new(envelope_json: &str, certificate_pem: &str) -> Self {
        // Rekor API expects the envelope as a JSON string, NOT base64-encoded
        // Rekor API expects the PEM to be base64-encoded
        let cert_base64 = base64::engine::general_purpose::STANDARD.encode(certificate_pem);

        Self {
            api_version: "0.0.1".to_string(),
            kind: "dsse".to_string(),
            spec: DsseSpec {
                proposed_content: DsseProposedContent {
                    envelope: envelope_json.to_string(),
                    verifiers: vec![cert_base64],
                },
            },
        }
    }
}

/// Response type for log entry retrieval (map of UUID -> entry)
pub type LogEntryResponse = HashMap<String, LogEntry>;

/// Search index request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchIndex {
    /// Email to search for
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Public key to search for
    #[serde(rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<SearchPublicKey>,
    /// Hash to search for
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Public key for search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPublicKey {
    /// Format of the key
    pub format: String,
    /// Key content
    pub content: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashed_rekord_creation() {
        let entry = HashedRekord::new(
            "abcd1234",
            "c2lnbmF0dXJl",
            "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        );
        assert_eq!(entry.kind, "hashedrekord");
        assert_eq!(entry.api_version, "0.0.1");
    }
}
