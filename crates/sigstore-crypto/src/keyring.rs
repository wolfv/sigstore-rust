//! Keyring for managing multiple verification keys
//!
//! A keyring holds multiple public keys and can verify signatures
//! against any of them.

use crate::error::{Error, Result};
use crate::verification::VerificationKey;
use std::collections::HashMap;

/// A keyring containing multiple verification keys
#[derive(Default)]
pub struct Keyring {
    /// Keys indexed by key ID
    keys: HashMap<Vec<u8>, VerificationKey>,
}

impl Keyring {
    /// Create a new empty keyring
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Add a key to the keyring
    pub fn add_key(&mut self, key_id: Vec<u8>, key: VerificationKey) {
        self.keys.insert(key_id, key);
    }

    /// Get a key by ID
    pub fn get_key(&self, key_id: &[u8]) -> Option<&VerificationKey> {
        self.keys.get(key_id)
    }

    /// Verify a signature using a specific key ID
    pub fn verify_with_key_id(&self, key_id: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
        let key = self
            .get_key(key_id)
            .ok_or_else(|| Error::Verification(format!("key not found: {:?}", key_id)))?;
        key.verify(data, signature)
    }

    /// Try to verify a signature with any key in the keyring
    pub fn verify_any(&self, data: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
        for (key_id, key) in &self.keys {
            if key.verify(data, signature).is_ok() {
                return Ok(key_id.clone());
            }
        }
        Err(Error::Verification(
            "no key in keyring verified the signature".to_string(),
        ))
    }

    /// Get the number of keys in the keyring
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Check if the keyring is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;
    use crate::signing::{KeyPair, SigningScheme};

    #[test]
    fn test_keyring_add_and_get() {
        let mut keyring = Keyring::new();
        let kp = KeyPair::generate_ed25519().unwrap();
        let key_id = sha256(kp.public_key_bytes()).to_vec();
        let vk = VerificationKey::new(kp.public_key_bytes().to_vec(), SigningScheme::Ed25519);

        keyring.add_key(key_id.clone(), vk);
        assert_eq!(keyring.len(), 1);
        assert!(keyring.get_key(&key_id).is_some());
    }

    #[test]
    fn test_keyring_verify() {
        let mut keyring = Keyring::new();
        let kp = KeyPair::generate_ed25519().unwrap();
        let key_id = sha256(kp.public_key_bytes()).to_vec();
        let vk = VerificationKey::new(kp.public_key_bytes().to_vec(), SigningScheme::Ed25519);

        keyring.add_key(key_id.clone(), vk);

        let data = b"test data";
        let sig = kp.sign(data).unwrap();

        assert!(keyring
            .verify_with_key_id(&key_id, data, sig.as_bytes())
            .is_ok());
    }

    #[test]
    fn test_keyring_verify_any() {
        let mut keyring = Keyring::new();

        // Add multiple keys
        for _ in 0..3 {
            let kp = KeyPair::generate_ed25519().unwrap();
            let key_id = sha256(kp.public_key_bytes()).to_vec();
            let vk = VerificationKey::new(kp.public_key_bytes().to_vec(), SigningScheme::Ed25519);
            keyring.add_key(key_id, vk);
        }

        // Sign with a new key and add it
        let kp = KeyPair::generate_ed25519().unwrap();
        let key_id = sha256(kp.public_key_bytes()).to_vec();
        let vk = VerificationKey::new(kp.public_key_bytes().to_vec(), SigningScheme::Ed25519);
        keyring.add_key(key_id.clone(), vk);

        let data = b"test data";
        let sig = kp.sign(data).unwrap();

        let result = keyring.verify_any(data, sig.as_bytes());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), key_id);
    }
}
