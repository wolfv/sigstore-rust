//! Hashing utilities using aws-lc-rs

use aws_lc_rs::digest::{self, Context, SHA256, SHA384, SHA512};

/// Hash data using SHA-256
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&SHA256, data);
    let mut result = [0u8; 32];
    result.copy_from_slice(digest.as_ref());
    result
}

/// Hash data using SHA-384
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let digest = digest::digest(&SHA384, data);
    let mut result = [0u8; 48];
    result.copy_from_slice(digest.as_ref());
    result
}

/// Hash data using SHA-512
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let digest = digest::digest(&SHA512, data);
    let mut result = [0u8; 64];
    result.copy_from_slice(digest.as_ref());
    result
}

/// Incremental SHA-256 hasher
pub struct Sha256Hasher {
    context: Context,
}

impl Sha256Hasher {
    /// Create a new SHA-256 hasher
    pub fn new() -> Self {
        Self {
            context: Context::new(&SHA256),
        }
    }

    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Finalize and get the digest
    pub fn finalize(self) -> [u8; 32] {
        let digest = self.context.finish();
        let mut result = [0u8; 32];
        result.copy_from_slice(digest.as_ref());
        result
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(hash.len(), 32);

        // Known SHA-256 hash of "hello"
        let expected =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_sha256_incremental() {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"hel");
        hasher.update(b"lo");
        let hash = hasher.finalize();

        let direct = sha256(b"hello");
        assert_eq!(hash, direct);
    }
}
