//! TUF client for fetching Sigstore trusted roots
//!
//! This module provides functionality to securely fetch trusted root configuration
//! from Sigstore's TUF repository using The Update Framework protocol.
//!
//! # Example
//!
//! ```no_run
//! use sigstore_trust_root::TrustedRoot;
//!
//! # async fn example() -> Result<(), sigstore_trust_root::Error> {
//! // Fetch trusted root via TUF from production Sigstore
//! let root = TrustedRoot::from_tuf().await?;
//!
//! // Or from staging
//! let staging_root = TrustedRoot::from_tuf_staging().await?;
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;

use tough::{HttpTransport, IntoVec, RepositoryLoader, TargetName};
use url::Url;

use crate::{Error, Result, TrustedRoot};

/// Default Sigstore production TUF repository URL
pub const DEFAULT_TUF_URL: &str = "https://tuf-repo-cdn.sigstore.dev";

/// Sigstore staging TUF repository URL
pub const STAGING_TUF_URL: &str = "https://tuf-repo-cdn.sigstage.dev";

/// Embedded root.json for production TUF instance (version 1, used to bootstrap trust)
pub const PRODUCTION_TUF_ROOT: &[u8] = include_bytes!("../repository/tuf_root.json");

/// Embedded root.json for staging TUF instance
pub const STAGING_TUF_ROOT: &[u8] = include_bytes!("../repository/tuf_staging_root.json");

/// Configuration for TUF client
#[derive(Debug, Clone)]
pub struct TufConfig {
    /// Base URL for the TUF repository
    pub url: String,
    /// Path to local cache directory (optional)
    pub cache_dir: Option<PathBuf>,
    /// Whether to disable local caching
    pub disable_cache: bool,
}

impl Default for TufConfig {
    fn default() -> Self {
        Self {
            url: DEFAULT_TUF_URL.to_string(),
            cache_dir: None,
            disable_cache: false,
        }
    }
}

impl TufConfig {
    /// Create configuration for production Sigstore instance
    pub fn production() -> Self {
        Self::default()
    }

    /// Create configuration for staging Sigstore instance
    pub fn staging() -> Self {
        Self {
            url: STAGING_TUF_URL.to_string(),
            ..Default::default()
        }
    }

    /// Set the cache directory
    pub fn with_cache_dir(mut self, path: PathBuf) -> Self {
        self.cache_dir = Some(path);
        self
    }

    /// Disable local caching
    pub fn without_cache(mut self) -> Self {
        self.disable_cache = true;
        self
    }
}

/// Internal TUF client for fetching targets
struct TufClient {
    config: TufConfig,
    root_json: &'static [u8],
}

impl TufClient {
    /// Create a new client for production
    fn production() -> Self {
        Self {
            config: TufConfig::production(),
            root_json: PRODUCTION_TUF_ROOT,
        }
    }

    /// Create a new client for staging
    fn staging() -> Self {
        Self {
            config: TufConfig::staging(),
            root_json: STAGING_TUF_ROOT,
        }
    }

    /// Create a new client with custom configuration
    fn new(config: TufConfig, root_json: &'static [u8]) -> Self {
        Self { config, root_json }
    }

    /// Fetch a target file from the TUF repository
    async fn fetch_target(&self, target_name: &str) -> Result<Vec<u8>> {
        // Parse URLs
        let base_url = Url::parse(&self.config.url).map_err(|e| Error::Tuf(e.to_string()))?;
        let metadata_url = base_url.clone();
        let targets_url = base_url
            .join("targets/")
            .map_err(|e| Error::Tuf(e.to_string()))?;

        // Create repository loader with embedded root
        let root_bytes = self.root_json.to_vec();
        let mut loader = RepositoryLoader::new(&root_bytes, metadata_url, targets_url);

        // Use HTTP transport
        loader = loader.transport(HttpTransport::default());

        // Optionally set datastore for caching
        if !self.config.disable_cache {
            let cache_dir = self.get_cache_dir()?;
            tokio::fs::create_dir_all(&cache_dir)
                .await
                .map_err(|e| Error::Tuf(format!("Failed to create cache directory: {}", e)))?;
            loader = loader.datastore(cache_dir);
        }

        // Load the repository (fetches and verifies all metadata)
        let repo = loader
            .load()
            .await
            .map_err(|e| Error::Tuf(format!("TUF repository load failed: {}", e)))?;

        // Fetch the target
        let target = TargetName::new(target_name)
            .map_err(|e| Error::Tuf(format!("Invalid target name: {}", e)))?;
        let stream = repo
            .read_target(&target)
            .await
            .map_err(|e| Error::Tuf(format!("Failed to read target: {}", e)))?
            .ok_or_else(|| Error::Tuf(format!("Target not found: {}", target_name)))?;

        // Read all bytes from the stream
        let bytes = stream
            .into_vec()
            .await
            .map_err(|e| Error::Tuf(format!("Failed to read target contents: {}", e)))?;

        Ok(bytes)
    }

    /// Get the cache directory path
    fn get_cache_dir(&self) -> Result<PathBuf> {
        if let Some(ref dir) = self.config.cache_dir {
            return Ok(dir.clone());
        }

        // Use platform-specific cache directory
        let project_dirs = directories::ProjectDirs::from("dev", "sigstore", "sigstore-rust")
            .ok_or_else(|| Error::Tuf("Could not determine cache directory".into()))?;

        Ok(project_dirs.cache_dir().join("tuf"))
    }
}

impl TrustedRoot {
    /// Fetch the trusted root from Sigstore's production TUF repository
    ///
    /// This securely fetches the `trusted_root.json` using the TUF protocol,
    /// verifying all metadata signatures against the embedded root of trust.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_trust_root::TrustedRoot;
    ///
    /// # async fn example() -> Result<(), sigstore_trust_root::Error> {
    /// let root = TrustedRoot::from_tuf().await?;
    /// println!("Loaded {} Rekor logs", root.tlogs.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_tuf() -> Result<Self> {
        let client = TufClient::production();
        let bytes = client.fetch_target("trusted_root.json").await?;
        let json = String::from_utf8(bytes)
            .map_err(|e| Error::Tuf(format!("Invalid UTF-8 in trusted_root.json: {}", e)))?;
        Self::from_json(&json)
    }

    /// Fetch the trusted root from Sigstore's staging TUF repository
    ///
    /// This is useful for testing against the staging Sigstore infrastructure.
    pub async fn from_tuf_staging() -> Result<Self> {
        let client = TufClient::staging();
        let bytes = client.fetch_target("trusted_root.json").await?;
        let json = String::from_utf8(bytes)
            .map_err(|e| Error::Tuf(format!("Invalid UTF-8 in trusted_root.json: {}", e)))?;
        Self::from_json(&json)
    }

    /// Fetch the trusted root from a custom TUF repository
    ///
    /// # Arguments
    ///
    /// * `config` - TUF client configuration
    /// * `tuf_root` - The TUF root.json to use for bootstrapping trust
    pub async fn from_tuf_with_config(config: TufConfig, tuf_root: &'static [u8]) -> Result<Self> {
        let client = TufClient::new(config, tuf_root);
        let bytes = client.fetch_target("trusted_root.json").await?;
        let json = String::from_utf8(bytes)
            .map_err(|e| Error::Tuf(format!("Invalid UTF-8 in trusted_root.json: {}", e)))?;
        Self::from_json(&json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuf_config_default() {
        let config = TufConfig::default();
        assert_eq!(config.url, DEFAULT_TUF_URL);
        assert!(config.cache_dir.is_none());
        assert!(!config.disable_cache);
    }

    #[test]
    fn test_tuf_config_staging() {
        let config = TufConfig::staging();
        assert_eq!(config.url, STAGING_TUF_URL);
    }

    #[test]
    fn test_tuf_config_builder() {
        let config = TufConfig::production()
            .with_cache_dir(PathBuf::from("/tmp/test"))
            .without_cache();
        assert!(config.disable_cache);
        assert_eq!(config.cache_dir, Some(PathBuf::from("/tmp/test")));
    }

    #[test]
    fn test_embedded_tuf_roots_are_valid_json() {
        // Verify the embedded TUF roots are valid JSON
        let _: serde_json::Value =
            serde_json::from_slice(PRODUCTION_TUF_ROOT).expect("Invalid production TUF root");
        let _: serde_json::Value =
            serde_json::from_slice(STAGING_TUF_ROOT).expect("Invalid staging TUF root");
    }
}
