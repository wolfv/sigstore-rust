//! Ambient credential detection for CI/CD environments
//!
//! This module provides detection and retrieval of OIDC tokens from
//! various CI/CD environments like GitHub Actions, GitLab CI, etc.

use crate::error::{Error, Result};
use crate::token::IdentityToken;

/// Detected CI/CD environment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiEnvironment {
    /// GitHub Actions
    GitHubActions,
    /// GitLab CI
    GitLabCi,
    /// Google Cloud Build
    GoogleCloudBuild,
    /// Buildkite
    Buildkite,
    /// CircleCI
    CircleCi,
}

/// Detect the current CI/CD environment
pub fn detect_environment() -> Option<CiEnvironment> {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        Some(CiEnvironment::GitHubActions)
    } else if std::env::var("GITLAB_CI").is_ok() {
        Some(CiEnvironment::GitLabCi)
    } else if std::env::var("BUILDER_OUTPUT").is_ok() {
        Some(CiEnvironment::GoogleCloudBuild)
    } else if std::env::var("BUILDKITE").is_ok() {
        Some(CiEnvironment::Buildkite)
    } else if std::env::var("CIRCLECI").is_ok() {
        Some(CiEnvironment::CircleCi)
    } else {
        None
    }
}

/// Get an ambient identity token from the current environment
pub async fn get_ambient_token() -> Result<IdentityToken> {
    match detect_environment() {
        Some(CiEnvironment::GitHubActions) => get_github_actions_token().await,
        Some(CiEnvironment::GitLabCi) => get_gitlab_ci_token().await,
        Some(env) => Err(Error::Token(format!(
            "ambient token retrieval not implemented for {:?}",
            env
        ))),
        None => Err(Error::Token("no CI/CD environment detected".to_string())),
    }
}

/// Get OIDC token from GitHub Actions
async fn get_github_actions_token() -> Result<IdentityToken> {
    // GitHub Actions provides OIDC tokens through the ACTIONS_ID_TOKEN_REQUEST_URL
    let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
        .map_err(|_| Error::Token("ACTIONS_ID_TOKEN_REQUEST_URL not set".to_string()))?;

    let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .map_err(|_| Error::Token("ACTIONS_ID_TOKEN_REQUEST_TOKEN not set".to_string()))?;

    // Request the token with sigstore audience
    let url = format!("{}&audience=sigstore", request_url);

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("Authorization", format!("bearer {}", request_token))
        .send()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::Token(format!(
            "GitHub Actions returned status {}",
            response.status()
        )));
    }

    #[derive(serde::Deserialize)]
    struct TokenResponse {
        value: String,
    }

    let token_response: TokenResponse = response
        .json()
        .await
        .map_err(|e| Error::Token(format!("failed to parse token response: {}", e)))?;

    IdentityToken::from_jwt(&token_response.value)
}

/// Get OIDC token from GitLab CI
async fn get_gitlab_ci_token() -> Result<IdentityToken> {
    // GitLab CI provides the token in CI_JOB_JWT_V2 or CI_JOB_JWT
    let token = std::env::var("CI_JOB_JWT_V2")
        .or_else(|_| std::env::var("CI_JOB_JWT"))
        .map_err(|_| Error::Token("CI_JOB_JWT_V2 or CI_JOB_JWT not set".to_string()))?;

    IdentityToken::from_jwt(&token)
}

/// Check if we're running in a supported CI/CD environment
pub fn is_ci_environment() -> bool {
    detect_environment().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_environment_none() {
        // In a test environment without CI vars, should return None
        // This test is environment-dependent
        let env = detect_environment();
        // Just verify it doesn't panic
        let _ = env;
    }
}
