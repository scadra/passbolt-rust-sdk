// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

use thiserror::Error;

// ── Module-level error types ─────────────────────────────────────────────────

/// Transport-level errors from the HTTP layer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransportError {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Request timed out: {0}")]
    Timeout(String),
}

/// Authentication errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("Login failed: {0}")]
    LoginFailed(String),

    #[error("MFA required")]
    MfaRequired,

    #[error("MFA verification failed after {attempts} attempt(s): {message}")]
    MfaFailed { attempts: u32, message: String },

    #[error(
        "MFA with a TOTP code is not enabled for this account; it offers: {}",
        providers.join(", ")
    )]
    MfaUnsupported { providers: Vec<String> },

    #[error("The server ended the session after too many MFA attempts: {0}")]
    MfaLockedOut(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Server identity mismatch: {0}")]
    ServerIdentityMismatch(String),

    #[error("Post-login key cross-check failed")]
    KeyCrossCheckFailed,
}

/// Cryptographic operation errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("Failed to parse PGP key: {0}")]
    KeyParse(String),

    #[error("PGP decryption failed: {0}")]
    Decrypt(String),

    #[error("PGP encryption failed: {0}")]
    Encrypt(String),

    #[error(
        "The shared metadata key changed: {pinned} was trusted, the server now uses {active}. \
         Check the new key with your administrator, then run `passbolt verify` to trust it."
    )]
    UntrustedMetadataKey { pinned: String, active: String },
}

/// Structured API error with optional validation details.
#[derive(Debug, Error)]
#[error("API error ({status}): {message}")]
pub struct ApiError {
    pub status: u16,
    pub message: String,
    pub validation_errors: Option<serde_json::Value>,
}

// ── Aggregator ───────────────────────────────────────────────────────────────

/// SDK-level error type for all Passbolt operations.
///
/// `#[non_exhaustive]` ensures downstream callers use wildcard patterns,
/// allowing us to add variants without breaking API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PassboltError {
    #[error(transparent)]
    Transport(#[from] TransportError),

    #[error(transparent)]
    Auth(#[from] AuthError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Api(#[from] ApiError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::transport(TransportError::Timeout("30s".into()).into(), "Request timed out: 30s")]
    #[case::login(AuthError::LoginFailed("bad key".into()).into(), "Login failed: bad key")]
    #[case::mfa_failed(
        AuthError::MfaFailed { attempts: 3, message: "The OTP is not valid.".into() }.into(),
        "MFA verification failed after 3 attempt(s): The OTP is not valid."
    )]
    #[case::crypto(CryptoError::Decrypt("no key".into()).into(), "PGP decryption failed: no key")]
    #[case::api(
        ApiError { status: 404, message: "Not found".into(), validation_errors: None }.into(),
        "API error (404): Not found"
    )]
    #[case::not_found(PassboltError::NotFound("r1".into()), "Resource not found: r1")]
    #[case::config(PassboltError::Config("no url".into()), "Configuration error: no url")]
    #[case::invalid_argument(PassboltError::InvalidArgument("--name".into()), "Invalid argument: --name")]
    #[case::other(PassboltError::Other("as is".into()), "as is")]
    fn test_error_message(#[case] error: PassboltError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn test_from_json_error() {
        let json_error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();

        let error = PassboltError::from(json_error);

        assert!(error.to_string().starts_with("JSON error: "), "{error}");
    }
}
