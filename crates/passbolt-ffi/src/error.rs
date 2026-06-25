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

use std::fmt;

use passbolt_sdk::error::{ApiError, PassboltError};

/// FFI-safe error type exposed to all target languages.
#[derive(Debug, uniffi::Error)]
pub enum PassboltFfiError {
    Transport { reason: String },
    Auth { reason: String },
    Crypto { reason: String },
    Api { status: u16, reason: String },
    NotFound { reason: String },
    Config { reason: String },
    InvalidArgument { reason: String },
    Other { reason: String },
}

impl fmt::Display for PassboltFfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { reason } => write!(f, "Transport error: {reason}"),
            Self::Auth { reason } => write!(f, "Auth error: {reason}"),
            Self::Crypto { reason } => write!(f, "Crypto error: {reason}"),
            Self::Api { status, reason } => write!(f, "API error ({status}): {reason}"),
            Self::NotFound { reason } => write!(f, "Not found: {reason}"),
            Self::Config { reason } => write!(f, "Config error: {reason}"),
            Self::InvalidArgument { reason } => write!(f, "Invalid argument: {reason}"),
            Self::Other { reason } => write!(f, "{reason}"),
        }
    }
}

impl From<PassboltError> for PassboltFfiError {
    fn from(e: PassboltError) -> Self {
        match e {
            PassboltError::Transport(transport_error) => Self::Transport {
                reason: transport_error.to_string(),
            },
            PassboltError::Auth(auth_error) => Self::Auth {
                reason: auth_error.to_string(),
            },
            PassboltError::Crypto(crypto_error) => Self::Crypto {
                reason: crypto_error.to_string(),
            },
            PassboltError::Api(ApiError {
                status, message, ..
            }) => Self::Api {
                status,
                reason: message,
            },
            PassboltError::NotFound(message) => Self::NotFound { reason: message },
            PassboltError::Config(message) => Self::Config { reason: message },
            PassboltError::InvalidArgument(message) => Self::InvalidArgument { reason: message },
            _ => Self::Other {
                reason: e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use passbolt_sdk::error::{AuthError, CryptoError, TransportError};
    use rstest::rstest;

    use super::*;

    fn variant_and_reason(error: &PassboltFfiError) -> (&'static str, &str) {
        match error {
            PassboltFfiError::Transport { reason } => ("Transport", reason),
            PassboltFfiError::Auth { reason } => ("Auth", reason),
            PassboltFfiError::Crypto { reason } => ("Crypto", reason),
            PassboltFfiError::Api { reason, .. } => ("Api", reason),
            PassboltFfiError::NotFound { reason } => ("NotFound", reason),
            PassboltFfiError::Config { reason } => ("Config", reason),
            PassboltFfiError::InvalidArgument { reason } => ("InvalidArgument", reason),
            PassboltFfiError::Other { reason } => ("Other", reason),
        }
    }

    fn json_error() -> serde_json::Error {
        serde_json::from_str::<serde_json::Value>("{").unwrap_err()
    }

    #[rstest]
    #[case::transport(
        TransportError::Network("connection refused".into()).into(),
        "Transport",
        "Network error: connection refused"
    )]
    #[case::auth(AuthError::SessionExpired.into(), "Auth", "Session expired")]
    #[case::crypto(
        CryptoError::Decrypt("bad packet".into()).into(),
        "Crypto",
        "PGP decryption failed: bad packet"
    )]
    #[case::not_found(PassboltError::NotFound("resource 42".into()), "NotFound", "resource 42")]
    #[case::config(PassboltError::Config("no server".into()), "Config", "no server")]
    #[case::invalid_argument(
        PassboltError::InvalidArgument("empty id".into()),
        "InvalidArgument",
        "empty id"
    )]
    #[case::other(PassboltError::Other("unexpected".into()), "Other", "unexpected")]
    fn test_from_passbolt_error_maps_variant_and_reason(
        #[case] error: PassboltError,
        #[case] expected_variant: &str,
        #[case] expected_reason: &str,
    ) {
        let ffi_error = PassboltFfiError::from(error);

        assert_eq!(
            variant_and_reason(&ffi_error),
            (expected_variant, expected_reason)
        );
    }

    #[test]
    fn test_from_api_error_keeps_status_and_reason() {
        let error = PassboltError::Api(ApiError {
            status: 403,
            message: "Forbidden".into(),
            validation_errors: None,
        });

        let ffi_error = PassboltFfiError::from(error);

        assert!(
            matches!(&ffi_error, PassboltFfiError::Api { status: 403, reason } if reason == "Forbidden"),
            "{ffi_error}"
        );
    }

    #[test]
    fn test_from_json_error_is_other_with_json_prefix() {
        let ffi_error = PassboltFfiError::from(PassboltError::Json(json_error()));

        let (variant, reason) = variant_and_reason(&ffi_error);
        assert_eq!(variant, "Other");
        assert!(reason.starts_with("JSON error: "), "{reason}");
    }

    #[rstest]
    #[case::transport(PassboltFfiError::Transport { reason: "down".into() }, "Transport error: down")]
    #[case::api(
        PassboltFfiError::Api { status: 500, reason: "boom".into() },
        "API error (500): boom"
    )]
    #[case::other(PassboltFfiError::Other { reason: "plain".into() }, "plain")]
    fn test_display_formats_variant(#[case] error: PassboltFfiError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }
}
