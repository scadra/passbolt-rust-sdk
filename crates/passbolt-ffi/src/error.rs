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

use passbolt_sdk::error::{ApiError, PassboltError as SdkError};

/// FFI-safe error type exposed to all target languages.
#[derive(Debug, uniffi::Error)]
pub enum PassboltError {
    Transport { reason: String },
    Auth { reason: String },
    Crypto { reason: String },
    Api { status: u16, reason: String },
    NotFound { reason: String },
    Config { reason: String },
    InvalidArgument { reason: String },
    Other { reason: String },
}

impl fmt::Display for PassboltError {
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

impl From<SdkError> for PassboltError {
    fn from(e: SdkError) -> Self {
        match e {
            SdkError::Transport(transport_error) => Self::Transport {
                reason: transport_error.to_string(),
            },
            SdkError::Auth(auth_error) => Self::Auth {
                reason: auth_error.to_string(),
            },
            SdkError::Crypto(crypto_error) => Self::Crypto {
                reason: crypto_error.to_string(),
            },
            SdkError::Api(ApiError {
                status, message, ..
            }) => Self::Api {
                status,
                reason: message,
            },
            SdkError::NotFound(message) => Self::NotFound { reason: message },
            SdkError::Config(message) => Self::Config { reason: message },
            SdkError::InvalidArgument(message) => Self::InvalidArgument { reason: message },
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

    fn variant_and_reason(error: &PassboltError) -> (&'static str, &str) {
        match error {
            PassboltError::Transport { reason } => ("Transport", reason),
            PassboltError::Auth { reason } => ("Auth", reason),
            PassboltError::Crypto { reason } => ("Crypto", reason),
            PassboltError::Api { reason, .. } => ("Api", reason),
            PassboltError::NotFound { reason } => ("NotFound", reason),
            PassboltError::Config { reason } => ("Config", reason),
            PassboltError::InvalidArgument { reason } => ("InvalidArgument", reason),
            PassboltError::Other { reason } => ("Other", reason),
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
    #[case::not_found(SdkError::NotFound("resource 42".into()), "NotFound", "resource 42")]
    #[case::config(SdkError::Config("no server".into()), "Config", "no server")]
    #[case::invalid_argument(
        SdkError::InvalidArgument("empty id".into()),
        "InvalidArgument",
        "empty id"
    )]
    #[case::other(SdkError::Other("unexpected".into()), "Other", "unexpected")]
    fn test_from_passbolt_error_maps_variant_and_reason(
        #[case] error: SdkError,
        #[case] expected_variant: &str,
        #[case] expected_reason: &str,
    ) {
        let ffi_error = PassboltError::from(error);

        assert_eq!(
            variant_and_reason(&ffi_error),
            (expected_variant, expected_reason)
        );
    }

    #[test]
    fn test_from_api_error_keeps_status_and_reason() {
        let error = SdkError::Api(ApiError {
            status: 403,
            message: "Forbidden".into(),
            validation_errors: None,
        });

        let ffi_error = PassboltError::from(error);

        assert!(
            matches!(&ffi_error, PassboltError::Api { status: 403, reason } if reason == "Forbidden"),
            "{ffi_error}"
        );
    }

    #[test]
    fn test_from_json_error_is_other_with_json_prefix() {
        let ffi_error = PassboltError::from(SdkError::Json(json_error()));

        let (variant, reason) = variant_and_reason(&ffi_error);
        assert_eq!(variant, "Other");
        assert!(reason.starts_with("JSON error: "), "{reason}");
    }

    #[rstest]
    #[case::transport(PassboltError::Transport { reason: "down".into() }, "Transport error: down")]
    #[case::api(
        PassboltError::Api { status: 500, reason: "boom".into() },
        "API error (500): boom"
    )]
    #[case::other(PassboltError::Other { reason: "plain".into() }, "plain")]
    fn test_display_formats_variant(#[case] error: PassboltError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }
}
