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

use crate::error::PassboltError;

/// Trait for providing MFA TOTP codes during authentication.
///
/// Synchronous because both interactive (rpassword) and non-interactive
/// (TOTP generation) implementations are CPU-only.
pub trait MfaProvider: Send + Sync {
    fn get_totp_code(&self) -> Result<String, PassboltError>;

    /// Told when the server refused the last code given, before another is asked.
    fn code_refused(&self) {}
}

/// Non-interactive MFA: the TOTP code of a base32 secret, as authenticator apps give it.
///
/// A code already sent is never sent again: a retry waits for the next 30-second window, and
/// at least `retry_delay`, so that each attempt has a chance.
#[cfg(feature = "totp")]
pub struct TotpProvider {
    secret: zeroize::Zeroizing<Vec<u8>>,
    offset_seconds: i64,
    retry_delay: std::time::Duration,
    last_window: std::sync::Mutex<Option<u64>>,
}

#[cfg(feature = "totp")]
impl TotpProvider {
    const PERIOD_SECONDS: u64 = 30;

    /// `secret` in base32; `offset_seconds` shifts the clock, as for a server ahead or behind.
    pub fn new(
        secret: &str,
        offset_seconds: i64,
        retry_delay: std::time::Duration,
    ) -> Result<Self, PassboltError> {
        let secret = totp_rs::Secret::Encoded(secret.trim().replace(' ', "").to_uppercase())
            .to_bytes()
            .map_err(|error| {
                PassboltError::InvalidArgument(format!(
                    "Invalid TOTP secret (must be base32): {error}"
                ))
            })?;
        Ok(Self {
            secret: zeroize::Zeroizing::new(secret),
            offset_seconds,
            retry_delay,
            last_window: std::sync::Mutex::new(None),
        })
    }

    /// The code at `unix_seconds` on the server's clock.
    #[must_use]
    pub fn code_at(&self, unix_seconds: u64) -> String {
        // Unchecked: 80-bit secrets (Google Authenticator's default) are below the RFC's 128-bit
        // advice, and still the most common.
        totp_rs::TOTP::new_unchecked(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            Self::PERIOD_SECONDS,
            self.secret.to_vec(),
        )
        .generate(unix_seconds)
    }

    /// The wait before trying again at `now`, the last code sent in the window `last_window`:
    /// until the next window, and at least `retry_delay`.
    fn wait_before_retry(&self, last_window: u64, now: u64) -> std::time::Duration {
        let next_window_start = (last_window + 1) * Self::PERIOD_SECONDS;
        std::time::Duration::from_secs(next_window_start.saturating_sub(now)).max(self.retry_delay)
    }

    fn server_now(&self) -> Result<u64, PassboltError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| PassboltError::Other(format!("System clock error: {error}")))?
            .as_secs();
        Ok(now.saturating_add_signed(self.offset_seconds))
    }
}

#[cfg(feature = "totp")]
impl MfaProvider for TotpProvider {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        let last_window = *self
            .last_window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut now = self.server_now()?;
        if let Some(last) = last_window {
            std::thread::sleep(self.wait_before_retry(last, now));
            now = self.server_now()?;
        }
        *self
            .last_window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(now / Self::PERIOD_SECONDS);
        Ok(self.code_at(now))
    }
}

#[cfg(all(test, feature = "totp"))]
mod tests {
    use rstest::rstest;

    use super::*;

    /// RFC 6238 SHA-1 seed "12345678901234567890", base32-encoded.
    const RFC_6238_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn provider(secret: &str) -> TotpProvider {
        TotpProvider::new(secret, 0, std::time::Duration::ZERO).unwrap()
    }

    #[rstest]
    #[case(59, "287082")]
    #[case(1_111_111_109, "081804")]
    #[case(1_234_567_890, "005924")]
    #[case(20_000_000_000, "353130")]
    fn test_codes_match_the_rfc_6238_vectors(#[case] now: u64, #[case] expected: &str) {
        assert_eq!(provider(RFC_6238_SECRET).code_at(now), expected);
    }

    #[test]
    fn test_an_80_bit_secret_is_accepted() {
        // Google Authenticator's default length, under the RFC's advice.
        assert!(TotpProvider::new("JBSWY3DPEHPK3PXP", 0, std::time::Duration::ZERO).is_ok());
    }

    #[test]
    fn test_a_secret_written_in_groups_is_accepted() {
        assert_eq!(
            provider("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").code_at(59),
            "287082"
        );
    }

    #[test]
    fn test_a_secret_that_is_not_base32_is_refused() {
        let error = TotpProvider::new("not base32!", 0, std::time::Duration::ZERO)
            .err()
            .unwrap();

        assert!(error.to_string().contains("base32"), "{error}");
    }

    #[test]
    fn test_the_offset_shifts_the_clock() {
        let ahead = TotpProvider::new(RFC_6238_SECRET, 3600, std::time::Duration::ZERO).unwrap();

        let difference =
            ahead.server_now().unwrap() - provider(RFC_6238_SECRET).server_now().unwrap();

        assert!((3599..=3601).contains(&difference), "{difference}");
    }

    #[rstest]
    #[case::start_of_the_window(60, 30)]
    #[case::end_of_the_window(89, 1)]
    #[case::window_already_over(95, 0)]
    fn test_a_retry_waits_for_the_next_window(#[case] now: u64, #[case] seconds: u64) {
        // The last code was sent in the window 60..90.
        assert_eq!(
            provider(RFC_6238_SECRET).wait_before_retry(2, now),
            std::time::Duration::from_secs(seconds)
        );
    }

    #[test]
    fn test_a_retry_waits_at_least_the_delay_asked() {
        let provider =
            TotpProvider::new(RFC_6238_SECRET, 0, std::time::Duration::from_secs(10)).unwrap();

        assert_eq!(
            provider.wait_before_retry(2, 89),
            std::time::Duration::from_secs(10)
        );
    }

    #[test]
    fn test_the_first_code_is_given_at_once() {
        let started = std::time::Instant::now();

        let code = provider(RFC_6238_SECRET).get_totp_code().unwrap();

        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(code.len(), 6);
    }
}
