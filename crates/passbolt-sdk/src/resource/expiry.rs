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

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use crate::error::PassboltError;

/// Parse an expiry string into a JSON value suitable for the API.
///
/// Accepted formats:
/// - RFC3339 date/time:   `"2025-12-31T00:00:00Z"`
/// - Duration from now:   `"2w"`, `"7d"`, `"48h"`, `"30m"`, or a sum: `"1w2d3h"`
/// - Clear expiry:        `"none"` / `""`
pub fn parse_expiry(input: &str) -> Result<Value, PassboltError> {
    let input = input.trim();

    if input.is_empty() || input.eq_ignore_ascii_case("none") {
        return Ok(Value::Null);
    }

    // Try RFC3339 first
    if let Ok(expires_at) = input.parse::<DateTime<Utc>>() {
        return Ok(Value::String(expires_at.to_rfc3339()));
    }

    // Duration from now: 7d, 48h, 30m, or a sum such as 1w2d3h.
    let delta = parse_duration(input).ok_or_else(|| {
        PassboltError::InvalidArgument(format!(
            "Unrecognised expiry format: {input}  \
             (use RFC3339, a duration like '2w'/'7d'/'48h'/'30m' or '1w2d3h', or 'none')"
        ))
    })?;
    let expires_at = Utc::now().checked_add_signed(delta).ok_or_else(|| {
        PassboltError::InvalidArgument(format!("Expiry duration out of range: {input}"))
    })?;

    Ok(Value::String(expires_at.to_rfc3339()))
}

/// A sum of `<amount><unit>` with units `w`, `d`, `h`, `m`, `s`; `None` if anything else.
fn parse_duration(input: &str) -> Option<Duration> {
    let mut total = Duration::zero();
    let mut rest = input;
    while !rest.is_empty() {
        let digits = rest.find(|character: char| !character.is_ascii_digit())?;
        let (amount, after) = rest.split_at(digits);
        let amount: i64 = amount.parse().ok()?;
        let mut units = after.chars();
        let part = match units.next()? {
            'w' => Duration::try_weeks(amount),
            'd' => Duration::try_days(amount),
            'h' => Duration::try_hours(amount),
            'm' => Duration::try_minutes(amount),
            's' => Duration::try_seconds(amount),
            _ => None,
        }?;
        total = total.checked_add(&part)?;
        rest = units.as_str();
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[rstest::rstest]
    #[case("2w", Some(Duration::weeks(2)))]
    #[case("7d", Some(Duration::days(7)))]
    #[case("1w2d3h", Some(Duration::weeks(1) + Duration::days(2) + Duration::hours(3)))]
    #[case("1h30m", Some(Duration::minutes(90)))]
    #[case("", Some(Duration::zero()))]
    #[case("d", None)]
    #[case("7", None)]
    #[case("7x", None)]
    #[case("1w-2d", None)]
    #[case("99999999999999999999w", None)]
    fn test_parse_duration(#[case] input: &str, #[case] expected: Option<Duration>) {
        assert_eq!(parse_duration(input), expected);
    }
}
