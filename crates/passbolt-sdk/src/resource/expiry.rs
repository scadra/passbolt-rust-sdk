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

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::Value;

use crate::error::PassboltError;

/// Parse an expiry string into a JSON value suitable for the API.
///
/// Accepted formats, sent in UTC to the second as go-passbolt-cli sends them:
/// - RFC3339 date/time:   `"2025-12-31T00:00:00Z"`
/// - Duration from now:   `"2w"`, `"7d"`, `"48h"`, `"30m"`, or a sum: `"1w2d3h"`
/// - Go duration from now: `"1.5h"`, `"300ms"`, `"2h45m30.5s"`, `"-1h"` (in the past)
/// - Clear expiry:        `"none"` / `""`
pub fn parse_expiry(input: &str) -> Result<Value, PassboltError> {
    let input = input.trim();

    if input.is_empty() || input.eq_ignore_ascii_case("none") {
        return Ok(Value::Null);
    }

    // Try RFC3339 first
    if let Ok(expires_at) = input.parse::<DateTime<Utc>>() {
        return Ok(Value::String(utc_seconds(expires_at)));
    }

    // Duration from now: 7d, 48h, 30m, a sum such as 1w2d3h, or a Go duration.
    let delta = parse_duration(input)
        .or_else(|| crate::duration::parse_go_duration(input).ok())
        .ok_or_else(|| {
            PassboltError::InvalidArgument(format!(
                "Unrecognised expiry format: {input}  \
                 (use RFC3339, a duration like '2w'/'7d'/'48h'/'1.5h'/'-1h' or '1w2d3h', or \
                 'none')"
            ))
        })?;
    let expires_at = Utc::now().checked_add_signed(delta).ok_or_else(|| {
        PassboltError::InvalidArgument(format!("Expiry duration out of range: {input}"))
    })?;

    Ok(Value::String(utc_seconds(expires_at)))
}

fn utc_seconds(date: DateTime<Utc>) -> String {
    date.to_rfc3339_opts(SecondsFormat::Secs, true)
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

    /// The expiry `input` gives, as a distance from now.
    fn from_now(input: &str) -> Duration {
        let expires_at: DateTime<Utc> = parse_expiry(input)
            .unwrap()
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        expires_at - Utc::now()
    }

    #[rstest::rstest]
    #[case("1.5h", Duration::minutes(90))]
    #[case("2h45m30.5s", Duration::seconds(9930))]
    #[case("-1h", Duration::hours(-1))]
    #[case("90m", Duration::minutes(90))]
    #[case("7d", Duration::days(7))]
    fn test_go_durations_and_ours_are_read_from_now(
        #[case] input: &str,
        #[case] expected: Duration,
    ) {
        assert!(
            (from_now(input) - expected).num_seconds().abs() <= 2,
            "{input}"
        );
    }

    #[test]
    fn test_a_date_is_sent_in_utc_to_the_second() {
        assert_eq!(
            parse_expiry("2025-12-31T01:00:00.123+01:00").unwrap(),
            "2025-12-31T00:00:00Z"
        );
    }

    #[rstest::rstest]
    #[case("7")]
    #[case("7x")]
    #[case("1.5")]
    fn test_an_unknown_expiry_is_refused(#[case] input: &str) {
        assert!(parse_expiry(input).is_err());
    }
}
