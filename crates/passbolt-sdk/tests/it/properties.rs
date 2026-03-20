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

//! User input parsers: `--expiry` and `--filter`.

use chrono::{DateTime, Duration, Utc};
use passbolt_sdk::filter::{Filter, FilterOp};
use passbolt_sdk::resource::expiry::parse_expiry;
use proptest::prelude::*;
use rstest::rstest;
use serde_json::Value;

#[rstest]
#[case("")]
#[case("none")]
#[case("NONE")]
#[case("  none  ")]
fn expiry_none_clears_the_date(#[case] input: &str) {
    assert_eq!(parse_expiry(input).unwrap(), Value::Null);
}

#[rstest]
#[case("2025-12-31T23:59:59Z", "2025-12-31T23:59:59Z")]
#[case("2025-12-31T23:59:59+02:00", "2025-12-31T21:59:59Z")]
#[case("2025-12-31T23:59:59.750Z", "2025-12-31T23:59:59Z")]
fn expiry_normalizes_rfc3339_to_utc_seconds(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(parse_expiry(input).unwrap(), Value::String(expected.into()));
}

#[rstest]
#[case("7d", Duration::days(7))]
#[case("48h", Duration::hours(48))]
#[case("30m", Duration::minutes(30))]
fn expiry_durations_start_now(#[case] input: &str, #[case] duration: Duration) {
    let before = Utc::now();

    let expiry: DateTime<Utc> = parse_expiry(input)
        .unwrap()
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // Sent to the second: up to one second before `before + duration`.
    assert!(
        (before + duration - Duration::seconds(1)..=Utc::now() + duration).contains(&expiry),
        "{expiry}"
    );
}

#[rstest]
#[case("tomorrow")]
#[case("7")]
#[case("d")]
#[case("7x")]
#[case("seven d")]
#[case("136807903027m")]
#[case("9223372036854775807d")]
fn expiry_rejects_invalid_input(#[case] input: &str) {
    assert!(parse_expiry(input).is_err());
}

#[test]
fn expiry_accepts_weeks_and_combined_durations() {
    assert!(parse_expiry("2w").is_ok());
    assert!(parse_expiry("1w2d3h").is_ok());
}

proptest! {
    #[test]
    fn expiry_never_panics(input in "\\PC*") {
        let _ = parse_expiry(&input);
    }

    #[test]
    fn expiry_never_panics_on_huge_durations(amount in any::<i64>(), unit in "[dhm]") {
        let _ = parse_expiry(&format!("{amount}{unit}"));
    }

    #[test]
    fn filter_parse_never_panics(input in "\\PC*") {
        let _ = Filter::parse(&input);
    }

    #[test]
    fn filter_equality_roundtrips(field in "[a-zA-Z_]{1,12}", value in "[a-zA-Z0-9 @._-]{0,20}") {
        let filter = Filter::parse(&format!("{field}={value}")).unwrap();

        prop_assert_eq!(&filter.field, &field.to_lowercase());
        prop_assert!(matches!(filter.op, FilterOp::Eq));
        prop_assert_eq!(&filter.value, value.trim());
        let uppercased_value = value.trim().to_uppercase();
        prop_assert!(filter.matches_str(&uppercased_value));
    }

    #[test]
    fn contains_matches_any_string_holding_the_value(prefix in "[a-z]{0,8}", needle in "[a-z]{1,8}", suffix in "[a-z]{0,8}") {
        let filter = Filter::parse(&format!("name~={needle}")).unwrap();

        let candidate = format!("{prefix}{needle}{suffix}");
        prop_assert!(filter.matches_str(&candidate));
    }
}
