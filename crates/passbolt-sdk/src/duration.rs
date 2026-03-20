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

//! Durations written as Go's `time.ParseDuration` reads them (`1m30s`, `500ms`, `1.5h`, `-1h`),
//! as go-passbolt-cli takes them on its command line and writes them in its config file.

use chrono::TimeDelta;

use crate::error::PassboltError;

const NANOSECOND: u128 = 1;
const MICROSECOND: u128 = 1_000 * NANOSECOND;
const MILLISECOND: u128 = 1_000 * MICROSECOND;
const SECOND: u128 = 1_000 * MILLISECOND;
const MINUTE: u128 = 60 * SECOND;
const HOUR: u128 = 60 * MINUTE;

fn unit_nanoseconds(unit: &str) -> Option<u128> {
    match unit {
        "ns" => Some(NANOSECOND),
        // U+00B5 (micro sign) and U+03BC (Greek mu), as Go accepts both.
        "us" | "\u{b5}s" | "\u{3bc}s" => Some(MICROSECOND),
        "ms" => Some(MILLISECOND),
        "s" => Some(SECOND),
        "m" => Some(MINUTE),
        "h" => Some(HOUR),
        _ => None,
    }
}

fn invalid(text: &str) -> PassboltError {
    PassboltError::InvalidArgument(format!("time: invalid duration {text:?}"))
}

/// Parse a duration with Go's grammar: an optional sign, then numbers (decimals allowed), each
/// followed by a unit among `ns`, `us` (`µs`), `ms`, `s`, `m` and `h`; `0` alone needs no unit.
/// The error messages are Go's.
pub fn parse_go_duration(text: &str) -> Result<TimeDelta, PassboltError> {
    let (negative, mut rest) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if rest == "0" {
        return Ok(TimeDelta::zero());
    }
    if rest.is_empty() {
        return Err(invalid(text));
    }
    let mut total: u128 = 0;
    while !rest.is_empty() {
        let integer_length = rest.bytes().take_while(u8::is_ascii_digit).count();
        let (integer_digits, after_integer) = rest.split_at(integer_length);
        let (fraction_digits, after_number) =
            after_integer
                .strip_prefix('.')
                .map_or(("", after_integer), |after_point| {
                    let fraction_length =
                        after_point.bytes().take_while(u8::is_ascii_digit).count();
                    after_point.split_at(fraction_length)
                });
        if integer_digits.is_empty() && fraction_digits.is_empty() {
            return Err(invalid(text));
        }
        let unit_length = after_number
            .find(|character: char| character == '.' || character.is_ascii_digit())
            .unwrap_or(after_number.len());
        let (unit, after_unit) = after_number.split_at(unit_length);
        if unit.is_empty() {
            return Err(PassboltError::InvalidArgument(format!(
                "time: missing unit in duration {text:?}"
            )));
        }
        let unit_size = unit_nanoseconds(unit).ok_or_else(|| {
            PassboltError::InvalidArgument(format!(
                "time: unknown unit {unit:?} in duration {text:?}"
            ))
        })?;

        let integer: u128 = if integer_digits.is_empty() {
            0
        } else {
            integer_digits.parse().map_err(|_| invalid(text))?
        };
        let mut amount = integer
            .checked_mul(unit_size)
            .ok_or_else(|| invalid(text))?;
        // Digits past the nanosecond do not count; at most 39 digits fit in a u128.
        let mut scale: u128 = 1;
        let mut fraction: u128 = 0;
        for digit in fraction_digits.bytes().take(30) {
            fraction = fraction * 10 + u128::from(digit - b'0');
            scale *= 10;
        }
        amount = amount
            .checked_add(fraction.saturating_mul(unit_size) / scale)
            .ok_or_else(|| invalid(text))?;
        total = total.checked_add(amount).ok_or_else(|| invalid(text))?;
        if total > u128::from(i64::MAX.unsigned_abs()) + u128::from(negative) {
            return Err(invalid(text));
        }
        rest = after_unit;
    }
    let nanoseconds = i128::try_from(total).map_err(|_| invalid(text))?;
    let nanoseconds = i64::try_from(if negative { -nanoseconds } else { nanoseconds })
        .map_err(|_| invalid(text))?;
    Ok(TimeDelta::nanoseconds(nanoseconds))
}

/// Write `duration` as Go's `Duration.String` does: `1h0m0s`, `1m30s`, `1.5s`, `500ms`, `0s`.
#[must_use]
pub fn format_go_duration(duration: TimeDelta) -> String {
    let nanoseconds = i128::from(duration.num_nanoseconds().unwrap_or(i64::MAX));
    let sign = if nanoseconds < 0 { "-" } else { "" };
    let magnitude = nanoseconds.unsigned_abs();
    if magnitude == 0 {
        return "0s".into();
    }
    if magnitude < SECOND {
        let (unit, size) = if magnitude < MICROSECOND {
            ("ns", NANOSECOND)
        } else if magnitude < MILLISECOND {
            ("\u{b5}s", MICROSECOND)
        } else {
            ("ms", MILLISECOND)
        };
        return format!("{sign}{}{unit}", decimal(magnitude, size));
    }
    let hours = magnitude / HOUR;
    let minutes = magnitude % HOUR / MINUTE;
    let seconds = decimal(magnitude % MINUTE, SECOND);
    if hours > 0 {
        format!("{sign}{hours}h{minutes}m{seconds}s")
    } else if minutes > 0 {
        format!("{sign}{minutes}m{seconds}s")
    } else {
        format!("{sign}{seconds}s")
    }
}

/// `value / size` with its fraction, without trailing zeros.
fn decimal(value: u128, size: u128) -> String {
    let whole = value / size;
    let remainder = value % size;
    if remainder == 0 {
        return whole.to_string();
    }
    let width = size.ilog10() as usize;
    let fraction = format!("{remainder:0width$}");
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rstest::rstest;

    #[rstest]
    #[case("0", 0)]
    #[case("0s", 0)]
    #[case("-0", 0)]
    #[case("1ns", 1)]
    #[case("1us", 1_000)]
    #[case("1\u{b5}s", 1_000)]
    #[case("1\u{3bc}s", 1_000)]
    #[case("500ms", 500_000_000)]
    #[case("30s", 30_000_000_000)]
    #[case("1m0s", 60_000_000_000)]
    #[case("1m30s", 90_000_000_000)]
    #[case("1.5h", 5_400_000_000_000)]
    #[case(".5s", 500_000_000)]
    #[case("1.s", 1_000_000_000)]
    #[case("-1h", -3_600_000_000_000)]
    #[case("+10s", 10_000_000_000)]
    #[case("1h2m3s4ms", 3_723_004_000_000)]
    #[case("1.0000000001s", 1_000_000_000)]
    #[case("9223372036854775807ns", i64::MAX)]
    #[case("-9223372036854775808ns", i64::MIN)]
    fn test_parse_go_duration_accepts(#[case] text: &str, #[case] nanoseconds: i64) {
        assert_eq!(
            parse_go_duration(text).unwrap().num_nanoseconds(),
            Some(nanoseconds)
        );
    }

    #[rstest]
    #[case("", "invalid duration")]
    #[case("-", "invalid duration")]
    #[case("s", "invalid duration")]
    #[case(".s", "invalid duration")]
    #[case("30", "missing unit")]
    #[case("1h30", "missing unit")]
    #[case("1d", "unknown unit \"d\"")]
    #[case("1 s", "unknown unit \" s\"")]
    #[case("9223372036854775808ns", "invalid duration")]
    #[case("99999999999999999999999h", "invalid duration")]
    fn test_parse_go_duration_rejects(#[case] text: &str, #[case] message: &str) {
        let error = parse_go_duration(text).unwrap_err().to_string();

        assert!(error.contains(message), "{error}");
    }

    #[rstest]
    #[case(0, "0s")]
    #[case(1, "1ns")]
    #[case(1_500, "1.5\u{b5}s")]
    #[case(500_000_000, "500ms")]
    #[case(1_500_000_000, "1.5s")]
    #[case(60_000_000_000, "1m0s")]
    #[case(90_000_000_000, "1m30s")]
    #[case(3_600_000_000_000, "1h0m0s")]
    #[case(-60_000_000_000, "-1m0s")]
    fn test_format_go_duration(#[case] nanoseconds: i64, #[case] expected: &str) {
        assert_eq!(
            format_go_duration(TimeDelta::nanoseconds(nanoseconds)),
            expected
        );
    }

    proptest! {
        #[test]
        fn test_format_then_parse_gives_the_same_duration(nanoseconds in i64::MIN + 1..i64::MAX) {
            let duration = TimeDelta::nanoseconds(nanoseconds);

            prop_assert_eq!(parse_go_duration(&format_go_duration(duration)).unwrap(), duration);
        }

        #[test]
        fn test_parse_never_panics(text in "\\PC*") {
            let _ = parse_go_duration(&text);
        }
    }
}
