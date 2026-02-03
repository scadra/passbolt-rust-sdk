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

/// Simple field-based filter for structured data.
///
/// Syntax: `field=value`, `field~=value` (contains), `field^=value` (starts),
/// `field$=value` (ends with). Case-insensitive comparisons.
use crate::error::PassboltError;

#[derive(Debug, Clone)]
pub struct Filter {
    pub field: String,
    pub op: FilterOp,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    Eq,
    Contains,
    StartsWith,
    EndsWith,
    NotEq,
}

impl Filter {
    /// `field<operator>value`: the first operator written splits it, so the value may hold
    /// operators itself (`uri=a!=b` is `uri` equal to `a!=b`).
    pub fn parse(expression: &str) -> Result<Self, PassboltError> {
        const OPERATORS: [(&str, FilterOp); 5] = [
            ("~=", FilterOp::Contains),
            ("^=", FilterOp::StartsWith),
            ("$=", FilterOp::EndsWith),
            ("!=", FilterOp::NotEq),
            ("=", FilterOp::Eq),
        ];
        // Two-character operators first: `a!=b` is `!=` at 1 before `=` at 2.
        let (position, operator, op) = OPERATORS
            .iter()
            .filter_map(|(operator, op)| {
                expression
                    .find(operator)
                    .map(|position| (position, *operator, *op))
            })
            .min_by_key(|(position, operator, _)| (*position, std::cmp::Reverse(operator.len())))
            .ok_or_else(|| {
                PassboltError::InvalidArgument(format!(
                    "Invalid filter expression: {expression}  (expected: field=value)"
                ))
            })?;
        Ok(Self {
            field: expression[..position].trim().to_lowercase(),
            op,
            value: expression[position + operator.len()..].trim().to_string(),
        })
    }

    /// Test a field value string against this filter.
    #[must_use]
    pub fn matches_str(&self, candidate: &str) -> bool {
        let value = self.value.to_lowercase();
        let candidate = candidate.to_lowercase();
        match self.op {
            FilterOp::Eq => candidate == value,
            FilterOp::NotEq => candidate != value,
            FilterOp::Contains => candidate.contains(&value),
            FilterOp::StartsWith => candidate.starts_with(&value),
            FilterOp::EndsWith => candidate.ends_with(&value),
        }
    }
}

/// Apply multiple filters against a map of field→value strings.
/// All filters must match (AND semantics).
#[must_use]
pub fn apply_filters<S: std::hash::BuildHasher>(
    filters: &[Filter],
    fields: &std::collections::HashMap<String, String, S>,
) -> bool {
    filters.iter().all(|filter| {
        fields
            .get(&filter.field)
            .is_some_and(|value| filter.matches_str(value))
    })
}

/// Generic filter: extract a field map per entity via `fields`, then apply `filters`.
///
/// Returns the input unchanged if `filters` is empty.
pub fn filter_entities<T, F>(entities: Vec<T>, filters: &[Filter], fields: F) -> Vec<T>
where
    F: Fn(&T) -> std::collections::HashMap<String, String>,
{
    if filters.is_empty() {
        return entities;
    }
    entities
        .into_iter()
        .filter(|entity| apply_filters(filters, &fields(entity)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ─── Filter::parse ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_eq() {
        let filter = Filter::parse("name=foo").unwrap();
        assert_eq!(filter.field, "name");
        assert!(matches!(filter.op, FilterOp::Eq));
        assert_eq!(filter.value, "foo");
    }

    #[test]
    fn test_parse_contains() {
        let filter = Filter::parse("name~=foo").unwrap();
        assert_eq!(filter.field, "name");
        assert!(matches!(filter.op, FilterOp::Contains));
        assert_eq!(filter.value, "foo");
    }

    #[test]
    fn test_parse_startswith() {
        let filter = Filter::parse("name^=foo").unwrap();
        assert_eq!(filter.field, "name");
        assert!(matches!(filter.op, FilterOp::StartsWith));
        assert_eq!(filter.value, "foo");
    }

    #[test]
    fn test_parse_endswith() {
        let filter = Filter::parse("name$=foo").unwrap();
        assert_eq!(filter.field, "name");
        assert!(matches!(filter.op, FilterOp::EndsWith));
        assert_eq!(filter.value, "foo");
    }

    #[test]
    fn test_parse_noteq() {
        let filter = Filter::parse("name!=foo").unwrap();
        assert_eq!(filter.field, "name");
        assert!(matches!(filter.op, FilterOp::NotEq));
        assert_eq!(filter.value, "foo");
    }

    #[test]
    fn test_parse_invalid() {
        assert!(Filter::parse("noop").is_err());
    }

    #[rstest::rstest]
    #[case::value_holding_another_operator("uri=a!=b", "uri", FilterOp::Eq, "a!=b")]
    #[case::value_holding_an_equal_sign("name~=x=y", "name", FilterOp::Contains, "x=y")]
    #[case::not_equal_before_equal("name!=a", "name", FilterOp::NotEq, "a")]
    #[case::starts_with_holding_contains(
        "uri^=https://a~=b",
        "uri",
        FilterOp::StartsWith,
        "https://a~=b"
    )]
    fn test_parse_splits_at_the_first_operator(
        #[case] expression: &str,
        #[case] field: &str,
        #[case] op: FilterOp,
        #[case] value: &str,
    ) {
        let filter = Filter::parse(expression).unwrap();

        assert_eq!(
            (filter.field.as_str(), filter.op, filter.value.as_str()),
            (field, op, value)
        );
    }

    #[test]
    fn test_an_invalid_expression_is_an_invalid_argument() {
        let error = Filter::parse("no operator").unwrap_err();

        assert!(
            matches!(error, PassboltError::InvalidArgument(_)),
            "{error:?}"
        );
    }

    #[test]
    fn test_parse_field_trimmed_lowercase() {
        let filter = Filter::parse("  Name  =bar").unwrap();
        assert_eq!(filter.field, "name");
        assert_eq!(filter.value, "bar");
    }

    // ─── Filter::matches_str ──────────────────────────────────────────────────

    #[test]
    fn test_matches_eq_case_insensitive() {
        let filter = Filter::parse("name=FOO").unwrap();
        assert!(filter.matches_str("foo"));
        assert!(filter.matches_str("FOO"));
        assert!(!filter.matches_str("bar"));
    }

    #[test]
    fn test_matches_contains() {
        let filter = Filter::parse("name~=oo").unwrap();
        assert!(filter.matches_str("foobar"));
        assert!(!filter.matches_str("bar"));
    }

    #[test]
    fn test_matches_startswith() {
        let filter = Filter::parse("name^=foo").unwrap();
        assert!(filter.matches_str("foobar"));
        assert!(!filter.matches_str("barfoo"));
    }

    #[test]
    fn test_matches_endswith() {
        let filter = Filter::parse("name$=bar").unwrap();
        assert!(filter.matches_str("foobar"));
        assert!(!filter.matches_str("barfoo"));
    }

    #[test]
    fn test_matches_not_eq() {
        let filter = Filter::parse("name!=foo").unwrap();
        assert!(filter.matches_str("bar"));
        assert!(!filter.matches_str("foo"));
    }

    // ─── filter_entities ─────────────────────────────────────────────────────

    fn make_fields(name: &str) -> HashMap<String, String> {
        let mut fields = HashMap::new();
        fields.insert("name".into(), name.into());
        fields
    }

    #[test]
    fn test_filter_entities_empty_filters_returns_all() {
        let items = vec!["alpha", "beta", "gamma"];
        let result = filter_entities(items.clone(), &[], |name| make_fields(name));
        assert_eq!(result, items);
    }

    #[test]
    fn test_filter_entities_no_match() {
        let items = vec!["alpha", "beta"];
        let filter = Filter::parse("name=zzz").unwrap();
        let result = filter_entities(items, &[filter], |name| make_fields(name));
        assert_eq!(result, [] as [&str; 0]);
    }

    #[test]
    fn test_filter_entities_partial_match() {
        let items = vec!["alpha", "beta", "alphabet"];
        let filter = Filter::parse("name^=alpha").unwrap();
        let result = filter_entities(items, &[filter], |name| make_fields(name));
        assert_eq!(result, vec!["alpha", "alphabet"]);
    }

    #[test]
    fn test_filter_entities_multiple_filters_and_semantics() {
        let items = vec!["foobar", "foo", "bar", "foobaz"];
        let starts_with_foo = Filter::parse("name^=foo").unwrap();
        let ends_with_bar = Filter::parse("name$=bar").unwrap();
        let result = filter_entities(items, &[starts_with_foo, ends_with_bar], |name| {
            make_fields(name)
        });
        // Only "foobar" starts with "foo" AND ends with "bar"
        assert_eq!(result, vec!["foobar"]);
    }
}
