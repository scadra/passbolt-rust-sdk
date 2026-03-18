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

//! `--filter` CEL expressions of `list resource|folder|user|group`, with the variables,
//! types and results of go-passbolt-cli (cel-go).

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use cel::common::ast::{operators, Expr, IdedExpr, LiteralValue};
use cel::{Context, Env, Program, Value};
use chrono::{DateTime, Utc};
use passbolt_sdk::filter::Filter as LegacyFilter;

/// The CEL type of a variable, as go-passbolt-cli declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    String,
    Bool,
    Int,
    Timestamp,
    /// `map(string, dyn)`
    Map,
}

/// One CEL variable: a spelling go-passbolt-cli accepts and the column it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Variable {
    pub name: &'static str,
    pub column: &'static str,
    pub kind: Kind,
}

const fn variable(name: &'static str, column: &'static str, kind: Kind) -> Variable {
    Variable { name, column, kind }
}

pub const RESOURCE_VARIABLES: &[Variable] = &[
    variable("id", "id", Kind::String),
    variable("ID", "id", Kind::String),
    variable("folder_parent_id", "folder_parent_id", Kind::String),
    variable("FolderParentID", "folder_parent_id", Kind::String),
    variable("folderparentid", "folder_parent_id", Kind::String),
    variable("name", "name", Kind::String),
    variable("Name", "name", Kind::String),
    variable("username", "username", Kind::String),
    variable("Username", "username", Kind::String),
    variable("uri", "uri", Kind::String),
    variable("URI", "uri", Kind::String),
    variable("password", "password", Kind::String),
    variable("Password", "password", Kind::String),
    variable("description", "description", Kind::String),
    variable("Description", "description", Kind::String),
    variable("created_timestamp", "created_timestamp", Kind::Timestamp),
    variable("CreatedTimestamp", "created_timestamp", Kind::Timestamp),
    variable("createdtimestamp", "created_timestamp", Kind::Timestamp),
    variable("modified_timestamp", "modified_timestamp", Kind::Timestamp),
    variable("ModifiedTimestamp", "modified_timestamp", Kind::Timestamp),
    variable("modifiedtimestamp", "modified_timestamp", Kind::Timestamp),
    variable("metadata", "metadata", Kind::Map),
    variable("Metadata", "metadata", Kind::Map),
    variable("secret", "secret", Kind::Map),
    variable("Secret", "secret", Kind::Map),
    variable("deleted", "deleted", Kind::Bool),
    variable("Deleted", "deleted", Kind::Bool),
    variable("expired", "expired", Kind::Bool),
    variable("Expired", "expired", Kind::Bool),
    variable("expired_at", "expired_at", Kind::Timestamp),
    variable("ExpiredAt", "expired_at", Kind::Timestamp),
    variable("expiredat", "expired_at", Kind::Timestamp),
    variable("resource_type_id", "resource_type_id", Kind::String),
    variable("ResourceTypeID", "resource_type_id", Kind::String),
    variable("resourcetypeid", "resource_type_id", Kind::String),
];

/// Resource columns whose value comes from the decrypted secret.
pub const RESOURCE_SECRET_COLUMNS: &[&str] = &["password", "description", "secret"];

pub const FOLDER_VARIABLES: &[Variable] = &[
    variable("id", "id", Kind::String),
    variable("ID", "id", Kind::String),
    variable("folder_parent_id", "folder_parent_id", Kind::String),
    variable("FolderParentID", "folder_parent_id", Kind::String),
    variable("folderparentid", "folder_parent_id", Kind::String),
    variable("name", "name", Kind::String),
    variable("Name", "name", Kind::String),
    variable("created_timestamp", "created_timestamp", Kind::Timestamp),
    variable("CreatedTimestamp", "created_timestamp", Kind::Timestamp),
    variable("createdtimestamp", "created_timestamp", Kind::Timestamp),
    variable("modified_timestamp", "modified_timestamp", Kind::Timestamp),
    variable("ModifiedTimestamp", "modified_timestamp", Kind::Timestamp),
    variable("modifiedtimestamp", "modified_timestamp", Kind::Timestamp),
    variable("personal", "personal", Kind::Bool),
    variable("Personal", "personal", Kind::Bool),
];

pub const USER_VARIABLES: &[Variable] = &[
    variable("id", "id", Kind::String),
    variable("ID", "id", Kind::String),
    variable("username", "username", Kind::String),
    variable("Username", "username", Kind::String),
    variable("first_name", "first_name", Kind::String),
    variable("FirstName", "first_name", Kind::String),
    variable("firstname", "first_name", Kind::String),
    variable("last_name", "last_name", Kind::String),
    variable("LastName", "last_name", Kind::String),
    variable("lastname", "last_name", Kind::String),
    variable("role", "role", Kind::String),
    variable("Role", "role", Kind::String),
    variable("created_timestamp", "created_timestamp", Kind::Timestamp),
    variable("CreatedTimestamp", "created_timestamp", Kind::Timestamp),
    variable("createdtimestamp", "created_timestamp", Kind::Timestamp),
    variable("modified_timestamp", "modified_timestamp", Kind::Timestamp),
    variable("ModifiedTimestamp", "modified_timestamp", Kind::Timestamp),
    variable("modifiedtimestamp", "modified_timestamp", Kind::Timestamp),
    variable("active", "active", Kind::Bool),
    variable("Active", "active", Kind::Bool),
    variable("deleted", "deleted", Kind::Bool),
    variable("Deleted", "deleted", Kind::Bool),
    variable("disabled", "disabled", Kind::Bool),
    variable("Disabled", "disabled", Kind::Bool),
];

pub const GROUP_VARIABLES: &[Variable] = &[
    variable("id", "id", Kind::String),
    variable("ID", "id", Kind::String),
    variable("name", "name", Kind::String),
    variable("Name", "name", Kind::String),
    variable("created_timestamp", "created_timestamp", Kind::Timestamp),
    variable("CreatedTimestamp", "created_timestamp", Kind::Timestamp),
    variable("createdtimestamp", "created_timestamp", Kind::Timestamp),
    variable("modified_timestamp", "modified_timestamp", Kind::Timestamp),
    variable("ModifiedTimestamp", "modified_timestamp", Kind::Timestamp),
    variable("modifiedtimestamp", "modified_timestamp", Kind::Timestamp),
    variable("deleted", "deleted", Kind::Bool),
    variable("Deleted", "deleted", Kind::Bool),
    variable("user_count", "user_count", Kind::Int),
    variable("UserCount", "user_count", Kind::Int),
    variable("usercount", "user_count", Kind::Int),
];

/// The value of one column for one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CelValue {
    String(String),
    Bool(bool),
    Int(i64),
    Timestamp(DateTime<Utc>),
    /// A JSON object; numbers become doubles, as Go's `encoding/json` decodes them.
    Map(serde_json::Map<String, serde_json::Value>),
}

/// Go's zero `time.Time`, which go-passbolt-cli gives `expired_at` when a resource never expired.
#[must_use]
pub fn zero_timestamp() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(-62_135_596_800, 0).unwrap_or_default()
}

/// A compiled `--filter` CEL expression.
pub struct Expression {
    text: String,
    program: Program,
    environment: Arc<Env>,
    /// Each variable spelling used in the expression, with the column it reads.
    references: Vec<Variable>,
}

impl Expression {
    /// Like cel-go, an undeclared variable and a result that is not a bool are compile errors.
    pub fn compile(text: &str, variables: &[Variable]) -> Result<Self> {
        let environment = Env::stdlib().with_optional_support(false);
        let program = environment
            .compile(text)
            .map_err(|errors| anyhow!("{errors}"))?;
        let mut checker = Checker {
            text,
            program: &program,
            variables,
            references: Vec::new(),
            scope: Vec::new(),
        };
        let result = checker.check(program.expression())?;
        if !matches!(result, StaticType::Bool | StaticType::Unknown) {
            bail!(
                "filter {text:?} must be a bool expression, not {}",
                result.name()
            );
        }
        let references = checker.references;
        Ok(Self {
            text: text.to_owned(),
            program,
            environment: Arc::new(environment),
            references,
        })
    }

    /// The canonical columns read by the expression, without duplicates.
    #[must_use]
    pub fn columns(&self) -> Vec<&'static str> {
        let mut columns: Vec<&'static str> = Vec::new();
        for reference in &self.references {
            if !columns.contains(&reference.column) {
                columns.push(reference.column);
            }
        }
        columns
    }

    /// Whether the expression reads one of `columns`, e.g. [`RESOURCE_SECRET_COLUMNS`].
    #[must_use]
    pub fn reads_any(&self, columns: &[&str]) -> bool {
        self.references
            .iter()
            .any(|reference| columns.contains(&reference.column))
    }

    /// `row` maps each canonical column of [`Expression::columns`] to its value.
    /// As in go-passbolt-cli, a result other than `true` does not match and an
    /// evaluation error (a missing map key, an overload that does not exist) is an error.
    pub fn matches(&self, row: &HashMap<&str, CelValue>) -> Result<bool> {
        let mut context = Context::with_env(Arc::clone(&self.environment));
        for reference in &self.references {
            let value = row
                .get(reference.column)
                .ok_or_else(|| anyhow!("no value for the filter column {}", reference.column))?;
            context.add_variable_from_value(reference.name, to_cel(value));
        }
        let result = self
            .program
            .execute(&context)
            .map_err(|error| anyhow!("filter {:?}: {error}", self.text))?;
        Ok(matches!(result, Value::Bool(true)))
    }

    /// The items whose row matches; none is an error naming `noun` (`resources`, `folders`,
    /// `users` or `groups`), worded as go-passbolt-cli words it.
    pub fn filter<T>(
        &self,
        items: Vec<T>,
        noun: &str,
        row: impl Fn(&T) -> HashMap<&'static str, CelValue>,
    ) -> Result<Vec<T>> {
        let mut matching = Vec::new();
        for item in items {
            if self.matches(&row(&item))? {
                matching.push(item);
            }
        }
        if matching.is_empty() {
            bail!("no such {noun} found with filter {}", self.text);
        }
        Ok(matching)
    }
}

/// A `--filter` value: CEL, or the legacy `field<operator>value` syntax.
pub enum FilterExpression {
    Cel(Expression),
    Legacy(LegacyFilter),
}

impl FilterExpression {
    /// CEL first; the legacy syntax only when the text is not CEL but parses as legacy,
    /// so `name=x` and `name~=x` stay legacy while `name != "x"` is CEL. Legacy has no `==`:
    /// a text holding one is CEL with a mistake. Otherwise the CEL error is reported when
    /// the text is not legacy either.
    pub fn parse(text: &str, variables: &[Variable]) -> Result<Self> {
        match Expression::compile(text, variables) {
            Ok(expression) => Ok(Self::Cel(expression)),
            Err(cel_error) if text.contains("==") => Err(cel_error),
            Err(cel_error) => LegacyFilter::parse(text)
                .map(Self::Legacy)
                .map_err(|_| cel_error),
        }
    }
}

fn to_cel(value: &CelValue) -> Value {
    match value {
        CelValue::String(text) => Value::from(text.clone()),
        CelValue::Bool(flag) => Value::Bool(*flag),
        CelValue::Int(number) => Value::Int(*number),
        CelValue::Timestamp(timestamp) => Value::Timestamp(timestamp.fixed_offset()),
        CelValue::Map(object) => object_to_cel(object),
    }
}

fn object_to_cel(object: &serde_json::Map<String, serde_json::Value>) -> Value {
    Value::from(
        object
            .iter()
            .map(|(key, value)| (key.clone(), json_to_cel(value)))
            .collect::<HashMap<String, Value>>(),
    )
}

fn json_to_cel(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(flag) => Value::Bool(*flag),
        serde_json::Value::Number(number) => Value::Float(number.as_f64().unwrap_or(f64::NAN)),
        serde_json::Value::String(text) => Value::from(text.clone()),
        serde_json::Value::Array(items) => {
            Value::from(items.iter().map(json_to_cel).collect::<Vec<_>>())
        }
        serde_json::Value::Object(object) => object_to_cel(object),
    }
}

/// What can be told of a sub-expression's type without running it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticType {
    Bool,
    String,
    Int,
    Uint,
    Double,
    Bytes,
    Null,
    Timestamp,
    Duration,
    List,
    Map,
    Unknown,
}

impl StaticType {
    const fn name(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::String => "string",
            Self::Int => "int",
            Self::Uint => "uint",
            Self::Double => "double",
            Self::Bytes => "bytes",
            Self::Null => "null_type",
            Self::Timestamp => "google.protobuf.Timestamp",
            Self::Duration => "google.protobuf.Duration",
            Self::List => "list",
            Self::Map => "map",
            Self::Unknown => "dyn",
        }
    }

    const fn of(kind: Kind) -> Self {
        match kind {
            Kind::String => Self::String,
            Kind::Bool => Self::Bool,
            Kind::Int => Self::Int,
            Kind::Timestamp => Self::Timestamp,
            Kind::Map => Self::Map,
        }
    }

    const fn is_number(self) -> bool {
        matches!(self, Self::Int | Self::Uint | Self::Double)
    }
}

/// Resolves identifiers against the declared variables and infers the result type.
struct Checker<'a> {
    text: &'a str,
    program: &'a Program,
    variables: &'a [Variable],
    references: Vec<Variable>,
    /// Comprehension variables in scope, innermost last.
    scope: Vec<(&'a str, StaticType)>,
}

impl<'a> Checker<'a> {
    fn check(&mut self, expression: &'a IdedExpr) -> Result<StaticType> {
        Ok(match &expression.expr {
            Expr::Unspecified => StaticType::Unknown,
            Expr::Literal(literal) => match literal {
                LiteralValue::Boolean(_) => StaticType::Bool,
                LiteralValue::Bytes(_) => StaticType::Bytes,
                LiteralValue::Double(_) => StaticType::Double,
                LiteralValue::Int(_) => StaticType::Int,
                LiteralValue::Null => StaticType::Null,
                LiteralValue::String(_) => StaticType::String,
                LiteralValue::UInt(_) => StaticType::Uint,
            },
            Expr::Ident(name) => self.identifier(expression.id, name)?,
            Expr::Select(select) => {
                self.check(&select.operand)?;
                if select.test {
                    StaticType::Bool
                } else {
                    StaticType::Unknown
                }
            }
            Expr::List(list) => {
                for element in &list.elements {
                    self.check(element)?;
                }
                StaticType::List
            }
            Expr::Map(map) => {
                for entry in &map.entries {
                    self.entry(&entry.expr)?;
                }
                StaticType::Map
            }
            Expr::Struct(structure) => {
                for entry in &structure.entries {
                    self.entry(&entry.expr)?;
                }
                StaticType::Unknown
            }
            Expr::Comprehension(comprehension) => {
                self.check(&comprehension.iter_range)?;
                let accumulator = self.check(&comprehension.accu_init)?;
                let depth = self.scope.len();
                self.scope
                    .push((comprehension.iter_var.as_str(), StaticType::Unknown));
                if let Some(second) = &comprehension.iter_var2 {
                    self.scope.push((second.as_str(), StaticType::Unknown));
                }
                self.scope
                    .push((comprehension.accu_var.as_str(), accumulator));
                self.check(&comprehension.loop_cond)?;
                self.check(&comprehension.loop_step)?;
                let result = self.check(&comprehension.result)?;
                self.scope.truncate(depth);
                result
            }
            Expr::Call(call) => {
                if !is_declared_function(&call.func_name) {
                    bail!("{}", self.undeclared(expression.id, &call.func_name));
                }
                if let Some(target) = &call.target {
                    self.check(target)?;
                }
                let mut arguments = Vec::with_capacity(call.args.len());
                for argument in &call.args {
                    arguments.push(self.check(argument)?);
                }
                call_type(&call.func_name, &arguments)
            }
        })
    }

    fn entry(&mut self, entry: &'a cel::common::ast::EntryExpr) -> Result<()> {
        match entry {
            cel::common::ast::EntryExpr::StructField(field) => {
                self.check(&field.value)?;
            }
            cel::common::ast::EntryExpr::MapEntry(map_entry) => {
                self.check(&map_entry.key)?;
                self.check(&map_entry.value)?;
            }
        }
        Ok(())
    }

    fn identifier(&mut self, id: u64, name: &str) -> Result<StaticType> {
        if let Some((_, bound)) = self.scope.iter().rev().find(|(bound, _)| *bound == name) {
            return Ok(*bound);
        }
        if let Some(variable) = self.variables.iter().find(|variable| variable.name == name) {
            if !self.references.contains(variable) {
                self.references.push(*variable);
            }
            return Ok(StaticType::of(variable.kind));
        }
        if matches!(
            name,
            "bool"
                | "bytes"
                | "double"
                | "duration"
                | "dyn"
                | "int"
                | "list"
                | "map"
                | "null_type"
                | "string"
                | "timestamp"
                | "type"
                | "uint"
        ) {
            return Ok(StaticType::Unknown);
        }
        bail!("{}", self.undeclared(id, name))
    }

    fn undeclared(&self, id: u64, name: &str) -> String {
        let start = self
            .program
            .source_info()
            .offset_for(id)
            .map_or(0, |(start, _)| usize::try_from(start).unwrap_or(0));
        let before = self.text.get(..start).unwrap_or_default();
        let line = before.matches('\n').count() + 1;
        let line_start = before.rfind('\n').map_or(0, |position| position + 1);
        let column = before[line_start..].chars().count() + 1;
        let source_line = self.text[line_start..].lines().next().unwrap_or_default();
        format!(
            "ERROR: <input>:{line}:{column}: undeclared reference to '{name}' (in container '')\n| {source_line}\n| {:.>column$}",
            "^"
        )
    }
}

/// Operators and the functions of cel-go's standard environment, the one go-passbolt-cli
/// builds: no extension (`math.*`, `lowerAscii`, `format`...), which cel-go rejects.
fn is_declared_function(function: &str) -> bool {
    function.starts_with('_')
        || function.starts_with('@')
        || matches!(
            function,
            operators::LOGICAL_NOT
                | operators::NEGATE
                | "size"
                | "contains"
                | "startsWith"
                | "endsWith"
                | "matches"
                | "bool"
                | "bytes"
                | "double"
                | "duration"
                | "dyn"
                | "int"
                | "string"
                | "timestamp"
                | "type"
                | "uint"
                | "getFullYear"
                | "getMonth"
                | "getDate"
                | "getDayOfMonth"
                | "getDayOfWeek"
                | "getDayOfYear"
                | "getHours"
                | "getMinutes"
                | "getSeconds"
                | "getMilliseconds"
        )
}

fn call_type(function: &str, arguments: &[StaticType]) -> StaticType {
    use StaticType as Type;
    match function {
        operators::LOGICAL_AND
        | operators::LOGICAL_OR
        | operators::LOGICAL_NOT
        | operators::NOT_STRICTLY_FALSE
        | operators::EQUALS
        | operators::NOT_EQUALS
        | operators::LESS
        | operators::LESS_EQUALS
        | operators::GREATER
        | operators::GREATER_EQUALS
        | operators::IN
        | "contains"
        | "startsWith"
        | "endsWith"
        | "matches"
        | "bool" => Type::Bool,
        "size" | "int" | "getFullYear" | "getMonth" | "getDate" | "getDayOfMonth"
        | "getDayOfWeek" | "getDayOfYear" | "getHours" | "getMinutes" | "getSeconds"
        | "getMilliseconds" => Type::Int,
        "string" => Type::String,
        "uint" => Type::Uint,
        "double" => Type::Double,
        "bytes" => Type::Bytes,
        "timestamp" => Type::Timestamp,
        "duration" => Type::Duration,
        operators::CONDITIONAL => match arguments {
            [_, when_true, when_false] if when_true == when_false => *when_true,
            _ => Type::Unknown,
        },
        operators::NEGATE => match arguments {
            [operand] if operand.is_number() || *operand == Type::Duration => *operand,
            _ => Type::Unknown,
        },
        operators::ADD => match arguments {
            [left, right] if left == right && *left != Type::Unknown => *left,
            [Type::Timestamp, Type::Duration] | [Type::Duration, Type::Timestamp] => {
                Type::Timestamp
            }
            _ => Type::Unknown,
        },
        operators::SUBSTRACT => match arguments {
            [Type::Timestamp, Type::Timestamp] => Type::Duration,
            [Type::Timestamp, Type::Duration] => Type::Timestamp,
            [left, right] if left == right && (left.is_number() || *left == Type::Duration) => {
                *left
            }
            _ => Type::Unknown,
        },
        operators::MULTIPLY | operators::DIVIDE | operators::MODULO => match arguments {
            [left, right] if left == right && left.is_number() => *left,
            _ => Type::Unknown,
        },
        _ => Type::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    fn timestamp(text: &str) -> CelValue {
        CelValue::Timestamp(DateTime::parse_from_rfc3339(text).unwrap().to_utc())
    }

    fn object(value: serde_json::Value) -> CelValue {
        let serde_json::Value::Object(object) = value else {
            panic!("not an object: {value}");
        };
        CelValue::Map(object)
    }

    fn text(value: &str) -> CelValue {
        CelValue::String(value.to_owned())
    }

    fn resource_row() -> HashMap<&'static str, CelValue> {
        HashMap::from([
            ("id", text("8e3874ae-4b40-590b-968a-418f704b9d9a")),
            ("folder_parent_id", text("")),
            ("name", text("GitLab Production")),
            ("username", text("admin@example.com")),
            ("uri", text("https://gitlab.example.com")),
            ("password", text("s3cr3t-P4ss")),
            ("description", text("CI deploy account")),
            ("created_timestamp", timestamp("2024-03-15T10:30:00Z")),
            ("modified_timestamp", timestamp("2025-01-02T08:00:00Z")),
            (
                "metadata",
                object(json!({
                    "name": "GitLab Production",
                    "username": "admin@example.com",
                    "uris": ["https://gitlab.example.com", "https://gitlab.example.org"],
                    "icon": {"type": "keepass-icon-set", "value": 42},
                })),
            ),
            (
                "secret",
                object(json!({"password": "s3cr3t-P4ss", "totp": {"digits": 6}})),
            ),
            ("deleted", CelValue::Bool(false)),
            ("expired", CelValue::Bool(false)),
            ("expired_at", CelValue::Timestamp(zero_timestamp())),
            (
                "resource_type_id",
                text("a28a04cd-6f53-518a-967c-9963bf9cec51"),
            ),
        ])
    }

    fn folder_row() -> HashMap<&'static str, CelValue> {
        HashMap::from([
            ("id", text("f1")),
            ("folder_parent_id", text("root")),
            ("name", text("Infrastructure")),
            ("created_timestamp", timestamp("2023-06-01T00:00:00Z")),
            ("modified_timestamp", timestamp("2024-06-01T00:00:00Z")),
            ("personal", CelValue::Bool(true)),
        ])
    }

    fn user_row() -> HashMap<&'static str, CelValue> {
        HashMap::from([
            ("id", text("u1")),
            ("username", text("ada@passbolt.com")),
            ("first_name", text("Ada")),
            ("last_name", text("Lovelace")),
            ("role", text("admin")),
            ("created_timestamp", timestamp("2022-12-31T23:59:59Z")),
            ("modified_timestamp", timestamp("2024-02-29T12:00:00Z")),
            ("active", CelValue::Bool(true)),
            ("deleted", CelValue::Bool(false)),
            ("disabled", CelValue::Bool(false)),
        ])
    }

    fn group_row() -> HashMap<&'static str, CelValue> {
        HashMap::from([
            ("id", text("g1")),
            ("name", text("Developers")),
            ("created_timestamp", timestamp("2021-01-01T00:00:00Z")),
            ("modified_timestamp", timestamp("2024-07-14T00:00:00Z")),
            ("deleted", CelValue::Bool(false)),
            ("user_count", CelValue::Int(5)),
        ])
    }

    fn evaluate(
        expression: &str,
        variables: &[Variable],
        row: &HashMap<&'static str, CelValue>,
    ) -> bool {
        Expression::compile(expression, variables)
            .unwrap()
            .matches(row)
            .unwrap()
    }

    #[rstest]
    #[case::equality(r#"name == "GitLab Production""#, true)]
    #[case::inequality(r#"name != "GitLab Production""#, false)]
    #[case::and(
        r#"name == "GitLab Production" && username == "admin@example.com""#,
        true
    )]
    #[case::or(r#"name == "nope" || uri.startsWith("https://gitlab")"#, true)]
    #[case::not(r#"!(name.contains("GitLab"))"#, false)]
    #[case::contains(r#"name.contains("Prod")"#, true)]
    #[case::starts_with(r#"username.startsWith("admin@")"#, true)]
    #[case::ends_with(r#"username.endsWith("@example.com")"#, true)]
    #[case::matches(r#"name.matches("^Git[Ll]ab")"#, true)]
    #[case::matches_global(r#"matches(uri, "example\\.org$")"#, false)]
    #[case::case_sensitive(r#"name == "gitlab production""#, false)]
    #[case::in_list(r#"name in ["GitLab Production", "GitHub"]"#, true)]
    #[case::size("size(password) >= 8", true)]
    #[case::ternary(r#"deleted ? false : name != """#, true)]
    #[case::empty_folder(r#"folder_parent_id == """#, true)]
    #[case::created_after(r#"created_timestamp > timestamp("2024-01-01T00:00:00Z")"#, true)]
    #[case::created_before(r#"created_timestamp < timestamp("2024-01-01T00:00:00Z")"#, false)]
    #[case::modified_equal(r#"modified_timestamp == timestamp("2025-01-02T08:00:00Z")"#, true)]
    #[case::timestamp_arithmetic(
        r#"modified_timestamp - created_timestamp > duration("7000h")"#,
        true
    )]
    #[case::timestamp_plus_duration(
        r#"created_timestamp + duration("24h") < timestamp("2024-03-17T00:00:00Z")"#,
        true
    )]
    #[case::full_year("created_timestamp.getFullYear() == 2024", true)]
    #[case::month_zero_based("created_timestamp.getMonth() == 2", true)]
    #[case::hours_in_zone(r#"created_timestamp.getHours("Europe/Paris") == 11"#, true)]
    #[case::timestamp_to_string(r#"string(created_timestamp) == "2024-03-15T10:30:00Z""#, true)]
    #[case::never_expired(r#"!expired && expired_at == timestamp("0001-01-01T00:00:00Z")"#, true)]
    #[case::deleted_false("deleted == false", true)]
    #[case::bool_alone("deleted", false)]
    #[case::metadata_dot(r#"metadata.name == "GitLab Production""#, true)]
    #[case::metadata_index(r#"metadata["username"] == "admin@example.com""#, true)]
    #[case::metadata_has("has(metadata.uris) && !has(metadata.custom_fields)", true)]
    #[case::metadata_in(r#""icon" in metadata"#, true)]
    #[case::metadata_number("metadata.icon.value == 42", true)]
    #[case::metadata_list_exists(r#"metadata.uris.exists(uri, uri.endsWith(".org"))"#, true)]
    #[case::metadata_list_all(r#"metadata.uris.all(uri, uri.startsWith("https://"))"#, true)]
    #[case::metadata_list_exists_one(
        r#"metadata.uris.exists_one(uri, uri.contains("gitlab"))"#,
        false
    )]
    #[case::metadata_list_filter(
        r#"size(metadata.uris.filter(uri, uri.endsWith(".com"))) == 1"#,
        true
    )]
    #[case::metadata_list_map(
        r#""https://gitlab.example.com/" in metadata.uris.map(uri, uri + "/")"#,
        true
    )]
    #[case::secret_index(r#"secret["password"] == password"#, true)]
    #[case::secret_nested("secret.totp.digits == 6", true)]
    #[case::type_id(r#"resource_type_id == "a28a04cd-6f53-518a-967c-9963bf9cec51""#, true)]
    fn test_resource_expressions(#[case] expression: &str, #[case] expected: bool) {
        assert_eq!(
            evaluate(expression, RESOURCE_VARIABLES, &resource_row()),
            expected,
            "{expression}"
        );
    }

    #[rstest]
    #[case::equality(r#"name == "Infrastructure""#, true)]
    #[case::personal("personal == true", true)]
    #[case::parent(r#"folder_parent_id == "root" && !personal"#, false)]
    #[case::created(r#"created_timestamp >= timestamp("2023-06-01T00:00:00Z")"#, true)]
    #[case::modified("modified_timestamp.getFullYear() < 2024", false)]
    #[case::pascal_case(r#"Personal && Name.startsWith("Infra")"#, true)]
    fn test_folder_expressions(#[case] expression: &str, #[case] expected: bool) {
        assert_eq!(
            evaluate(expression, FOLDER_VARIABLES, &folder_row()),
            expected,
            "{expression}"
        );
    }

    #[rstest]
    #[case::role(r#"role == "admin""#, true)]
    #[case::domain(r#"username.endsWith("@passbolt.com") && active"#, true)]
    #[case::names(r#"first_name == "Ada" && last_name.startsWith("Love")"#, true)]
    #[case::disabled("disabled || deleted", false)]
    #[case::created(r#"created_timestamp < timestamp("2023-01-01T00:00:00Z")"#, true)]
    #[case::active_users("active == true && deleted == false", true)]
    #[case::concat_alias(r#"firstname + " " + lastname == "Ada Lovelace""#, true)]
    fn test_user_expressions(#[case] expression: &str, #[case] expected: bool) {
        assert_eq!(
            evaluate(expression, USER_VARIABLES, &user_row()),
            expected,
            "{expression}"
        );
    }

    #[rstest]
    #[case::user_count("user_count > 2", true)]
    #[case::user_count_equal("user_count == 5", true)]
    #[case::user_count_arithmetic("user_count % 2 == 1 && user_count * 2 == 10", true)]
    #[case::user_count_double("double(user_count) / 2.0 == 2.5", true)]
    #[case::name(r#"name.matches("(?i)^dev")"#, true)]
    #[case::not_deleted("!deleted && user_count < 3", false)]
    #[case::modified(r#"modified_timestamp > timestamp("2024-07-13T23:59:59Z")"#, true)]
    fn test_group_expressions(#[case] expression: &str, #[case] expected: bool) {
        assert_eq!(
            evaluate(expression, GROUP_VARIABLES, &group_row()),
            expected,
            "{expression}"
        );
    }

    #[rstest]
    #[case::int_to_string(r#"string(user_count) == "5""#)]
    #[case::string_to_int(r#"int("5") == user_count"#)]
    #[case::uint("uint(user_count) == 5u")]
    #[case::heterogeneous_equality("user_count == 5.0 && user_count == 5u")]
    #[case::type_of("type(user_count) == int && type(name) == string")]
    #[case::dyn_value("dyn(user_count) == 5")]
    #[case::bytes_value(r#"bytes(name) == b"Developers""#)]
    #[case::epoch_seconds("int(created_timestamp) == 1609459200")]
    #[case::timestamp_from_seconds("timestamp(1609459200) == created_timestamp")]
    #[case::day_of_week("modified_timestamp.getDayOfWeek() == 0")]
    #[case::day_of_month_zero_based("modified_timestamp.getDayOfMonth() == 13")]
    #[case::date_one_based("modified_timestamp.getDate() == 14")]
    #[case::fixed_offset(r#"created_timestamp.getHours("+02:00") == 2"#)]
    #[case::duration_accessor("(modified_timestamp - created_timestamp).getHours() > 24")]
    #[case::string_comparison(r#"name > "Admins" && name < "Ops""#)]
    #[case::two_variable_map("[1, 2].map(number, number > 1, number * 2) == [4]")]
    #[case::raw_string(r#"name.matches(r"^D\w+s$")"#)]
    fn test_standard_library(#[case] expression: &str) {
        assert!(
            evaluate(expression, GROUP_VARIABLES, &group_row()),
            "{expression}"
        );
    }

    #[rstest]
    #[case::canonical("created_timestamp")]
    #[case::pascal_case("CreatedTimestamp")]
    #[case::lower_concat("createdtimestamp")]
    fn test_every_alias_reads_its_column(#[case] name: &str) {
        let expression = Expression::compile(
            &format!(r#"{name} > timestamp("2024-01-01T00:00:00Z")"#),
            RESOURCE_VARIABLES,
        )
        .unwrap();

        assert_eq!(expression.columns(), ["created_timestamp"]);
        assert!(expression.matches(&resource_row()).unwrap());
    }

    #[rstest]
    #[case::resource(RESOURCE_VARIABLES)]
    #[case::folder(FOLDER_VARIABLES)]
    #[case::user(USER_VARIABLES)]
    #[case::group(GROUP_VARIABLES)]
    fn test_each_variable_compiles_with_its_type(#[case] variables: &[Variable]) {
        for variable in variables {
            let expression = match variable.kind {
                Kind::String => format!(r#"{} != "\u0000""#, variable.name),
                Kind::Bool => format!("{} || true", variable.name),
                Kind::Int => format!("{} >= 0", variable.name),
                Kind::Timestamp => {
                    format!(r#"{} >= timestamp("0001-01-01T00:00:00Z")"#, variable.name)
                }
                Kind::Map => format!("size({}) >= 0", variable.name),
            };

            let compiled = Expression::compile(&expression, variables).unwrap();

            assert_eq!(compiled.columns(), [variable.column], "{expression}");
        }
    }

    #[rstest]
    #[case::canonical("name")]
    #[case::pascal_case("Name")]
    fn test_name_spellings(#[case] name: &str) {
        assert!(evaluate(
            &format!(r#"{name} == "Developers""#),
            GROUP_VARIABLES,
            &group_row()
        ));
    }

    #[rstest]
    #[case::other_entity_column("user_count > 2", RESOURCE_VARIABLES, "user_count")]
    #[case::wrong_case("NAME == \"x\"", RESOURCE_VARIABLES, "NAME")]
    #[case::undeclared_concat("foldername == \"x\"", FOLDER_VARIABLES, "foldername")]
    #[case::bare_word("name == x", GROUP_VARIABLES, "x")]
    #[case::extension_function(r#"name.lowerAscii() == "x""#, GROUP_VARIABLES, "lowerAscii")]
    #[case::unknown_function(r#"lower(name) == "x""#, GROUP_VARIABLES, "lower")]
    fn test_an_unknown_variable_does_not_compile(
        #[case] expression: &str,
        #[case] variables: &[Variable],
        #[case] name: &str,
    ) {
        let error = Expression::compile(expression, variables)
            .err()
            .unwrap()
            .to_string();

        assert!(
            error.contains(&format!("undeclared reference to '{name}'")),
            "{error}"
        );
    }

    #[test]
    fn test_an_unknown_variable_error_points_at_it() {
        let error = Expression::compile("name == \"a\" && nope", GROUP_VARIABLES)
            .err()
            .unwrap()
            .to_string();

        assert_eq!(
            error,
            "ERROR: <input>:1:16: undeclared reference to 'nope' (in container '')\n| name == \"a\" && nope\n| ...............^"
        );
    }

    #[test]
    fn test_comprehension_variables_are_not_columns() {
        let expression = Expression::compile(
            r#"metadata.uris.exists(name, name == "x")"#,
            RESOURCE_VARIABLES,
        )
        .unwrap();

        assert_eq!(expression.columns(), ["metadata"]);
    }

    #[rstest]
    #[case::string("name", "string")]
    #[case::int("user_count", "int")]
    #[case::arithmetic("user_count + 1", "int")]
    #[case::timestamp("created_timestamp", "google.protobuf.Timestamp")]
    #[case::literal(r#""yes""#, "string")]
    #[case::size("size(name)", "int")]
    #[case::list("[deleted]", "list")]
    fn test_a_non_bool_expression_does_not_compile(
        #[case] expression: &str,
        #[case] type_name: &str,
    ) {
        let error = Expression::compile(expression, GROUP_VARIABLES)
            .err()
            .unwrap()
            .to_string();

        assert!(
            error.ends_with(&format!("must be a bool expression, not {type_name}")),
            "{error}"
        );
    }

    #[test]
    fn test_a_dynamic_non_bool_result_does_not_match() {
        let expression = Expression::compile("metadata.name", RESOURCE_VARIABLES).unwrap();

        assert!(!expression.matches(&resource_row()).unwrap());
    }

    #[rstest]
    #[case::missing_map_key(r#"metadata.custom == "x""#)]
    #[case::no_such_overload("name > 2")]
    fn test_an_evaluation_error_is_an_error(#[case] expression: &str) {
        let expression = Expression::compile(expression, RESOURCE_VARIABLES).unwrap();

        assert!(expression.matches(&resource_row()).is_err());
    }

    #[test]
    fn test_a_syntax_error_does_not_compile() {
        assert!(Expression::compile("name ==", RESOURCE_VARIABLES).is_err());
    }

    #[rstest]
    #[case::reads_password("password != \"\"", true)]
    #[case::reads_secret_alias("has(Secret.totp)", true)]
    #[case::reads_description("Description.contains(\"x\")", true)]
    #[case::reads_metadata_only("metadata.name == name", false)]
    fn test_secret_columns(#[case] expression: &str, #[case] reads_secret: bool) {
        let expression = Expression::compile(expression, RESOURCE_VARIABLES).unwrap();

        assert_eq!(expression.reads_any(RESOURCE_SECRET_COLUMNS), reads_secret);
    }

    #[test]
    fn test_columns_are_canonical_and_unique() {
        let expression = Expression::compile(
            r#"Name == "a" || name == "b" || ID == "c" || id == "d""#,
            RESOURCE_VARIABLES,
        )
        .unwrap();

        assert_eq!(expression.columns(), ["name", "id"]);
    }

    #[test]
    fn test_a_row_without_a_read_column_is_an_error() {
        let expression = Expression::compile("user_count > 2", GROUP_VARIABLES).unwrap();

        let error = expression.matches(&HashMap::new()).unwrap_err();

        assert_eq!(
            error.to_string(),
            "no value for the filter column user_count"
        );
    }

    #[test]
    fn test_filter_keeps_the_matching_items() {
        let expression = Expression::compile("user_count > 2", GROUP_VARIABLES).unwrap();

        let kept = expression
            .filter(vec![1_i64, 3, 5], "groups", |count| {
                HashMap::from([("user_count", CelValue::Int(*count))])
            })
            .unwrap();

        assert_eq!(kept, [3, 5]);
    }

    #[test]
    fn test_filter_matching_nothing_is_an_error() {
        let expression = Expression::compile("user_count > 9", GROUP_VARIABLES).unwrap();

        let error = expression
            .filter(vec![1_i64], "groups", |count| {
                HashMap::from([("user_count", CelValue::Int(*count))])
            })
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "no such groups found with filter user_count > 9"
        );
    }

    #[rstest]
    #[case::equal("name=GitLab", false)]
    #[case::contains("name~=Lab", false)]
    #[case::starts_with("uri^=https://", false)]
    #[case::ends_with("username$=@example.com", false)]
    #[case::not_equal_bare_word("name!=GitLab", false)]
    #[case::not_equal_bare_words_with_spaces("name != GitLab", false)]
    #[case::cel_not_equal(r#"name != "GitLab""#, true)]
    #[case::cel_equal(r#"name == "GitLab""#, true)]
    #[case::cel_bool("deleted != true", true)]
    fn test_cel_or_legacy(#[case] text: &str, #[case] is_cel: bool) {
        let parsed = FilterExpression::parse(text, RESOURCE_VARIABLES).unwrap();

        assert_eq!(matches!(parsed, FilterExpression::Cel(_)), is_cel, "{text}");
    }

    #[rstest]
    #[case::neither("nope")]
    #[case::unknown_cel_variable(r#"nope == "x""#)]
    #[case::syntax_error_with_an_equal(r#"name == "x" && "#)]
    #[case::comparison("nope > 2")]
    fn test_neither_cel_nor_legacy_reports_the_cel_error(#[case] text: &str) {
        let error = FilterExpression::parse(text, RESOURCE_VARIABLES)
            .err()
            .unwrap()
            .to_string();

        assert!(error.starts_with("ERROR: <input>:1:"), "{error}");
    }
}
