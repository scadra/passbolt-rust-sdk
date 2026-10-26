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

use serde::Serialize;
use unicode_width::UnicodeWidthStr;

/// Print a table as go-passbolt-cli prints it (pterm without styles): every cell padded to its
/// column, ` | ` between cells, the headers as the first row, then an empty line.
///
/// Cells are stripped of control characters to prevent terminal injection; a line break
/// continues the cell on the next line, in its column.
pub fn print_table(headers: &[&str], rows: Vec<Vec<String>>) {
    print!("{}", render_table(headers, rows));
}

fn render_table(headers: &[&str], rows: Vec<Vec<String>>) -> String {
    let table: Vec<Vec<Vec<String>>> =
        std::iter::once(headers.iter().map(|header| (*header).to_string()).collect())
            .chain(rows)
            .map(|row: Vec<String>| {
                row.iter()
                    .map(|cell| cell.split('\n').map(strip_control_chars).collect())
                    .collect()
            })
            .collect();
    let mut widths: Vec<usize> = Vec::new();
    for row in &table {
        for (index, cell) in row.iter().enumerate() {
            let width = cell.iter().map(|line| line.width()).max().unwrap_or(0);
            match widths.get_mut(index) {
                Some(known) => *known = (*known).max(width),
                None => widths.push(width),
            }
        }
    }
    let mut rendered = String::new();
    for row in &table {
        let height = row.iter().map(Vec::len).max().unwrap_or(0);
        for line_index in 0..height {
            for (index, cell) in row.iter().enumerate() {
                let line = cell.get(line_index).map_or("", String::as_str);
                rendered.push_str(line);
                rendered.push_str(&" ".repeat(widths[index] - line.width()));
                if index + 1 < row.len() {
                    rendered.push_str(" | ");
                }
            }
            rendered.push('\n');
        }
    }
    rendered.push('\n');
    rendered
}

/// Remove ASCII control characters (0x00–0x1F and 0x7F) from a string.
/// Prevents terminal escape injection from resource names/values.
fn strip_control_chars(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .collect()
}

/// Print any serializable value as JSON indented by two spaces.
pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}

/// Report a write with `--json`: `{"id": …, "result": "deleted"}`. Without it nothing is
/// printed, as go-passbolt-cli prints nothing.
pub fn print_done(json: bool, result: &str, id: &str) -> anyhow::Result<()> {
    if json {
        return print_json(&serde_json::json!({ "id": id, "result": result }));
    }
    Ok(())
}

/// Print `Key: value` lines, stripped of control characters like table cells.
pub fn print_kv(pairs: &[(&str, &str)]) {
    for (key, value) in pairs {
        println!("{}", format_kv(key, value));
    }
}

fn format_kv(key: &str, value: &str) -> String {
    format!(
        "{}: {}",
        strip_control_chars(key),
        strip_control_chars(value)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_control_chars_removes_escape() {
        // \x1b (ESC, 0x1B) is a control char and is removed;
        // the printable chars that follow it ("[31m") are kept as-is.
        assert_eq!(strip_control_chars("\x1b[31mred\x1b[0m"), "[31mred[0m");
    }

    #[test]
    fn test_strip_control_chars_removes_null_and_tab() {
        assert_eq!(strip_control_chars("a\x00b\tc"), "abc");
    }

    #[test]
    fn test_strip_control_chars_passthrough_normal() {
        assert_eq!(strip_control_chars("hello world"), "hello world");
    }

    #[test]
    fn test_a_table_pads_every_cell_and_separates_them() {
        let table = render_table(
            &["id", "name"],
            vec![
                vec!["1".into(), "GitHub".into()],
                vec!["22".into(), "é".into()],
            ],
        );

        assert_eq!(table, "id | name  \n1  | GitHub\n22 | é     \n\n");
    }

    #[test]
    fn test_a_line_break_continues_the_cell_in_its_column() {
        let table = render_table(&["a", "b"], vec![vec!["x\ny".into(), "z".into()]]);

        assert_eq!(table, "a | b\nx | z\ny |  \n\n");
    }

    #[test]
    fn test_a_table_cell_loses_its_control_characters() {
        let table = render_table(&["name"], vec![vec!["\x1b[31mred".into()]]);

        assert_eq!(table, "name   \n[31mred\n\n");
    }

    #[test]
    fn test_format_kv_strips_control_characters_from_the_value() {
        assert_eq!(format_kv("Name", "\x1b[31mred\x07"), "Name: [31mred");
    }

    #[test]
    fn test_format_kv_strips_control_characters_from_the_key() {
        assert_eq!(
            format_kv("Na\x1b]0;title\x07me", "value"),
            "Na]0;titleme: value"
        );
    }
}
