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

//! CSV files read and written as the browser extension does with `PapaParse`: the delimiter
//! guessed from the first rows, the first row as column names, every cell quoted on write.

use std::collections::HashMap;

/// The delimiters tried, in `PapaParse`'s order.
const DELIMITERS: [char; 6] = [',', '\t', '|', ';', '\u{1e}', '\u{1f}'];

/// One data row, by column name; a column the row lacks is absent.
pub type Row = HashMap<String, String>;

/// A CSV file read with its first row as column names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Row>,
}

/// Read `text`: a leading byte order mark is skipped, empty lines too, and a column name used
/// twice becomes `name_1`, `name_2`…
#[must_use]
pub fn read(text: &str) -> Table {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let delimiter = guess_delimiter(text);
    let mut records = records(text, delimiter, None)
        .into_iter()
        .filter(|record| !is_empty_line(record));
    let Some(header) = records.next() else {
        return Table::default();
    };
    let columns = unique_columns(header);
    let rows = records
        .map(|record| columns.iter().cloned().zip(record).collect::<Row>())
        .collect();
    Table { columns, rows }
}

/// A line holding one empty cell.
const fn is_empty_line(record: &[String]) -> bool {
    matches!(record, [cell] if cell.is_empty())
}

fn unique_columns(header: Vec<String>) -> Vec<String> {
    let mut used: std::collections::HashSet<String> = header.iter().cloned().collect();
    let mut counts: HashMap<String, usize> = HashMap::new();
    header
        .into_iter()
        .map(|column| {
            let count = counts.entry(column.clone()).or_insert(0);
            *count += 1;
            if *count == 1 {
                return column;
            }
            let mut suffix = *count - 1;
            let renamed = loop {
                let candidate = format!("{column}_{suffix}");
                suffix += 1;
                if !used.contains(&candidate) {
                    break candidate;
                }
            };
            used.insert(renamed.clone());
            renamed
        })
        .collect()
}

/// `PapaParse`'s guess: over the first ten records, the delimiter giving at least two
/// columns on average, with the steadiest column count, then the most columns; `,` else.
fn guess_delimiter(text: &str) -> char {
    let mut best: Option<(char, usize, f64)> = None;
    for delimiter in DELIMITERS {
        let preview = records(text, delimiter, Some(10));
        let mut delta = 0;
        let mut previous: Option<usize> = None;
        let mut total = 0;
        let mut empty_lines = 0;
        for record in &preview {
            if is_empty_line(record) {
                empty_lines += 1;
                continue;
            }
            total += record.len();
            match previous {
                None => previous = Some(record.len()),
                Some(count) if !record.is_empty() => {
                    delta += count.abs_diff(record.len());
                    previous = Some(record.len());
                }
                Some(_) => {}
            }
        }
        let lines = preview.len().saturating_sub(empty_lines);
        #[allow(clippy::cast_precision_loss)] // A preview holds ten records.
        let average = if lines == 0 {
            total as f64
        } else {
            total as f64 / lines as f64
        };
        let better = best.is_none_or(|(_, best_delta, best_average)| {
            delta <= best_delta && average > best_average
        });
        if better && average > 1.99 {
            best = Some((delimiter, delta, average));
        }
    }
    best.map_or(',', |(delimiter, _, _)| delimiter)
}

/// The records of `text`: `"` quotes a cell, `""` inside quotes is one `"`, and `\r\n`, `\n`
/// or `\r` ends a record; at most `limit` records.
fn records(text: &str, delimiter: char, limit: Option<usize>) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut cell = String::new();
    let mut characters = text.chars().peekable();
    let mut quoted = false;
    let mut at_cell_start = true;
    while let Some(character) = characters.next() {
        if limit.is_some_and(|limit| records.len() >= limit) {
            return records;
        }
        if quoted {
            if character == '"' {
                if characters.peek() == Some(&'"') {
                    characters.next();
                    cell.push('"');
                } else {
                    quoted = false;
                }
            } else {
                cell.push(character);
            }
            continue;
        }
        match character {
            '"' if at_cell_start => {
                quoted = true;
                at_cell_start = false;
            }
            '\r' | '\n' => {
                if character == '\r' && characters.peek() == Some(&'\n') {
                    characters.next();
                }
                record.push(std::mem::take(&mut cell));
                records.push(std::mem::take(&mut record));
                at_cell_start = true;
            }
            _ if character == delimiter => {
                record.push(std::mem::take(&mut cell));
                at_cell_start = true;
            }
            _ => {
                cell.push(character);
                at_cell_start = false;
            }
        }
    }
    if !cell.is_empty() || !record.is_empty() || !at_cell_start {
        record.push(cell);
        records.push(record);
    }
    if let Some(limit) = limit {
        records.truncate(limit);
    }
    records
}

/// A CSV file with these `columns` and `rows`: every cell quoted, `"` doubled, `\r\n`
/// between lines, none after the last one.
#[must_use]
pub fn write(columns: &[&str], rows: &[Vec<String>], delimiter: char) -> String {
    let separator = format!("\"{delimiter}\"");
    let mut file = format!("\"{}\"\r\n", columns.join(&separator));
    let lines: Vec<String> = rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|cell| format!("\"{}\"", cell.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(&delimiter.to_string())
        })
        .collect();
    file.push_str(&lines.join("\r\n"));
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_file_is_read_with_its_first_row_as_columns() {
        let table = read("\u{feff}Title,Password\r\n\"Git\"\"hub\",\"a,b\nc\"\r\n\r\nAWS,x\r\n");

        assert_eq!(table.columns, ["Title", "Password"]);
        assert_eq!(table.rows.len(), 2);
        assert_eq!(table.rows[0]["Title"], "Git\"hub");
        assert_eq!(table.rows[0]["Password"], "a,b\nc");
        assert_eq!(table.rows[1]["Title"], "AWS");
    }

    #[rstest::rstest]
    #[case("a;b;c\n1;2;3\n", ';')]
    #[case("a\tb\n1\t2\n", '\t')]
    #[case("a|b\n1|2\n", '|')]
    #[case("a,b;c\n1,2;3\n", ',')]
    #[case("single\nvalue\n", ',')]
    fn test_the_delimiter_is_guessed_as_papaparse_guesses_it(
        #[case] text: &str,
        #[case] delimiter: char,
    ) {
        assert_eq!(guess_delimiter(text), delimiter);
    }

    #[test]
    fn test_a_short_row_lacks_the_missing_columns() {
        let table = read("a,b,c\n1,2\n");

        assert_eq!(table.rows[0].get("c"), None);
        assert_eq!(table.rows[0]["b"], "2");
    }

    #[test]
    fn test_a_column_named_twice_is_renamed() {
        assert_eq!(read("a,a,a_1\n").columns, ["a", "a_2", "a_1"]);
    }

    #[test]
    fn test_every_cell_is_quoted_on_write() {
        let file = write(
            &["Title", "Notes"],
            &[
                vec!["Git\"hub".into(), "line\r\nnext".into()],
                vec!["AWS".into(), String::new()],
            ],
            ',',
        );

        assert_eq!(
            file,
            "\"Title\",\"Notes\"\r\n\"Git\"\"hub\",\"line\r\nnext\"\r\n\"AWS\",\"\""
        );
    }

    #[test]
    fn test_a_written_file_reads_back() {
        let rows = vec![vec!["a,b".to_string(), "\"q\"".to_string()]];

        let table = read(&write(&["x", "y"], &rows, ';'));

        assert_eq!(table.rows[0]["x"], "a,b");
        assert_eq!(table.rows[0]["y"], "\"q\"");
    }
}
