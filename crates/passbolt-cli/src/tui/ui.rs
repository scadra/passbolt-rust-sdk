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

//! What the terminal UI shows, in the manner of openapi-tui: a header with the tabs, panes
//! with plain borders (the focused one thick and green, larger, or alone with `f`), a status
//! line with the command line, and the help, the form or the confirmation as popups.

use chrono::Utc;
use passbolt_sdk::resource::view::ResourceView;
use ratatui::layout::{Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, HighlightSpacing, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::Frame;

use super::app::{App, Mode, Pane, Tab};
use super::form::{Field, Form};

/// The border of the focused pane.
const FOCUSED: Color = Color::LightGreen;

/// The keys, for the help.
pub const KEYS: [(&str, &str); 22] = [
    ("l → Tab", "next pane"),
    ("h ← S-Tab", "previous pane"),
    ("j ↓  k ↑", "move in the list, scroll the metadata"),
    ("PgUp PgDn", "move by ten"),
    (
        "1…5  [ ]",
        "tabs: all, favorites, personal, shared, expired",
    ),
    ("f", "the focused pane alone, Esc to come back"),
    (
        "g Enter",
        "in the folders: into the resources of the folder",
    ),
    ("b Backspace", "in the folders: back to the parent folder"),
    ("/", "filter by name, username or URI in every folder"),
    (":", "command line, ↑ ↓ for the last commands"),
    ("c Enter", "copy the password"),
    ("u", "copy the username"),
    ("a", "copy the URI"),
    ("t", "copy the TOTP code"),
    ("o", "open the URI in the browser"),
    ("s", "show / hide the secret"),
    ("n", "new resource in the selected folder"),
    ("e", "edit the resource"),
    ("d", "delete the resource"),
    ("r", "reload from the server"),
    ("?", "this help"),
    ("q", "quit"),
];

/// The commands of the command line, for the help.
pub const COMMANDS: [(&str, &str); 13] = [
    (
        "copy [password|username|uri|totp]",
        "copy a field, the password by default",
    ),
    ("open", "open the URI"),
    ("show", "show / hide the secret"),
    ("new  edit  delete", "create, edit or delete a resource"),
    ("filter <text>", "filter, or without text clear the filter"),
    ("tab <name|number>", "select a tab"),
    (
        "folder <name>",
        "select the first folder whose name starts so",
    ),
    ("fullscreen  f", "the focused pane alone"),
    ("reload  r", "reload from the server"),
    ("help", "this help"),
    ("quit  q", "quit"),
    ("", ""),
    (
        "In a form",
        "Tab next field, Ctrl+G generate, Ctrl+R show, Ctrl+S save, Esc cancel",
    ),
];

pub fn draw(frame: &mut Frame, app: &App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    draw_header(frame, app, header);
    if app.fullscreen {
        draw_pane(frame, app, app.focus, body);
    } else {
        let [left, right] =
            Layout::horizontal([Constraint::Fill(2), Constraint::Fill(3)]).areas(body);
        let height = |pane| {
            if app.focus == pane {
                Constraint::Fill(3)
            } else {
                Constraint::Fill(1)
            }
        };
        let [resources, folders] =
            Layout::vertical([height(Pane::Resources), height(Pane::Folders)]).areas(left);
        let [details, secret, metadata] = Layout::vertical([
            height(Pane::Details),
            height(Pane::Secret),
            height(Pane::Metadata),
        ])
        .areas(right);
        for (pane, area) in [
            (Pane::Resources, resources),
            (Pane::Folders, folders),
            (Pane::Details, details),
            (Pane::Secret, secret),
            (Pane::Metadata, metadata),
        ] {
            draw_pane(frame, app, pane, area);
        }
    }
    draw_footer(frame, app, footer);

    match &app.mode {
        Mode::Help(scroll) => draw_help(frame, *scroll),
        Mode::ConfirmDelete(id) => draw_confirm(frame, &app.name_of(id)),
        Mode::Form(form) => draw_form(frame, form),
        Mode::Normal | Mode::Filter(_) | Mode::Command(_) => {}
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let mut tabs = vec![Span::raw(" ")];
    for (index, tab) in Tab::ALL.iter().enumerate() {
        let label = Span::raw(format!(" {} {} ", index + 1, tab.title()));
        tabs.push(if *tab == app.tab {
            label.fg(FOCUSED).bold().underlined()
        } else {
            label.dark_gray()
        });
    }
    frame.render_widget(Line::from(tabs), area);
    frame.render_widget(
        Line::from(vec![
            Span::raw(format!("[ passbolt {} ", symbols::DOT)).blue(),
            Span::raw(format!("{} ", app.server)).light_cyan(),
            Span::raw("]").blue(),
        ])
        .right_aligned(),
        area,
    );
}

/// A pane: plain borders, thick and green when focused, its title on the left.
fn block(app: &App, pane: Pane) -> Block<'static> {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Line::from(pane.title()));
    if app.focus == pane {
        block
            .border_type(BorderType::Thick)
            .border_style(Style::default().fg(FOCUSED))
    } else {
        block.border_type(BorderType::Plain)
    }
}

fn draw_pane(frame: &mut Frame, app: &App, pane: Pane, area: Rect) {
    match pane {
        Pane::Resources => draw_resources(frame, app, area),
        Pane::Folders => draw_folders(frame, app, area),
        Pane::Details => draw_details(frame, app, area),
        Pane::Secret => draw_secret(frame, app, area),
        Pane::Metadata => draw_metadata(frame, app, area),
    }
}

/// The type of a resource, short and coloured, as openapi-tui shows the methods.
fn badge(view: &ResourceView) -> Span<'static> {
    if view.error.is_some() {
        return Span::raw(" ERR   ").light_red();
    }
    let slug = view.resource_type.as_deref().unwrap_or_default();
    let (label, color) = match slug {
        "v5-default-with-totp" | "password-description-totp" => ("PASS+", Color::LightBlue),
        _ if slug.contains("totp") => ("TOTP", Color::LightMagenta),
        _ if slug.contains("note") => ("NOTE", Color::LightYellow),
        _ if slug.contains("pin") => ("PIN", Color::LightGreen),
        _ if slug.contains("custom") => ("FIELDS", Color::Gray),
        "" => ("?", Color::DarkGray),
        _ => ("PASS", Color::LightCyan),
    };
    Span::styled(format!(" {label:6}"), Style::default().fg(color))
}

fn list<'a>(items: Vec<ListItem<'a>>, block: Block<'a>) -> List<'a> {
    List::new(items)
        .block(block)
        .highlight_symbol(symbols::scrollbar::HORIZONTAL.end)
        .highlight_spacing(HighlightSpacing::Always)
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
}

fn draw_resources(frame: &mut Frame, app: &App, area: Rect) {
    let visible = app.visible();
    let items: Vec<ListItem> = visible
        .iter()
        .map(|view| {
            let mut spans = vec![badge(view), Span::raw(view.name.clone())];
            if !view.username.is_empty() {
                spans.push(Span::raw(format!("  {}", view.username)).dark_gray());
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let scope = if app.filter.is_empty() {
        app.folders[app.folder_index].name.clone()
    } else {
        format!("/{}", app.filter)
    };
    let position = if visible.is_empty() {
        0
    } else {
        app.resource_index + 1
    };
    let block = block(app, Pane::Resources)
        .title(Line::from(format!("[{scope}]")).italic().right_aligned())
        .title_bottom(Line::from(format!("{position} of {}", visible.len())).right_aligned());
    let selected = (!visible.is_empty()).then_some(app.resource_index);
    let mut state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(list(items, block), area, &mut state);
}

fn draw_folders(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .folders
        .iter()
        .map(|row| {
            let count = app
                .resources
                .iter()
                .filter(|view| row.id.is_none() || view.folder_parent_id == row.id)
                .count();
            ListItem::new(Line::from(vec![
                Span::raw(format!("{}{}", "  ".repeat(row.depth), row.name)),
                Span::raw(format!("  {count}")).dark_gray(),
            ]))
        })
        .collect();
    let block = block(app, Pane::Folders).title_bottom(
        Line::from(format!("{} of {}", app.folder_index + 1, app.folders.len())).right_aligned(),
    );
    let mut state = ListState::default().with_selected(Some(app.folder_index));
    frame.render_stateful_widget(list(items, block), area, &mut state);
}

fn field(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("{label:>10}  ")).dark_gray(),
        Span::raw(value.into()),
    ])
}

fn draw_details(frame: &mut Frame, app: &App, area: Rect) {
    let block = block(app, Pane::Details);
    let Some(view) = app.selected() else {
        frame.render_widget(Paragraph::new(" No resource.").block(block), area);
        return;
    };
    let mut lines = vec![
        Line::from(vec![badge(view), Span::raw(view.name.clone()).bold()]),
        field("Username", view.username.clone()),
    ];
    let uris = if view.uris.is_empty() && !view.uri.is_empty() {
        vec![view.uri.clone()]
    } else {
        view.uris.clone()
    };
    for (index, uri) in uris.iter().enumerate() {
        lines.push(field(if index == 0 { "URI" } else { "" }, uri.clone()));
    }
    lines.push(field(
        "Folder",
        app.folder_name(view.folder_parent_id.as_ref()),
    ));
    if let Some(resource_type) = &view.resource_type {
        lines.push(field("Type", resource_type.clone()));
    }
    if let Some(personal) = view.personal {
        lines.push(field(
            "Access",
            if personal { "personal" } else { "shared" },
        ));
    }
    if let Some(expired) = view.expired {
        let date = expired.format("%Y-%m-%d %H:%M").to_string();
        lines.push(if expired <= Utc::now() {
            Line::from(vec![
                Span::raw(format!("{:>10}  ", "Expired")).dark_gray(),
                Span::raw(date).light_red(),
            ])
        } else {
            field("Expires", date)
        });
    }
    if let Some(modified) = view.modified {
        lines.push(field(
            "Modified",
            modified.format("%Y-%m-%d %H:%M").to_string(),
        ));
    }
    if let Some(error) = &view.error {
        lines.push(Line::from(vec![
            Span::raw(format!("{:>10}  ", "Error")).dark_gray(),
            Span::raw(error.clone()).light_red(),
        ]));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_secret(frame: &mut Frame, app: &App, area: Rect) {
    let block = block(app, Pane::Secret)
        .title_bottom(Line::from(" [c copy] [s show] [t TOTP] ").right_aligned());
    let Some(view) = app.selected() else {
        frame.render_widget(Paragraph::new("").block(block), area);
        return;
    };
    let mut lines = Vec::new();
    match &app.revealed {
        Some(revealed) if revealed.id == view.id => {
            lines.push(field("Password", revealed.password.to_string()));
            if let Some(note) = &revealed.note {
                lines.push(field("Note", ""));
                lines.extend(note.lines().map(|line| Line::raw(format!("  {line}"))));
            }
        }
        _ => lines.push(Line::from(vec![
            Span::raw(format!("{:>10}  ", "Password")).dark_gray(),
            Span::raw("••••••••").dark_gray(),
            Span::raw("  s shows it").dark_gray().italic(),
        ])),
    }
    if !view.description.is_empty() {
        lines.push(field("Notes", ""));
        lines.extend(
            view.description
                .lines()
                .map(|line| Line::raw(format!("  {line}"))),
        );
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// A line of pretty JSON, coloured: keys, strings, numbers and literals.
fn json_line(line: &str) -> Line<'static> {
    let indent = line.len() - line.trim_start().len();
    let rest = line.trim_start();
    let mut spans = vec![Span::raw(" ".repeat(indent))];
    let (key, value) = match rest.find("\": ") {
        Some(end) if rest.starts_with('"') => (Some(&rest[..=end]), &rest[end + 2..]),
        _ => (None, rest),
    };
    if let Some(key) = key {
        spans.push(Span::raw(key.to_string()).light_cyan());
        spans.push(Span::raw(":"));
    }
    let trimmed = value.trim_start().trim_end_matches(',');
    let style = if trimmed.starts_with('"') {
        Style::default().fg(Color::LightGreen)
    } else if trimmed.parse::<f64>().is_ok() {
        Style::default().fg(Color::LightYellow)
    } else if matches!(trimmed, "true" | "false" | "null") {
        Style::default().fg(Color::LightMagenta)
    } else {
        Style::default()
    };
    spans.push(Span::styled(value.to_string(), style));
    Line::from(spans)
}

fn draw_metadata(frame: &mut Frame, app: &App, area: Rect) {
    let lines: Vec<Line> = app
        .selected()
        .and_then(|view| serde_json::to_string_pretty(&view.metadata).ok())
        .map(|json| json.lines().map(json_line).collect())
        .unwrap_or_default();
    let block = block(app, Pane::Metadata)
        .title(Line::from("[decrypted]").italic().right_aligned())
        .title_bottom(Line::from(" [j,k scroll] ").right_aligned());
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .scroll((app.metadata_scroll, 0)),
        area,
    );
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let line = match app.input_line() {
        Some((prompt, text)) => Line::from(vec![
            Span::raw(prompt.to_string()).light_blue(),
            Span::raw(format!("{text}▏")),
        ]),
        None => Line::from(Span::raw(app.status().to_string())).dark_gray(),
    };
    frame.render_widget(line, area);
    let mut right = Vec::new();
    if let Some(seconds) = app.clipboard_left {
        right.push(Span::raw(format!("clipboard cleared in {seconds}s  ")).light_yellow());
    }
    right.push(Span::raw(format!("[{}]", app.mode.letter())));
    frame.render_widget(Line::from(right).right_aligned(), area);
}

/// A rectangle of `width` x `height` in the middle of the screen.
fn centered(frame: &Frame, width: u16, height: u16) -> Rect {
    let area = frame.area();
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

fn popup(title: &str, bottom: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(FOCUSED))
        .title(Line::from(format!(" {title} ")))
        .title_bottom(Line::from(format!(" {bottom} ")).right_aligned())
}

fn help_lines() -> Vec<Line<'static>> {
    let row = |left: &str, right: &str, width: usize| {
        Line::from(vec![
            Span::raw(format!("{left:>width$}  ")).light_cyan(),
            Span::raw(right.to_string()),
        ])
    };
    let mut lines = vec![Line::raw("Keys").bold()];
    lines.extend(KEYS.iter().map(|(keys, what)| row(keys, what, 12)));
    lines.push(Line::raw(""));
    lines.push(Line::raw("Commands, after :").bold());
    lines.extend(
        COMMANDS
            .iter()
            .map(|(command, what)| row(command, what, 34)),
    );
    lines
}

fn draw_help(frame: &mut Frame, scroll: u16) {
    let area = centered(frame, 90, 30);
    frame.render_widget(Clear, area);
    frame.render_widget(
        popup("Help — keys & commands", "[j,k scroll] [any key close]"),
        area,
    );
    frame.render_widget(
        Paragraph::new(help_lines()).scroll((scroll, 0)),
        area.inner(Margin {
            horizontal: 2,
            vertical: 1,
        }),
    );
}

fn draw_confirm(frame: &mut Frame, name: &str) {
    let area = centered(frame, 50, 5);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![Line::raw(""), Line::raw(format!("  Delete {name}?"))])
            .block(popup("Delete", "[y delete] [any key keep]")),
        area,
    );
}

fn draw_form(frame: &mut Frame, form: &Form) {
    let title = if form.id.is_some() {
        "Edit resource"
    } else {
        "New resource"
    };
    let area = centered(frame, 70, 9);
    frame.render_widget(Clear, area);
    let lines: Vec<Line> = Field::ALL
        .iter()
        .map(|field| {
            let value = form.value(*field);
            let shown = match field {
                Field::Password if value.is_empty() && form.id.is_some() => {
                    "(unchanged)".to_string()
                }
                Field::Password if !form.show_password => "•".repeat(value.chars().count()),
                _ => value.to_string(),
            };
            let focused = *field == form.focus;
            let label = Span::raw(format!("{:>12}  ", field.label()));
            let label = if focused {
                label.fg(FOCUSED).bold()
            } else {
                label.dark_gray()
            };
            let cursor = if focused { "▏" } else { "" };
            Line::from(vec![label, Span::raw(format!("{shown}{cursor}"))])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .block(popup(
                title,
                "[Tab next] [C-g generate] [C-r show] [C-s save] [Esc cancel]",
            ))
            .wrap(Wrap { trim: false }),
        area.inner(Margin {
            horizontal: 0,
            vertical: 0,
        }),
    );
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::Terminal;
    use serde_json::json;
    use zeroize::Zeroizing;

    use super::*;
    use crate::tui::app::Revealed;
    use crate::tui::test_view;

    fn app() -> App {
        App::new(
            "passbolt.example.com".into(),
            &[],
            vec![test_view(json!({
                "id": "r-1", "name": "GitHub", "username": "ada",
                "uri": "https://github.com", "description": "code hosting"
            }))],
        )
    }

    fn screen(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        text(terminal.backend().buffer())
    }

    fn text(buffer: &Buffer) -> String {
        buffer
            .content
            .chunks(usize::from(buffer.area.width))
            .map(|row| {
                row.iter()
                    .map(ratatui::buffer::Cell::symbol)
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn test_the_screen_has_the_tabs_the_panes_and_the_server() {
        let screen = screen(&app());

        for text in [
            "1 All",
            "5 Expired",
            "Resources",
            "Folders",
            "Details",
            "Secret",
            "Metadata",
            "[ passbolt • passbolt.example.com ]",
            "1 of 1",
            "[All items]",
            "[N]",
        ] {
            assert!(screen.contains(text), "{text} missing in\n{screen}");
        }
    }

    #[test]
    fn test_the_focused_pane_has_a_thick_border() {
        let screen = screen(&app());

        assert!(screen.contains("┏Resources"), "{screen}");
        assert!(screen.contains("┌Folders"), "{screen}");
    }

    #[test]
    fn test_the_secret_is_hidden_until_revealed() {
        let mut app = app();
        assert!(screen(&app).contains("s shows it"));

        app.revealed = Some(Revealed {
            id: "r-1".into(),
            password: Zeroizing::new("hunter2".into()),
            note: None,
        });

        assert!(screen(&app).contains("hunter2"));
    }

    #[test]
    fn test_the_fullscreen_shows_the_focused_pane_alone() {
        let mut app = app();
        app.fullscreen = true;

        let screen = screen(&app);

        assert!(screen.contains("Resources"), "{screen}");
        assert!(!screen.contains("Folders"), "{screen}");
    }

    #[test]
    fn test_the_command_line_shows_what_is_typed() {
        let mut app = app();
        app.handle_key(ratatui::crossterm::event::KeyEvent::from(
            ratatui::crossterm::event::KeyCode::Char(':'),
        ));
        app.handle_key(ratatui::crossterm::event::KeyEvent::from(
            ratatui::crossterm::event::KeyCode::Char('q'),
        ));

        let screen = screen(&app);

        assert!(screen.contains(":q▏"), "{screen}");
        assert!(screen.contains("[C]"), "{screen}");
    }

    #[test]
    fn test_the_form_masks_the_password() {
        let mut app = app();
        let mut form = Form::new_resource(None);
        form.set_password("hunter2".into());
        app.mode = Mode::Form(Box::new(form));

        let screen = screen(&app);

        assert!(screen.contains("New resource"), "{screen}");
        assert!(screen.contains("•••••••"), "{screen}");
        assert!(!screen.contains("hunter2"), "{screen}");
    }

    #[test]
    fn test_the_help_lists_the_keys_and_commands() {
        let mut app = app();
        app.mode = Mode::Help(0);

        let screen = screen(&app);

        assert!(screen.contains("Help — keys & commands"), "{screen}");
        assert!(screen.contains("copy the TOTP code"), "{screen}");
    }

    #[test]
    fn test_the_metadata_json_is_coloured() {
        let line = json_line(r#"  "name": "GitHub","#);

        assert_eq!(line.spans[1].content, "\"name\"");
        assert_eq!(line.spans[1].style.fg, Some(Color::LightCyan));
        assert_eq!(line.spans[3].style.fg, Some(Color::LightGreen));
    }
}
