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

//! What the terminal UI shows: the folders, the resources, the details of the selected one,
//! the status line, and the help, the form or the confirmation over them.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, Focus, Mode};
use super::form::{Field, Form};

/// The keys, for the help and the bottom line.
pub const KEYS: [(&str, &str); 17] = [
    ("↑↓ j k", "move"),
    ("Tab ← →", "folders / resources"),
    ("/", "search in every folder"),
    ("c Enter", "copy the password"),
    ("u", "copy the username"),
    ("l", "copy the URI"),
    ("t", "copy the TOTP code"),
    ("o", "open the URI"),
    ("s", "show / hide the password"),
    ("n", "new resource in the folder"),
    ("e", "edit the resource"),
    ("d", "delete the resource"),
    ("r", "reload from the server"),
    ("Ctrl+G", "in a form: generate the password"),
    ("Ctrl+R", "in a form: show the password"),
    ("Ctrl+S", "in a form: save"),
    ("q Esc", "quit"),
];

pub fn draw(frame: &mut Frame, app: &App) {
    let [main, status] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());
    let [folders, resources, details] = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(40),
        Constraint::Percentage(35),
    ])
    .areas(main);

    draw_folders(frame, app, folders);
    draw_resources(frame, app, resources);
    draw_details(frame, app, details);
    draw_status(frame, app, status);

    match &app.mode {
        Mode::Help => draw_help(frame),
        Mode::ConfirmDelete(id) => draw_confirm(frame, &app.name_of(id)),
        Mode::Form(form) => draw_form(frame, form),
        Mode::Normal | Mode::Search => {}
    }
}

fn panel(title: String, focused: bool) -> Block<'static> {
    let block = Block::default().borders(Borders::ALL).title(title);
    if focused {
        block.border_style(Style::default().bold())
    } else {
        block
    }
}

fn highlight() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

fn draw_folders(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .folders
        .iter()
        .map(|row| ListItem::new(format!("{}{}", "  ".repeat(row.depth), row.name)))
        .collect();
    let mut state = ListState::default().with_selected(Some(app.folder_index));
    let list = List::new(items)
        .block(panel(" Folders ".into(), app.focus == Focus::Folders))
        .highlight_style(highlight());
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_resources(frame: &mut Frame, app: &App, area: Rect) {
    let visible = app.visible();
    let items: Vec<ListItem> = visible
        .iter()
        .map(|view| {
            let mut spans = vec![Span::raw(view.name.clone())];
            if !view.username.is_empty() {
                spans.push(Span::raw(format!("  {}", view.username)).dim());
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let title = if app.search.is_empty() {
        format!(" Resources ({}) ", visible.len())
    } else {
        format!(" Search: {} ({}) ", app.search, visible.len())
    };
    let selected = (!visible.is_empty()).then_some(app.resource_index);
    let mut state = ListState::default().with_selected(selected);
    let list = List::new(items)
        .block(panel(title, app.focus == Focus::Resources))
        .highlight_style(highlight());
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_details(frame: &mut Frame, app: &App, area: Rect) {
    let block = panel(" Details ".into(), false);
    let Some(view) = app.selected() else {
        frame.render_widget(Paragraph::new("No resource.").block(block), area);
        return;
    };
    let password = match &app.revealed {
        Some(revealed) if revealed.id == view.id => revealed.password.to_string(),
        _ => "•••••••• (s to show)".into(),
    };
    let field = |label: &str, value: &str| {
        Line::from(vec![
            Span::raw(format!("{label}: ")).bold(),
            Span::raw(value.to_string()),
        ])
    };
    let mut lines = vec![
        field("Name", &view.name),
        field("Username", &view.username),
        field("URI", &view.uri),
        field("Password", &password),
    ];
    for uri in view.uris.iter().skip(1) {
        lines.push(field("URI", uri));
    }
    if let Some(resource_type) = &view.resource_type {
        lines.push(field("Type", resource_type));
    }
    if let Some(expired) = view.expired {
        lines.push(field("Expires", &expired.format("%Y-%m-%d").to_string()));
    }
    if let Some(modified) = view.modified {
        lines.push(field(
            "Modified",
            &modified.format("%Y-%m-%d %H:%M").to_string(),
        ));
    }
    if let Some(error) = &view.error {
        lines.push(field("Error", error));
    }
    if !view.description.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::raw(view.description.clone()));
    }
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let text = match app.mode {
        Mode::Search => format!("/{}  Enter: keep, Esc: clear", app.search),
        _ => app.status.clone(),
    };
    let mut spans = vec![Span::raw(text)];
    if let Some(seconds) = app.clipboard_left {
        spans.push(Span::raw(format!("  [clipboard cleared in {seconds}s]")).bold());
    }
    spans.push(Span::raw("  ? help  / search  c copy  q quit").dim());
    let line = Line::from(spans);
    frame.render_widget(Paragraph::new(line), area);
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

fn draw_help(frame: &mut Frame) {
    let lines: Vec<Line> = KEYS
        .iter()
        .map(|(keys, what)| {
            Line::from(vec![
                Span::raw(format!("{keys:>10}  ")).bold(),
                Span::raw(*what),
            ])
        })
        .collect();
    let area = centered(frame, 52, u16::try_from(KEYS.len()).unwrap_or(u16::MAX) + 2);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(panel(" Keys (any key to close) ".into(), true)),
        area,
    );
}

fn draw_confirm(frame: &mut Frame, name: &str) {
    let area = centered(frame, 50, 5);
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::raw(format!("Delete {name}?")),
            Line::raw(""),
            Line::raw("y: delete, any other key: keep").dim(),
        ])
        .block(panel(" Delete ".into(), true)),
        area,
    );
}

fn draw_form(frame: &mut Frame, form: &Form) {
    let title = if form.id.is_some() {
        " Edit resource "
    } else {
        " New resource "
    };
    let area = centered(frame, 64, 13);
    frame.render_widget(Clear, area);
    let mut lines: Vec<Line> = Field::ALL
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
            let cursor = if *field == form.focus { "▏" } else { "" };
            let label = Span::raw(format!("{:>12}: ", field.label()));
            let label = if *field == form.focus {
                label.bold()
            } else {
                label
            };
            Line::from(vec![label, Span::raw(format!("{shown}{cursor}"))])
        })
        .collect();
    lines.push(Line::raw(""));
    lines.push(
        Line::raw("Tab: next field  Ctrl+G: generate  Ctrl+R: show  Ctrl+S: save  Esc: cancel")
            .dim(),
    );
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel(title.into(), true))
            .wrap(Wrap { trim: false }),
        area,
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
            &[],
            &[],
            vec![test_view(json!({
                "id": "r-1", "name": "GitHub", "username": "ada",
                "uri": "https://github.com", "description": "code hosting"
            }))],
        )
    }

    fn screen(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
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
    fn test_the_screen_shows_the_folders_resources_and_details() {
        let screen = screen(&app());

        assert!(screen.contains("All items"), "{screen}");
        assert!(screen.contains("Resources (1)"), "{screen}");
        assert!(screen.contains("Username: ada"), "{screen}");
        assert!(screen.contains("code hosting"), "{screen}");
    }

    #[test]
    fn test_the_password_is_hidden_until_revealed() {
        let mut app = app();
        assert!(screen(&app).contains("(s to show)"));

        app.revealed = Some(Revealed {
            id: "r-1".into(),
            password: Zeroizing::new("hunter2".into()),
        });

        assert!(screen(&app).contains("Password: hunter2"));
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
    fn test_the_help_lists_the_keys() {
        let mut app = app();
        app.mode = Mode::Help;

        let screen = screen(&app);

        assert!(screen.contains("copy the TOTP code"), "{screen}");
    }
}
