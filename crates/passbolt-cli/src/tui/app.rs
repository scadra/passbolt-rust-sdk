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

//! The state of the terminal UI and what each key or command does to it: no terminal, no
//! network, so the tests drive it with keys. The actions that need the server go back to the
//! runner.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use chrono::Utc;
use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::types::FolderTreeNode;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use super::form::{Form, FormOutcome};

/// How long a message of an action stays in the status line.
const FLASH_FOR: Duration = Duration::from_secs(6);

/// The commands kept for `↑` on the command line.
const COMMAND_HISTORY: usize = 50;

/// A line of the folder pane: `All items`, then the folders as a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderRow {
    /// `None` for `All items`.
    pub id: Option<String>,
    pub parent_id: Option<String>,
    pub name: String,
    pub depth: usize,
}

/// The rows of `tree`, `All items` first, each folder after its parent, sorted by name.
pub fn folder_rows(tree: &[FolderTreeNode]) -> Vec<FolderRow> {
    fn push(rows: &mut Vec<FolderRow>, nodes: &[FolderTreeNode], depth: usize) {
        let mut nodes: Vec<&FolderTreeNode> = nodes.iter().collect();
        nodes.sort_by_key(|node| node.folder.name.to_lowercase());
        for node in nodes {
            rows.push(FolderRow {
                id: Some(node.folder.id.clone()),
                parent_id: node.folder.folder_parent_id.clone(),
                name: node.folder.name.clone(),
                depth,
            });
            push(rows, &node.children, depth + 1);
        }
    }
    let mut rows = vec![FolderRow {
        id: None,
        parent_id: None,
        name: "All items".into(),
        depth: 0,
    }];
    push(&mut rows, tree, 0);
    rows
}

/// The panes, in the order `h` and `l` move through them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Resources,
    Folders,
    Details,
    Secret,
    Metadata,
}

impl Pane {
    pub const ALL: [Self; 5] = [
        Self::Resources,
        Self::Folders,
        Self::Details,
        Self::Secret,
        Self::Metadata,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            Self::Resources => "Resources",
            Self::Folders => "Folders",
            Self::Details => "Details",
            Self::Secret => "Secret",
            Self::Metadata => "Metadata",
        }
    }

    fn step(self, step: isize) -> Self {
        let index = Self::ALL
            .iter()
            .position(|pane| *pane == self)
            .unwrap_or_default();
        let count = Self::ALL.len();
        Self::ALL[(index + count).saturating_add_signed(step) % count]
    }
}

/// The tabs of the header: which resources the lists show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    All,
    Favorites,
    Personal,
    Shared,
    Expired,
}

impl Tab {
    pub const ALL: [Self; 5] = [
        Self::All,
        Self::Favorites,
        Self::Personal,
        Self::Shared,
        Self::Expired,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Favorites => "Favorites",
            Self::Personal => "Personal",
            Self::Shared => "Shared",
            Self::Expired => "Expired",
        }
    }

    fn holds(self, view: &ResourceView) -> bool {
        match self {
            Self::All => true,
            Self::Favorites => view.resource.favorite.is_some(),
            Self::Personal => view.personal == Some(true),
            Self::Shared => view.personal == Some(false),
            Self::Expired => view.expired.is_some_and(|expired| expired <= Utc::now()),
        }
    }

    fn named(name: &str) -> Option<Self> {
        let name = name.to_lowercase();
        Self::ALL.into_iter().find(|tab| {
            tab.title().to_lowercase().starts_with(&name)
                || name.parse::<usize>().ok()
                    == Self::ALL
                        .iter()
                        .position(|other| other == tab)
                        .map(|index| index + 1)
        })
    }
}

/// A line typed at the bottom: the command after `:`, the filter after `/`.
#[derive(Debug, Default)]
pub struct Input {
    pub text: String,
    /// The command of the history shown, from the last one.
    history_index: Option<usize>,
}

/// What the keys go to.
#[derive(Debug)]
pub enum Mode {
    Normal,
    /// Typing the filter after `/`.
    Filter(Input),
    /// Typing a command after `:`.
    Command(Input),
    /// The help, scrolled by this many lines.
    Help(u16),
    /// Asking before deleting the resource of this id.
    ConfirmDelete(String),
    Form(Box<Form>),
}

impl Mode {
    /// The letter of the status line: `N`ormal, `I`nsert (a form, the filter) or `C`ommand.
    pub const fn letter(&self) -> char {
        match self {
            Self::Filter(_) | Self::Form(_) => 'I',
            Self::Command(_) => 'C',
            Self::Normal | Self::Help(_) | Self::ConfirmDelete(_) => 'N',
        }
    }
}

/// What the runner does for a key: the calls to the server, the clipboard, the browser.
#[derive(Debug)]
pub enum Action {
    CopyPassword(String),
    CopyUsername(String),
    CopyUri(String),
    CopyTotp(String),
    OpenUri(String),
    Reveal(String),
    Delete(String),
    Save(FormOutcome),
    /// A password from the policies of the organization, for the form.
    Generate,
    Refresh,
}

/// The decrypted secret of one resource, shown until another is selected.
pub struct Revealed {
    pub id: String,
    pub password: Zeroizing<String>,
    /// The secret note of a v5 type.
    pub note: Option<Zeroizing<String>>,
}

pub struct App {
    pub folders: Vec<FolderRow>,
    pub resources: Vec<ResourceView>,
    pub folder_index: usize,
    pub resource_index: usize,
    pub focus: Pane,
    pub tab: Tab,
    /// The filter typed after `/`, over every folder.
    pub filter: String,
    pub mode: Mode,
    /// The focused pane alone on the screen.
    pub fullscreen: bool,
    pub metadata_scroll: u16,
    pub revealed: Option<Revealed>,
    /// The server and the user, in the header.
    pub server: String,
    /// The last message of an action, until it times out.
    flash: Option<(String, Instant)>,
    commands: VecDeque<String>,
    /// The seconds before the copied secret leaves the clipboard.
    pub clipboard_left: Option<u64>,
    pub quit: bool,
}

impl App {
    pub fn new(server: String, tree: &[FolderTreeNode], resources: Vec<ResourceView>) -> Self {
        let mut app = Self {
            folders: folder_rows(tree),
            resources: Vec::new(),
            folder_index: 0,
            resource_index: 0,
            focus: Pane::Resources,
            tab: Tab::All,
            filter: String::new(),
            mode: Mode::Normal,
            fullscreen: false,
            metadata_scroll: 0,
            revealed: None,
            server,
            flash: None,
            commands: VecDeque::new(),
            clipboard_left: None,
            quit: false,
        };
        app.set_resources(resources);
        app
    }

    /// Show `message` in the status line for a few seconds.
    pub fn flash(&mut self, message: impl Into<String>) {
        self.flash = Some((message.into(), Instant::now()));
    }

    /// The message of the status line: the last flash, or the reminder of the keys.
    pub fn status(&self) -> &str {
        match &self.flash {
            Some((message, at)) if at.elapsed() < FLASH_FOR => message,
            _ => "? help  : command  / filter  h l panes  1-5 tabs  f fullscreen  q quit",
        }
    }

    /// Replace the resources, sorted by name, keeping the selected one when it is still there.
    pub fn set_resources(&mut self, mut resources: Vec<ResourceView>) {
        let selected = self.selected().map(|view| view.id.clone());
        resources.sort_by_key(|view| view.name.to_lowercase());
        self.resources = resources;
        self.resource_index = selected
            .and_then(|id| self.visible().iter().position(|view| view.id == id))
            .unwrap_or(0);
        self.clamp();
    }

    /// The resources of the tab, then of the selected folder or matching the filter in all of
    /// them.
    pub fn visible(&self) -> Vec<&ResourceView> {
        let filter = self.filter.to_lowercase();
        let folder_id = self.folders[self.folder_index].id.as_ref();
        self.resources
            .iter()
            .filter(|view| self.tab.holds(view))
            .filter(|view| {
                if filter.is_empty() {
                    folder_id
                        .is_none_or(|folder_id| view.folder_parent_id.as_ref() == Some(folder_id))
                } else {
                    [&view.name, &view.username, &view.uri]
                        .iter()
                        .any(|text| text.to_lowercase().contains(&filter))
                }
            })
            .collect()
    }

    pub fn selected(&self) -> Option<&ResourceView> {
        self.visible().get(self.resource_index).copied()
    }

    /// The folder new resources go to: the selected one.
    pub fn selected_folder_id(&self) -> Option<String> {
        self.folders[self.folder_index].id.clone()
    }

    /// The name of the folder of `id`, for the details.
    pub fn folder_name(&self, id: Option<&String>) -> String {
        id.and_then(|id| self.folders.iter().find(|row| row.id.as_ref() == Some(id)))
            .map_or_else(|| "(root)".into(), |row| row.name.clone())
    }

    /// The name of the resource of `id`, for the messages.
    pub fn name_of(&self, id: &str) -> String {
        self.resources
            .iter()
            .find(|view| view.id == id)
            .map_or_else(String::new, |view| view.name.clone())
    }

    fn clamp(&mut self) {
        let count = self.visible().len();
        self.resource_index = self.resource_index.min(count.saturating_sub(1));
        let selected = self.selected().map(|view| view.id.clone());
        if self
            .revealed
            .as_ref()
            .is_some_and(|revealed| Some(&revealed.id) != selected.as_ref())
        {
            self.revealed = None;
            self.metadata_scroll = 0;
        }
    }

    fn move_selection(&mut self, step: isize) {
        match self.focus {
            Pane::Folders => {
                let last = self.folders.len().saturating_sub(1);
                self.folder_index = self.folder_index.saturating_add_signed(step).min(last);
                self.resource_index = 0;
            }
            Pane::Metadata => {
                let step = i16::try_from(step.clamp(-1000, 1000)).unwrap_or_default();
                self.metadata_scroll = self.metadata_scroll.saturating_add_signed(step);
            }
            Pane::Resources | Pane::Details | Pane::Secret => {
                let last = self.visible().len().saturating_sub(1);
                self.resource_index = self.resource_index.saturating_add_signed(step).min(last);
            }
        }
        self.clamp();
    }

    fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.resource_index = 0;
        self.clamp();
        self.flash(format!("{} ({})", tab.title(), self.visible().len()));
    }

    /// The action of `key`, after its change of state.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return None;
        }
        match &mut self.mode {
            Mode::Normal => self.normal_key(key),
            Mode::Filter(input) => {
                match key.code {
                    KeyCode::Esc => {
                        self.filter.clear();
                        self.mode = Mode::Normal;
                    }
                    KeyCode::Enter => self.mode = Mode::Normal,
                    KeyCode::Backspace => {
                        input.text.pop();
                        self.filter.clone_from(&input.text);
                    }
                    KeyCode::Char(character) => {
                        input.text.push(character);
                        self.filter.clone_from(&input.text);
                    }
                    _ => {}
                }
                self.resource_index = 0;
                self.clamp();
                None
            }
            Mode::Command(input) => match key.code {
                KeyCode::Esc => {
                    self.mode = Mode::Normal;
                    None
                }
                KeyCode::Enter => {
                    let command = std::mem::take(&mut input.text);
                    self.mode = Mode::Normal;
                    self.run_command(&command)
                }
                KeyCode::Up | KeyCode::Down if !self.commands.is_empty() => {
                    let count = self.commands.len();
                    let index = match (key.code, input.history_index) {
                        (KeyCode::Up, Some(index)) => (index + 1).min(count - 1),
                        (_, Some(index)) => index.saturating_sub(1),
                        (_, None) => 0,
                    };
                    input.history_index = Some(index);
                    input.text.clone_from(&self.commands[index]);
                    None
                }
                KeyCode::Backspace => {
                    input.text.pop();
                    None
                }
                KeyCode::Char(character) => {
                    input.text.push(character);
                    None
                }
                _ => None,
            },
            Mode::Help(scroll) => {
                match key.code {
                    KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                    KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                    _ => self.mode = Mode::Normal,
                }
                None
            }
            Mode::ConfirmDelete(id) => {
                let id = id.clone();
                self.mode = Mode::Normal;
                if matches!(key.code, KeyCode::Char('y' | 'Y')) {
                    Some(Action::Delete(id))
                } else {
                    self.flash("Not deleted.");
                    None
                }
            }
            Mode::Form(form) => match form.handle_key(key) {
                Some(FormKey::Cancel) => {
                    self.mode = Mode::Normal;
                    self.flash("Cancelled.");
                    None
                }
                Some(FormKey::Generate) => Some(Action::Generate),
                Some(FormKey::Save(outcome)) => Some(Action::Save(outcome)),
                Some(FormKey::Invalid(message)) => {
                    self.flash(message);
                    None
                }
                None => None,
            },
        }
    }

    fn on_selected(&self, action: fn(String) -> Action) -> Option<Action> {
        self.selected().map(|view| action(view.id.clone()))
    }

    fn normal_key(&mut self, key: KeyEvent) -> Option<Action> {
        if self.navigate(key.code) {
            return None;
        }
        match key.code {
            KeyCode::Char('q') => {
                self.quit = true;
                None
            }
            KeyCode::Esc => {
                if self.fullscreen {
                    self.fullscreen = false;
                } else {
                    self.filter.clear();
                    self.clamp();
                }
                None
            }
            KeyCode::Char('?') => {
                self.mode = Mode::Help(0);
                None
            }
            KeyCode::Char('/') => {
                self.mode = Mode::Filter(Input {
                    text: self.filter.clone(),
                    history_index: None,
                });
                None
            }
            KeyCode::Char(':') => {
                self.mode = Mode::Command(Input::default());
                None
            }
            // In the folders, into the resources of the folder, or back to its parent.
            KeyCode::Char('g') | KeyCode::Enter if self.focus == Pane::Folders => {
                self.focus = Pane::Resources;
                None
            }
            KeyCode::Char('b') | KeyCode::Backspace if self.focus == Pane::Folders => {
                let parent = self.folders[self.folder_index].parent_id.clone();
                self.folder_index = self
                    .folders
                    .iter()
                    .position(|row| row.id == parent)
                    .unwrap_or(0);
                self.resource_index = 0;
                self.clamp();
                None
            }
            KeyCode::Char('c') | KeyCode::Enter => self.on_selected(Action::CopyPassword),
            KeyCode::Char('u') => self.on_selected(Action::CopyUsername),
            KeyCode::Char('a') => self.on_selected(Action::CopyUri),
            KeyCode::Char('t') => self.on_selected(Action::CopyTotp),
            KeyCode::Char('o') => self.on_selected(Action::OpenUri),
            KeyCode::Char('s') => self.show(),
            KeyCode::Char('r') => Some(Action::Refresh),
            KeyCode::Char('n') => {
                self.mode = Mode::Form(Box::new(Form::new_resource(self.selected_folder_id())));
                None
            }
            KeyCode::Char('e') => {
                self.edit();
                None
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                self.confirm_delete();
                None
            }
            _ => None,
        }
    }

    /// The keys that move between the panes, the tabs and in a list; `false` for another key.
    fn navigate(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char('l') | KeyCode::Right | KeyCode::Tab => {
                self.focus = self.focus.step(1);
                true
            }
            KeyCode::Char('h') | KeyCode::Left | KeyCode::BackTab => {
                self.focus = self.focus.step(-1);
                true
            }
            KeyCode::Char('f') => {
                self.fullscreen = !self.fullscreen;
                true
            }
            KeyCode::Char(digit @ '1'..='5') => {
                let index = usize::from(digit as u8 - b'1');
                self.set_tab(Tab::ALL[index]);
                true
            }
            KeyCode::Char(bracket @ (']' | '[')) => {
                let index = Tab::ALL
                    .iter()
                    .position(|tab| *tab == self.tab)
                    .unwrap_or_default();
                let count = Tab::ALL.len();
                let next = if bracket == ']' {
                    index + 1
                } else {
                    index + count - 1
                };
                self.set_tab(Tab::ALL[next % count]);
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
                true
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
                true
            }
            KeyCode::PageDown => {
                self.move_selection(10);
                true
            }
            KeyCode::PageUp => {
                self.move_selection(-10);
                true
            }
            KeyCode::Home => {
                self.move_selection(isize::MIN / 2);
                true
            }
            KeyCode::End => {
                self.move_selection(isize::MAX / 2);
                true
            }
            _ => false,
        }
    }

    fn show(&mut self) -> Option<Action> {
        if self.revealed.take().is_some() {
            return None;
        }
        self.on_selected(Action::Reveal)
    }

    fn edit(&mut self) {
        if let Some(view) = self.selected() {
            self.mode = Mode::Form(Box::new(Form::edit(view)));
        }
    }

    fn confirm_delete(&mut self) {
        if let Some(view) = self.selected() {
            self.mode = Mode::ConfirmDelete(view.id.clone());
        }
    }

    /// The action of a command typed after `:`.
    fn run_command(&mut self, line: &str) -> Option<Action> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        self.commands.retain(|command| command != line);
        self.commands.push_front(line.to_string());
        self.commands.truncate(COMMAND_HISTORY);
        let (command, argument) = line.split_once(' ').unwrap_or((line, ""));
        let argument = argument.trim();
        match command {
            "q" | "quit" => {
                self.quit = true;
                None
            }
            "help" => {
                self.mode = Mode::Help(0);
                None
            }
            "r" | "reload" => Some(Action::Refresh),
            "copy" | "c" => match argument {
                "" | "password" => self.on_selected(Action::CopyPassword),
                "username" | "user" => self.on_selected(Action::CopyUsername),
                "uri" | "url" => self.on_selected(Action::CopyUri),
                "totp" => self.on_selected(Action::CopyTotp),
                other => {
                    self.flash(format!(
                        "copy what? password, username, uri or totp, not {other}"
                    ));
                    None
                }
            },
            "open" => self.on_selected(Action::OpenUri),
            "show" => self.show(),
            "new" => {
                self.mode = Mode::Form(Box::new(Form::new_resource(self.selected_folder_id())));
                None
            }
            "edit" => {
                self.edit();
                None
            }
            "delete" => {
                self.confirm_delete();
                None
            }
            "filter" => {
                self.filter = argument.to_string();
                self.resource_index = 0;
                self.clamp();
                None
            }
            "tab" => {
                match Tab::named(argument) {
                    Some(tab) => self.set_tab(tab),
                    None => self.flash(format!(
                        "No tab {argument}: all, favorites, personal, shared, expired"
                    )),
                }
                None
            }
            "folder" => {
                let name = argument.to_lowercase();
                match self
                    .folders
                    .iter()
                    .position(|row| row.name.to_lowercase().starts_with(&name))
                {
                    Some(index) => {
                        self.folder_index = index;
                        self.filter.clear();
                        self.resource_index = 0;
                        self.clamp();
                    }
                    None => self.flash(format!("No folder {argument}")),
                }
                None
            }
            "f" | "fullscreen" => {
                self.fullscreen = !self.fullscreen;
                None
            }
            other => {
                self.flash(format!("Unknown command: {other} (:help lists them)"));
                None
            }
        }
    }

    /// The command line or the filter being typed, with its prompt.
    pub fn input_line(&self) -> Option<(char, &str)> {
        match &self.mode {
            Mode::Filter(input) => Some(('/', &input.text)),
            Mode::Command(input) => Some((':', &input.text)),
            _ => None,
        }
    }
}

/// What a key does in the form, for the app.
#[derive(Debug)]
pub enum FormKey {
    Cancel,
    Generate,
    Save(FormOutcome),
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;
    use crate::tui::test_view;

    fn view(id: &str, name: &str, folder: Option<&str>) -> ResourceView {
        test_view(json!({
            "id": id,
            "name": name,
            "username": format!("{name}-user"),
            "uri": format!("https://{name}.example.com"),
            "folder_parent_id": folder,
            "personal": folder.is_none(),
        }))
    }

    fn folder(id: &str, name: &str, parent: Option<&str>) -> passbolt_sdk::types::Folder {
        serde_json::from_value(json!({
            "id": id, "name": name, "folder_parent_id": parent,
            "created": null, "modified": null
        }))
        .unwrap()
    }

    fn app() -> App {
        let folders = vec![
            folder("f-ops", "Ops", None),
            folder("f-db", "Databases", Some("f-ops")),
        ];
        let tree = passbolt_sdk::build_folder_tree(&folders);
        App::new(
            "passbolt.example.com".into(),
            &tree,
            vec![
                view("r-gitlab", "gitlab", None),
                view("r-aws", "aws", Some("f-ops")),
                view("r-pg", "postgres", Some("f-db")),
            ],
        )
    }

    fn press(app: &mut App, code: KeyCode) -> Option<Action> {
        app.handle_key(KeyEvent::from(code))
    }

    fn type_text(app: &mut App, text: &str) {
        for character in text.chars() {
            press(app, KeyCode::Char(character));
        }
    }

    fn command(app: &mut App, line: &str) -> Option<Action> {
        press(app, KeyCode::Char(':'));
        type_text(app, line);
        press(app, KeyCode::Enter)
    }

    fn names(app: &App) -> Vec<&str> {
        app.visible()
            .iter()
            .map(|view| view.name.as_str())
            .collect()
    }

    #[test]
    fn test_the_folders_are_a_tree_under_all_items() {
        let app = app();

        let rows: Vec<(&str, usize)> = app
            .folders
            .iter()
            .map(|row| (row.name.as_str(), row.depth))
            .collect();

        assert_eq!(rows, [("All items", 0), ("Ops", 0), ("Databases", 1)]);
    }

    #[test]
    fn test_all_items_lists_every_resource_by_name() {
        assert_eq!(names(&app()), ["aws", "gitlab", "postgres"]);
    }

    #[test]
    fn test_l_and_h_move_through_the_panes() {
        let mut app = app();

        press(&mut app, KeyCode::Char('l'));
        assert_eq!(app.focus, Pane::Folders);
        press(&mut app, KeyCode::Char('h'));
        press(&mut app, KeyCode::Char('h'));

        assert_eq!(app.focus, Pane::Metadata);
    }

    #[test]
    fn test_a_folder_lists_its_own_resources() {
        let mut app = app();
        press(&mut app, KeyCode::Char('l'));

        press(&mut app, KeyCode::Char('j'));
        press(&mut app, KeyCode::Char('j'));

        assert_eq!(names(&app), ["postgres"]);
        assert_eq!(app.selected_folder_id().as_deref(), Some("f-db"));
    }

    #[test]
    fn test_b_goes_back_to_the_parent_folder() {
        let mut app = app();
        command(&mut app, "folder data");
        app.focus = Pane::Folders;

        press(&mut app, KeyCode::Char('b'));

        assert_eq!(app.selected_folder_id().as_deref(), Some("f-ops"));
    }

    #[test]
    fn test_the_filter_looks_in_every_folder() {
        let mut app = app();
        press(&mut app, KeyCode::Char('/'));

        type_text(&mut app, "POST");

        assert_eq!(app.selected().map(|view| view.id.as_str()), Some("r-pg"));
        assert_eq!(app.input_line(), Some(('/', "POST")));
    }

    #[test]
    fn test_escape_clears_the_filter() {
        let mut app = app();
        press(&mut app, KeyCode::Char('/'));
        type_text(&mut app, "zzz");

        press(&mut app, KeyCode::Esc);

        assert_eq!(app.filter, "");
        assert_eq!(app.visible().len(), 3);
    }

    #[rstest]
    #[case::personal(KeyCode::Char('3'), Tab::Personal, &["gitlab"])]
    #[case::shared(KeyCode::Char('4'), Tab::Shared, &["aws", "postgres"])]
    #[case::next(KeyCode::Char(']'), Tab::Favorites, &[])]
    #[case::previous(KeyCode::Char('['), Tab::Expired, &[])]
    fn test_the_tabs_select_the_resources(
        #[case] code: KeyCode,
        #[case] tab: Tab,
        #[case] expected: &[&str],
    ) {
        let mut app = app();

        press(&mut app, code);

        assert_eq!(app.tab, tab);
        assert_eq!(names(&app), expected);
    }

    #[rstest]
    #[case::password(KeyCode::Char('c'), "CopyPassword(\"r-aws\")")]
    #[case::enter(KeyCode::Enter, "CopyPassword(\"r-aws\")")]
    #[case::username(KeyCode::Char('u'), "CopyUsername(\"r-aws\")")]
    #[case::uri(KeyCode::Char('a'), "CopyUri(\"r-aws\")")]
    #[case::totp(KeyCode::Char('t'), "CopyTotp(\"r-aws\")")]
    #[case::open(KeyCode::Char('o'), "OpenUri(\"r-aws\")")]
    #[case::reveal(KeyCode::Char('s'), "Reveal(\"r-aws\")")]
    fn test_the_keys_act_on_the_selected_resource(#[case] code: KeyCode, #[case] action: &str) {
        assert_eq!(format!("{:?}", press(&mut app(), code).unwrap()), action);
    }

    #[rstest]
    #[case::copy("copy", "CopyPassword(\"r-aws\")")]
    #[case::copy_username("copy username", "CopyUsername(\"r-aws\")")]
    #[case::copy_uri("copy uri", "CopyUri(\"r-aws\")")]
    #[case::copy_totp("copy totp", "CopyTotp(\"r-aws\")")]
    #[case::open("open", "OpenUri(\"r-aws\")")]
    #[case::reload("reload", "Refresh")]
    fn test_the_commands_act_as_their_keys(#[case] line: &str, #[case] action: &str) {
        assert_eq!(format!("{:?}", command(&mut app(), line).unwrap()), action);
    }

    #[test]
    fn test_an_unknown_command_says_so() {
        let mut app = app();

        command(&mut app, "frobnicate");

        assert!(
            app.status().contains("Unknown command: frobnicate"),
            "{}",
            app.status()
        );
    }

    #[test]
    fn test_up_brings_the_last_command_back() {
        let mut app = app();
        command(&mut app, "tab shared");
        press(&mut app, KeyCode::Char(':'));

        press(&mut app, KeyCode::Up);

        assert_eq!(app.input_line(), Some((':', "tab shared")));
    }

    #[test]
    fn test_the_mode_letter_follows_the_input() {
        let mut app = app();
        assert_eq!(app.mode.letter(), 'N');

        press(&mut app, KeyCode::Char(':'));
        assert_eq!(app.mode.letter(), 'C');
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Char('n'));

        assert_eq!(app.mode.letter(), 'I');
    }

    #[test]
    fn test_f_toggles_the_fullscreen_pane() {
        let mut app = app();

        press(&mut app, KeyCode::Char('f'));
        assert!(app.fullscreen);
        press(&mut app, KeyCode::Esc);

        assert!(!app.fullscreen);
    }

    #[test]
    fn test_a_deletion_is_confirmed() {
        let mut app = app();
        press(&mut app, KeyCode::Char('d'));

        let action = press(&mut app, KeyCode::Char('y'));

        assert!(matches!(action, Some(Action::Delete(id)) if id == "r-aws"));
    }

    #[test]
    fn test_any_other_key_keeps_the_resource() {
        let mut app = app();
        press(&mut app, KeyCode::Char('d'));

        let action = press(&mut app, KeyCode::Char('n'));

        assert!(action.is_none());
        assert!(matches!(app.mode, Mode::Normal));
    }

    #[test]
    fn test_the_revealed_secret_is_hidden_on_another_resource() {
        let mut app = app();
        app.revealed = Some(Revealed {
            id: "r-aws".into(),
            password: Zeroizing::new("secret".into()),
            note: None,
        });

        press(&mut app, KeyCode::Char('j'));

        assert!(app.revealed.is_none());
    }

    #[test]
    fn test_the_selection_stays_on_its_resource_after_a_refresh() {
        let mut app = app();
        press(&mut app, KeyCode::Char('j'));

        app.set_resources(vec![
            view("r-new", "azure", None),
            view("r-gitlab", "gitlab", None),
        ]);

        assert_eq!(
            app.selected().map(|view| view.id.as_str()),
            Some("r-gitlab")
        );
    }

    #[test]
    fn test_a_new_resource_goes_to_the_selected_folder() {
        let mut app = app();
        command(&mut app, "folder ops");

        press(&mut app, KeyCode::Char('n'));

        let Mode::Form(form) = &app.mode else {
            panic!("no form");
        };
        assert_eq!(form.folder_parent_id.as_deref(), Some("f-ops"));
    }

    #[test]
    fn test_q_quits() {
        let mut app = app();

        press(&mut app, KeyCode::Char('q'));

        assert!(app.quit);
    }
}
