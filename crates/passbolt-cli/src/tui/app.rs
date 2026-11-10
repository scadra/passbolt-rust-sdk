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

//! The state of the terminal UI and what each key does to it: no terminal, no network, so
//! the tests drive it with keys. The actions that need the server go back to the runner.

use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::types::{Folder, FolderTreeNode};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use super::form::{Form, FormOutcome};

/// A line of the folder panel: `All items`, then the folders as a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderRow {
    /// `None` for `All items`.
    pub id: Option<String>,
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
                name: node.folder.name.clone(),
                depth,
            });
            push(rows, &node.children, depth + 1);
        }
    }
    let mut rows = vec![FolderRow {
        id: None,
        name: "All items".into(),
        depth: 0,
    }];
    push(&mut rows, tree, 0);
    rows
}

/// The panel the arrows move in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Folders,
    Resources,
}

/// What the keys go to.
#[derive(Debug)]
pub enum Mode {
    Normal,
    /// Typing the search.
    Search,
    Help,
    /// Asking before deleting the resource of this id.
    ConfirmDelete(String),
    Form(Box<Form>),
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

/// The decrypted password of one resource, shown until another is selected.
pub struct Revealed {
    pub id: String,
    pub password: Zeroizing<String>,
}

pub struct App {
    pub folders: Vec<FolderRow>,
    pub resources: Vec<ResourceView>,
    pub folder_index: usize,
    pub resource_index: usize,
    pub focus: Focus,
    pub search: String,
    pub mode: Mode,
    pub revealed: Option<Revealed>,
    /// The last thing done or failed, at the bottom.
    pub status: String,
    /// The seconds before the copied secret leaves the clipboard.
    pub clipboard_left: Option<u64>,
    pub quit: bool,
}

impl App {
    pub fn new(folders: &[Folder], tree: &[FolderTreeNode], resources: Vec<ResourceView>) -> Self {
        let mut app = Self {
            folders: folder_rows(tree),
            resources: Vec::new(),
            folder_index: 0,
            resource_index: 0,
            focus: Focus::Resources,
            search: String::new(),
            mode: Mode::Normal,
            revealed: None,
            status: format!("{} folders. Press ? for help.", folders.len()),
            clipboard_left: None,
            quit: false,
        };
        app.set_resources(resources);
        app
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

    /// The resources of the selected folder, or matching the search in all of them.
    pub fn visible(&self) -> Vec<&ResourceView> {
        let search = self.search.to_lowercase();
        if !search.is_empty() {
            return self
                .resources
                .iter()
                .filter(|view| {
                    [&view.name, &view.username, &view.uri]
                        .iter()
                        .any(|text| text.to_lowercase().contains(&search))
                })
                .collect();
        }
        self.folders[self.folder_index].id.as_ref().map_or_else(
            || self.resources.iter().collect(),
            |folder_id| {
                self.resources
                    .iter()
                    .filter(|view| view.folder_parent_id.as_ref() == Some(folder_id))
                    .collect()
            },
        )
    }

    pub fn selected(&self) -> Option<&ResourceView> {
        self.visible().get(self.resource_index).copied()
    }

    /// The folder new resources go to: the selected one.
    pub fn selected_folder_id(&self) -> Option<String> {
        self.folders[self.folder_index].id.clone()
    }

    fn clamp(&mut self) {
        let count = self.visible().len();
        self.resource_index = self.resource_index.min(count.saturating_sub(1));
        if self
            .revealed
            .as_ref()
            .is_some_and(|revealed| Some(&revealed.id) != self.selected().map(|view| &view.id))
        {
            self.revealed = None;
        }
    }

    fn move_selection(&mut self, step: isize) {
        let count = match self.focus {
            Focus::Folders => self.folders.len(),
            Focus::Resources => self.visible().len(),
        };
        let index = match self.focus {
            Focus::Folders => &mut self.folder_index,
            Focus::Resources => &mut self.resource_index,
        };
        if count == 0 {
            return;
        }
        *index = index.saturating_add_signed(step).min(count - 1);
        if self.focus == Focus::Folders {
            self.resource_index = 0;
        }
        self.clamp();
    }

    /// The action of `key`, after its change of state.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return None;
        }
        match &mut self.mode {
            Mode::Normal => self.normal_key(key),
            Mode::Search => {
                match key.code {
                    KeyCode::Esc => {
                        self.search.clear();
                        self.mode = Mode::Normal;
                    }
                    KeyCode::Enter => self.mode = Mode::Normal,
                    KeyCode::Backspace => {
                        self.search.pop();
                    }
                    KeyCode::Char(character) => self.search.push(character),
                    _ => {}
                }
                self.resource_index = 0;
                self.clamp();
                None
            }
            Mode::Help => {
                self.mode = Mode::Normal;
                None
            }
            Mode::ConfirmDelete(id) => {
                let id = id.clone();
                self.mode = Mode::Normal;
                if matches!(key.code, KeyCode::Char('y' | 'Y')) {
                    Some(Action::Delete(id))
                } else {
                    self.status = "Not deleted.".into();
                    None
                }
            }
            Mode::Form(form) => match form.handle_key(key) {
                Some(FormKey::Cancel) => {
                    self.mode = Mode::Normal;
                    self.status = "Cancelled.".into();
                    None
                }
                Some(FormKey::Generate) => Some(Action::Generate),
                Some(FormKey::Save(outcome)) => Some(Action::Save(outcome)),
                Some(FormKey::Invalid(message)) => {
                    self.status = message;
                    None
                }
                None => None,
            },
        }
    }

    fn normal_key(&mut self, key: KeyEvent) -> Option<Action> {
        let selected = self.selected().map(|view| view.id.clone());
        let on_selected = |action: fn(String) -> Action| selected.clone().map(action);
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.search.is_empty() {
                    self.quit = true;
                } else {
                    self.search.clear();
                    self.clamp();
                }
                None
            }
            KeyCode::Char('?') => {
                self.mode = Mode::Help;
                None
            }
            KeyCode::Char('/') => {
                self.mode = Mode::Search;
                None
            }
            KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right => {
                self.focus = match key.code {
                    KeyCode::Left => Focus::Folders,
                    KeyCode::Right => Focus::Resources,
                    _ if self.focus == Focus::Folders => Focus::Resources,
                    _ => Focus::Folders,
                };
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
                None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
                None
            }
            KeyCode::PageDown => {
                self.move_selection(10);
                None
            }
            KeyCode::PageUp => {
                self.move_selection(-10);
                None
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.move_selection(isize::MIN / 2);
                None
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.move_selection(isize::MAX / 2);
                None
            }
            KeyCode::Char('c') | KeyCode::Enter => on_selected(Action::CopyPassword),
            KeyCode::Char('u') => on_selected(Action::CopyUsername),
            KeyCode::Char('l') => on_selected(Action::CopyUri),
            KeyCode::Char('t') => on_selected(Action::CopyTotp),
            KeyCode::Char('o') => on_selected(Action::OpenUri),
            KeyCode::Char('s') => {
                if self.revealed.is_some() {
                    self.revealed = None;
                    None
                } else {
                    on_selected(Action::Reveal)
                }
            }
            KeyCode::Char('r') => Some(Action::Refresh),
            KeyCode::Char('n') => {
                self.mode = Mode::Form(Box::new(Form::new_resource(self.selected_folder_id())));
                None
            }
            KeyCode::Char('e') => {
                if let Some(view) = self.selected() {
                    self.mode = Mode::Form(Box::new(Form::edit(view)));
                }
                None
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if let Some(view) = self.selected() {
                    self.mode = Mode::ConfirmDelete(view.id.clone());
                }
                None
            }
            _ => None,
        }
    }

    /// The name of the resource of `id`, for the messages.
    pub fn name_of(&self, id: &str) -> String {
        self.resources
            .iter()
            .find(|view| view.id == id)
            .map_or_else(String::new, |view| view.name.clone())
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
        }))
    }

    fn folder(id: &str, name: &str, parent: Option<&str>) -> Folder {
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
            &folders,
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

    #[test]
    fn test_the_folders_are_a_tree_under_all_items() {
        let rows: Vec<(String, usize)> = app()
            .folders
            .iter()
            .map(|row| (row.name.clone(), row.depth))
            .collect();

        assert_eq!(
            rows,
            [
                ("All items".into(), 0),
                ("Ops".into(), 0),
                ("Databases".into(), 1)
            ]
        );
    }

    #[test]
    fn test_all_items_lists_every_resource_by_name() {
        let app = app();

        let names: Vec<&str> = app
            .visible()
            .iter()
            .map(|view| view.name.as_str())
            .collect();

        assert_eq!(names, ["aws", "gitlab", "postgres"]);
    }

    #[test]
    fn test_a_folder_lists_its_own_resources() {
        let mut app = app();
        press(&mut app, KeyCode::Left);

        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Down);

        let names: Vec<&str> = app
            .visible()
            .iter()
            .map(|view| view.name.as_str())
            .collect();
        assert_eq!(names, ["postgres"]);
        assert_eq!(app.selected_folder_id().as_deref(), Some("f-db"));
    }

    #[test]
    fn test_the_search_looks_in_every_folder() {
        let mut app = app();
        press(&mut app, KeyCode::Char('/'));

        type_text(&mut app, "POST");

        assert_eq!(app.selected().map(|view| view.id.as_str()), Some("r-pg"));
    }

    #[test]
    fn test_escape_clears_the_search() {
        let mut app = app();
        press(&mut app, KeyCode::Char('/'));
        type_text(&mut app, "zzz");

        press(&mut app, KeyCode::Esc);

        assert_eq!(app.search, "");
        assert_eq!(app.visible().len(), 3);
    }

    #[rstest]
    #[case::password(KeyCode::Char('c'), "CopyPassword(\"r-aws\")")]
    #[case::enter(KeyCode::Enter, "CopyPassword(\"r-aws\")")]
    #[case::username(KeyCode::Char('u'), "CopyUsername(\"r-aws\")")]
    #[case::uri(KeyCode::Char('l'), "CopyUri(\"r-aws\")")]
    #[case::totp(KeyCode::Char('t'), "CopyTotp(\"r-aws\")")]
    #[case::open(KeyCode::Char('o'), "OpenUri(\"r-aws\")")]
    #[case::reveal(KeyCode::Char('s'), "Reveal(\"r-aws\")")]
    fn test_the_keys_act_on_the_selected_resource(#[case] code: KeyCode, #[case] action: &str) {
        assert_eq!(format!("{:?}", press(&mut app(), code).unwrap()), action);
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
    fn test_the_revealed_password_is_hidden_on_another_resource() {
        let mut app = app();
        app.revealed = Some(Revealed {
            id: "r-aws".into(),
            password: Zeroizing::new("secret".into()),
        });

        press(&mut app, KeyCode::Down);

        assert!(app.revealed.is_none());
    }

    #[test]
    fn test_the_selection_stays_on_its_resource_after_a_refresh() {
        let mut app = app();
        press(&mut app, KeyCode::Down);

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
        press(&mut app, KeyCode::Left);
        press(&mut app, KeyCode::Down);

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
