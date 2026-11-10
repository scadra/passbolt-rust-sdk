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

//! The form creating or editing a resource: its fields, the keys that fill them, and the
//! resource or changes it gives.

use passbolt_sdk::resource::create::NewResource;
use passbolt_sdk::resource::update::ResourceChanges;
use passbolt_sdk::resource::view::ResourceView;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use super::app::FormKey;

/// The fields, in their order on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Username,
    Uri,
    Password,
    Description,
}

impl Field {
    pub const ALL: [Self; 5] = [
        Self::Name,
        Self::Username,
        Self::Uri,
        Self::Password,
        Self::Description,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Username => "Username",
            Self::Uri => "URI",
            Self::Password => "Password",
            Self::Description => "Description",
        }
    }
}

/// What the form saves.
#[derive(Debug)]
pub enum FormOutcome {
    Create(Box<NewResource>),
    Update(String, Box<ResourceChanges>),
}

pub struct Form {
    /// The resource edited; `None` creates one.
    pub id: Option<String>,
    pub folder_parent_id: Option<String>,
    pub name: String,
    pub username: String,
    pub uri: String,
    /// Empty when editing keeps the current password.
    pub password: Zeroizing<String>,
    pub description: String,
    pub focus: Field,
    pub show_password: bool,
    /// The values when the form opened, to send only the changes.
    original: [String; 4],
}

impl std::fmt::Debug for Form {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Form")
            .field("id", &self.id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Form {
    pub fn new_resource(folder_parent_id: Option<String>) -> Self {
        Self {
            id: None,
            folder_parent_id,
            name: String::new(),
            username: String::new(),
            uri: String::new(),
            password: Zeroizing::new(String::new()),
            description: String::new(),
            focus: Field::Name,
            show_password: false,
            original: Default::default(),
        }
    }

    pub fn edit(view: &ResourceView) -> Self {
        let original = [
            view.name.clone(),
            view.username.clone(),
            view.uri.clone(),
            view.description.clone(),
        ];
        Self {
            id: Some(view.id.clone()),
            folder_parent_id: view.folder_parent_id.clone(),
            name: original[0].clone(),
            username: original[1].clone(),
            uri: original[2].clone(),
            password: Zeroizing::new(String::new()),
            description: original[3].clone(),
            focus: Field::Name,
            show_password: false,
            original,
        }
    }

    pub fn value(&self, field: Field) -> &str {
        match field {
            Field::Name => &self.name,
            Field::Username => &self.username,
            Field::Uri => &self.uri,
            Field::Password => &self.password,
            Field::Description => &self.description,
        }
    }

    fn value_mut(&mut self, field: Field) -> &mut String {
        match field {
            Field::Name => &mut self.name,
            Field::Username => &mut self.username,
            Field::Uri => &mut self.uri,
            Field::Password => &mut self.password,
            Field::Description => &mut self.description,
        }
    }

    fn move_focus(&mut self, step: isize) {
        let index = Field::ALL
            .iter()
            .position(|field| *field == self.focus)
            .unwrap_or_default();
        let count = Field::ALL.len();
        let next = (index + count).saturating_add_signed(step) % count;
        self.focus = Field::ALL[next];
    }

    /// Set the password, a generated one.
    pub fn set_password(&mut self, password: String) {
        self.password = Zeroizing::new(password);
        self.focus = Field::Password;
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<FormKey> {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => Some(FormKey::Cancel),
            KeyCode::Char('g') if control => Some(FormKey::Generate),
            KeyCode::Char('r') if control => {
                self.show_password = !self.show_password;
                None
            }
            KeyCode::Char('s') if control => Some(self.save()),
            KeyCode::Enter if self.focus == Field::Description => Some(self.save()),
            KeyCode::Enter | KeyCode::Tab | KeyCode::Down => {
                self.move_focus(1);
                None
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.move_focus(-1);
                None
            }
            KeyCode::Backspace => {
                self.value_mut(self.focus).pop();
                None
            }
            KeyCode::Char(character) if !control => {
                self.value_mut(self.focus).push(character);
                None
            }
            _ => None,
        }
    }

    fn save(&self) -> FormKey {
        if self.name.trim().is_empty() {
            return FormKey::Invalid("A resource needs a name.".into());
        }
        let password = (!self.password.is_empty()).then(|| self.password.to_string());
        match &self.id {
            None => FormKey::Save(FormOutcome::Create(Box::new(NewResource {
                name: self.name.trim().to_string(),
                username: non_empty(&self.username),
                uris: non_empty(&self.uri).into_iter().collect(),
                description: non_empty(&self.description),
                password,
                folder_parent_id: self.folder_parent_id.clone(),
                ..NewResource::default()
            }))),
            Some(id) => {
                let changed = |index: usize, value: &str| {
                    (self.original[index] != value).then(|| value.trim().to_string())
                };
                let uri = changed(2, &self.uri);
                FormKey::Save(FormOutcome::Update(
                    id.clone(),
                    Box::new(ResourceChanges {
                        name: changed(0, &self.name),
                        username: changed(1, &self.username),
                        uris: uri.map(|uri| {
                            if uri.is_empty() {
                                Vec::new()
                            } else {
                                vec![uri]
                            }
                        }),
                        description: changed(3, &self.description),
                        password,
                        ..ResourceChanges::default()
                    }),
                ))
            }
        }
    }
}

fn non_empty(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::tui::test_view;

    fn type_text(form: &mut Form, text: &str) {
        for character in text.chars() {
            form.handle_key(KeyEvent::from(KeyCode::Char(character)));
        }
    }

    fn press(form: &mut Form, code: KeyCode) -> Option<FormKey> {
        form.handle_key(KeyEvent::from(code))
    }

    fn control(form: &mut Form, character: char) -> Option<FormKey> {
        form.handle_key(KeyEvent::new(
            KeyCode::Char(character),
            KeyModifiers::CONTROL,
        ))
    }

    #[test]
    fn test_a_new_resource_takes_the_fields_typed() {
        let mut form = Form::new_resource(Some("f-ops".into()));
        type_text(&mut form, "GitHub");
        press(&mut form, KeyCode::Tab);
        type_text(&mut form, "ada");
        press(&mut form, KeyCode::Tab);
        press(&mut form, KeyCode::Tab);
        type_text(&mut form, "s3cr3t");

        let Some(FormKey::Save(FormOutcome::Create(new))) = control(&mut form, 's') else {
            panic!("not saved");
        };

        assert_eq!(new.name, "GitHub");
        assert_eq!(new.username.as_deref(), Some("ada"));
        assert_eq!(new.uris, Vec::<String>::new());
        assert_eq!(new.password.as_deref(), Some("s3cr3t"));
        assert_eq!(new.folder_parent_id.as_deref(), Some("f-ops"));
    }

    #[test]
    fn test_a_resource_without_name_is_not_saved() {
        let mut form = Form::new_resource(None);

        let key = control(&mut form, 's');

        assert!(matches!(key, Some(FormKey::Invalid(_))));
    }

    #[test]
    fn test_an_edit_sends_only_the_fields_changed() {
        let view = test_view(json!({
            "id": "r-1", "name": "GitHub", "username": "ada", "uri": "https://github.com",
            "description": "code"
        }));
        let mut form = Form::edit(&view);
        press(&mut form, KeyCode::Tab);
        press(&mut form, KeyCode::Backspace);
        type_text(&mut form, "dy");

        let Some(FormKey::Save(FormOutcome::Update(id, changes))) = control(&mut form, 's') else {
            panic!("not saved");
        };

        assert_eq!(id, "r-1");
        assert_eq!(changes.username.as_deref(), Some("addy"));
        assert_eq!(changes.name, None);
        assert_eq!(changes.uris, None);
        // An empty password keeps the current one.
        assert_eq!(changes.password, None);
    }

    #[test]
    fn test_control_g_asks_for_a_generated_password() {
        let mut form = Form::new_resource(None);

        assert!(matches!(control(&mut form, 'g'), Some(FormKey::Generate)));
    }

    #[test]
    fn test_a_generated_password_fills_the_password_field() {
        let mut form = Form::new_resource(None);

        form.set_password("generated".into());

        assert_eq!(form.value(Field::Password), "generated");
        assert_eq!(form.focus, Field::Password);
    }

    #[test]
    fn test_the_focus_wraps_around_the_fields() {
        let mut form = Form::new_resource(None);

        press(&mut form, KeyCode::Up);

        assert_eq!(form.focus, Field::Description);
    }
}
