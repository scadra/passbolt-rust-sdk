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

//! `passbolt tui`: browse, copy and edit the resources in the terminal.
//!
//! The list holds the decrypted metadata only; a secret is decrypted when it is copied or
//! shown, and kept in memory that is zeroed once dropped.

mod app;
mod clipboard;
mod form;
mod ui;

use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use passbolt_sdk::generator::{generate_secret, PasswordPolicies};
use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::types::{Folder, FolderTreeNode};
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::DefaultTerminal;
use zeroize::Zeroizing;

use crate::Client;
use app::{Action, App, Mode, Revealed};
use clipboard::{Clipboard, Copied, CLEAR_AFTER};
use form::FormOutcome;

/// How often the screen is drawn again without a key: the clipboard countdown.
const TICK: Duration = Duration::from_millis(250);

/// The folders, their tree and the resources, without their secrets.
async fn load(client: &Client) -> Result<(Vec<Folder>, Vec<FolderTreeNode>, Vec<ResourceView>)> {
    let folders = client
        .get_folders(passbolt_sdk::FolderQuery::default())
        .await
        .context("listing Folder")?;
    let tree = passbolt_sdk::build_folder_tree(&folders);
    let resources = passbolt_sdk::resource::list::list_resources(
        client,
        passbolt_sdk::ResourceQuery::default(),
        &[],
        None,
    )
    .await
    .context("listing Resource")?;
    Ok((folders, tree, resources))
}

pub async fn run(client: &Client) -> Result<()> {
    eprintln!("Loading the resources…");
    let (folders, tree, resources) = load(client).await?;
    let mut app = App::new(&folders, &tree, resources);
    let mut session = Session {
        client,
        clipboard: Clipboard::new(),
        policies: None,
    };
    // Restores the terminal on a panic too.
    let mut terminal = ratatui::init();
    let result = session.event_loop(&mut terminal, &mut app).await;
    session.clipboard.clear();
    ratatui::restore();
    result
}

/// What the actions need beyond the state of the app.
struct Session<'client> {
    client: &'client Client,
    clipboard: Clipboard,
    /// Read once, on the first generated password.
    policies: Option<PasswordPolicies>,
}

impl Session<'_> {
    async fn event_loop(&mut self, terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
        while !app.quit {
            terminal.draw(|frame| ui::draw(frame, app))?;
            self.clipboard.tick();
            app.clipboard_left = self.clipboard.seconds_left();
            if !event::poll(TICK)? {
                continue;
            }
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if let Some(action) = app.handle_key(key) {
                app.status = "Working…".into();
                terminal.draw(|frame| ui::draw(frame, app))?;
                if let Err(error) = self.perform(app, action).await {
                    app.status = format!("Error: {error:#}");
                }
            }
        }
        Ok(())
    }

    async fn perform(&mut self, app: &mut App, action: Action) -> Result<()> {
        match action {
            Action::CopyPassword(id) => {
                let view = passbolt_sdk::resource::get::get_resource_view(self.client, &id)
                    .await
                    .context("decrypting the secret")?;
                let Some(password) = view.password.map(Zeroizing::new) else {
                    app.status = format!("{} has no password.", view.name);
                    return Ok(());
                };
                let copied = self.clipboard.copy(&password, true);
                app.status = copied_message(&format!("Password of {}", view.name), copied, true);
            }
            Action::CopyUsername(id) => {
                self.copy_field(app, &id, "Username", |view| &view.username);
            }
            Action::CopyUri(id) => {
                self.copy_field(app, &id, "URI", |view| &view.uri);
            }
            Action::CopyTotp(id) => {
                let (code, ttl) = passbolt_sdk::resource::get::get_totp_code(self.client, &id)
                    .await
                    .context("generating the TOTP code")?;
                let copied = self.clipboard.copy(&code, true);
                app.status = format!(
                    "{} ({ttl}s left)",
                    copied_message(&format!("TOTP code of {}", app.name_of(&id)), copied, true)
                );
            }
            Action::OpenUri(id) => {
                let uri = app
                    .resources
                    .iter()
                    .find(|view| view.id == id)
                    .map(|view| view.uri.clone())
                    .unwrap_or_default();
                open_in_browser(&uri)?;
                app.status = format!("Opened {uri}");
            }
            Action::Reveal(id) => {
                let view = passbolt_sdk::resource::get::get_resource_view(self.client, &id)
                    .await
                    .context("decrypting the secret")?;
                app.revealed = Some(Revealed {
                    id,
                    password: Zeroizing::new(view.password.unwrap_or_default()),
                });
                app.status = "Shown: s hides it.".into();
            }
            Action::Delete(id) => {
                let name = app.name_of(&id);
                self.client
                    .delete_resource(&id)
                    .await
                    .context("deleting Resource")?;
                self.reload(app).await?;
                app.status = format!("{name} deleted.");
            }
            Action::Save(outcome) => self.save(app, outcome).await?,
            Action::Generate => self.generate(app).await?,
            Action::Refresh => {
                self.reload(app).await?;
                app.status = format!("{} resources.", app.resources.len());
            }
        }
        Ok(())
    }

    async fn save(&self, app: &mut App, outcome: FormOutcome) -> Result<()> {
        let done = match outcome {
            FormOutcome::Create(new) => {
                passbolt_sdk::resource::create::create_resource(self.client, &new)
                    .await
                    .context("creating resource")?;
                format!("{} created.", new.name)
            }
            FormOutcome::Update(id, changes) => {
                passbolt_sdk::resource::update::update_resource(self.client, &id, &changes)
                    .await
                    .context("updating resource")?;
                format!("{} updated.", app.name_of(&id))
            }
        };
        app.mode = Mode::Normal;
        self.reload(app).await?;
        app.status = done;
        Ok(())
    }

    /// A password from the policies of the organization, into the form.
    async fn generate(&mut self, app: &mut App) -> Result<()> {
        let policies = match self.policies.take() {
            Some(policies) => policies,
            None => self
                .client
                .get_password_policies()
                .await
                .context("reading the password policies")?,
        };
        let secret = generate_secret(&policies)?;
        self.policies = Some(policies);
        if let Mode::Form(form) = &mut app.mode {
            form.set_password(secret);
        }
        app.status = "Generated from the password policies: Ctrl+R shows it.".into();
        Ok(())
    }

    fn copy_field(
        &mut self,
        app: &mut App,
        id: &str,
        label: &str,
        field: fn(&ResourceView) -> &String,
    ) {
        let Some(value) = app.resources.iter().find(|view| view.id == id).map(field) else {
            return;
        };
        if value.is_empty() {
            app.status = format!("No {}.", label.to_lowercase());
            return;
        }
        let copied = self.clipboard.copy(value, false);
        app.status = copied_message(label, copied, false);
    }

    async fn reload(&self, app: &mut App) -> Result<()> {
        let (_, tree, resources) = load(self.client).await?;
        let folder_id = app.selected_folder_id();
        app.folders = app::folder_rows(&tree);
        app.folder_index = app
            .folders
            .iter()
            .position(|row| row.id == folder_id)
            .unwrap_or(0);
        app.set_resources(resources);
        Ok(())
    }
}

fn copied_message(what: &str, copied: Copied, secret: bool) -> String {
    let place = match copied {
        Copied::System => "copied",
        Copied::Terminal => "copied to the terminal clipboard",
    };
    if secret {
        format!("{what} {place}, cleared in {}s.", CLEAR_AFTER.as_secs())
    } else {
        format!("{what} {place}.")
    }
}

/// Open `uri` in the browser of this machine: web addresses only, never a program.
fn open_in_browser(uri: &str) -> Result<()> {
    let uri = uri.trim();
    if !(uri.starts_with("https://") || uri.starts_with("http://")) {
        bail!("only http and https URIs are opened");
    }
    let mut command = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        let mut command = Command::new("rundll32");
        command.arg("url.dll,FileProtocolHandler");
        command
    } else {
        Command::new("xdg-open")
    };
    command
        .arg(uri)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("opening the browser")?;
    Ok(())
}

/// A resource view made of v4 fields, for the tests.
#[cfg(test)]
pub fn test_view(resource: serde_json::Value) -> ResourceView {
    ResourceView::new(serde_json::from_value(resource).unwrap(), None, &[]).unwrap()
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::program("file:///bin/sh")]
    #[case::script("javascript:alert(1)")]
    #[case::empty("")]
    fn test_only_web_addresses_are_opened(#[case] uri: &str) {
        let error = open_in_browser(uri).unwrap_err();

        assert!(error.to_string().contains("only http"), "{error}");
    }

    #[test]
    fn test_a_copied_secret_says_when_it_is_cleared() {
        let message = copied_message("Password of GitHub", Copied::System, true);

        assert_eq!(message, "Password of GitHub copied, cleared in 30s.");
    }
}
