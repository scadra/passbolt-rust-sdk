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

//! The clipboard of the terminal UI: the system one, and over SSH the one of the terminal
//! the user types in (OSC 52). A copied secret is cleared after a while, as the extension does.

use std::io::Write;
use std::time::{Duration, Instant};

use base64::Engine;
use zeroize::Zeroizing;

/// How long a copied secret stays in the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

/// Where a copy went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Copied {
    /// The clipboard of this machine.
    System,
    /// The clipboard of the terminal, through its escape sequence: over SSH, or without a
    /// system clipboard. Not every terminal accepts it.
    Terminal,
}

pub struct Clipboard {
    system: Option<arboard::Clipboard>,
    over_ssh: bool,
    /// The secret copied and when, to clear it if it is still there.
    pending: Option<(Zeroizing<String>, Instant, Copied)>,
}

impl Clipboard {
    pub fn new() -> Self {
        Self {
            system: arboard::Clipboard::new().ok(),
            over_ssh: std::env::var_os("SSH_CONNECTION").is_some()
                || std::env::var_os("SSH_TTY").is_some(),
            pending: None,
        }
    }

    /// Copy `text`; a `secret` is cleared after [`CLEAR_AFTER`].
    pub fn copy(&mut self, text: &str, secret: bool) -> Copied {
        let on_system = !self.over_ssh
            && self
                .system
                .as_mut()
                .is_some_and(|system| system.set_text(text.to_string()).is_ok());
        let copied = if on_system {
            Copied::System
        } else {
            osc52(text);
            Copied::Terminal
        };
        self.pending = secret.then(|| (Zeroizing::new(text.to_string()), Instant::now(), copied));
        copied
    }

    /// Clear the secret copied once its time is up: call it on each tick.
    pub fn tick(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|(_, copied_at, _)| copied_at.elapsed() >= CLEAR_AFTER)
        {
            self.clear();
        }
    }

    /// Clear the secret copied now, if the clipboard still holds it: on exit.
    pub fn clear(&mut self) {
        let Some((secret, _, copied)) = self.pending.take() else {
            return;
        };
        match (copied, &mut self.system) {
            (Copied::System, Some(system)) => {
                // Something copied since is the user's: kept.
                let still_ours = system
                    .get_text()
                    .is_ok_and(|current| Zeroizing::new(current).as_str() == secret.as_str());
                if still_ours {
                    let _ = system.clear();
                }
            }
            _ => osc52(""),
        }
    }

    /// The seconds before the copied secret is cleared, for the status line.
    pub fn seconds_left(&self) -> Option<u64> {
        self.pending
            .as_ref()
            .map(|(_, copied_at, _)| CLEAR_AFTER.saturating_sub(copied_at.elapsed()).as_secs())
    }
}

/// The escape sequence setting the clipboard of the terminal to `text`.
pub fn osc52_sequence(text: &str) -> Zeroizing<String> {
    let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(text));
    Zeroizing::new(format!("\x1b]52;c;{}\x07", encoded.as_str()))
}

fn osc52(text: &str) {
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(osc52_sequence(text).as_bytes());
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_terminal_gets_the_text_in_base64() {
        assert_eq!(
            osc52_sequence("hunter2").as_str(),
            "\x1b]52;c;aHVudGVyMg==\x07"
        );
    }

    #[test]
    fn test_an_empty_sequence_clears_the_terminal_clipboard() {
        assert_eq!(osc52_sequence("").as_str(), "\x1b]52;c;\x07");
    }
}
