---
title: Terminal UI
sidebar_position: 8
---

# Terminal UI

Browse your vault from the keyboard, find a password and copy it without typing a command, over
SSH too.

## Prerequisites

- The CLI configured to log in: see [configuration](configuration.md) and
  [authentication](authentication.md). `passbolt tui` logs in as the other commands do.
- A published binary, or a build from source with the default features: a build with
  `--no-default-features` leaves the terminal UI out.

## Open the terminal UI

```bash
passbolt tui
```

The UI loads the folders and the resources, then opens on all of them:

```text
  1 All  2 Favorites  3 Personal  4 Shared  5 Expired              [ passbolt • passbolt.example.com ]
┏Resources━━━━━━━━━━━━━━━━━━━━[All items]┓┌Details──────────────────────────────────────────────────┐
┃→ PASS   AWS Console  admin@example.com ┃│ PASS   AWS Console                                       │
┃  PASS+  GitLab  ada                    ┃│  Username  admin@example.com                             │
┃  NOTE   Recovery codes                 ┃│       URI  https://console.aws.amazon.com                │
┃  PIN    Office door                    ┃│    Folder  Ops                                           │
┃  TOTP   Grafana 2FA                    ┃│    Access  shared                                        │
┃                                        ┃└──────────────────────────────────────────────────────────┘
┃                                        ┃┌Secret────────────────────────────────────────────────────┐
┃                                 1 of 42┃│  Password  ••••••••  s shows it                          │
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛└─────────────────────────── [c copy] [s show] [t TOTP] ┘
┌Folders─────────────────────────────────┐┌Metadata─────────────────────────────────────[decrypted]┐
│→ All items  42                         ││{                                                         │
│  Ops  12                               ││  "name": "AWS Console",                                  │
│    Databases  3                        ││  "username": "admin@example.com",                        │
└──────────────────────────────────1 of 3┘└───────────────────────────────────────── [j,k scroll] ┘
Password of AWS Console copied, cleared in 30s.          clipboard cleared in 27s  [N]
```

## The screen

- **The header** holds the tabs on the left and the server on the right.
- **The panes**: Resources and Folders on the left; Details, Secret and Metadata on the right.
  The focused pane has a thick green border and takes more room. `f` shows it alone, `Esc`
  brings the others back.
- **The lists** show `n of m` at the bottom. The resources show their scope at the top:
  `[All items]`, the folder, or `/filter`.
- **The resources** carry a coloured badge for their type:

  | Badge | Type |
  |---|---|
  | `PASS` | A password |
  | `PASS+` | A password with a TOTP |
  | `TOTP` | A TOTP alone |
  | `NOTE` | A note |
  | `PIN` | A PIN code |
  | `FIELDS` | Custom fields |
  | `ERR` | A resource that could not be decrypted |

- **Details** shows the URIs, the folder, the type, personal or shared, the expiry (red once
  expired) and the date of the last change.
- **Secret** shows the password, hidden until you press `s`, and the note.
- **Metadata** shows the decrypted metadata as JSON.
- **The status line** shows the message of the last action for a few seconds, the countdown of
  the clipboard, and the mode: `[N]` normal, `[I]` typing (a form, the filter), `[C]` a command.

## Keys

| Key | Action |
|---|---|
| `l` `→` `Tab`, `h` `←` `Shift+Tab` | Next, previous pane |
| `j` `↓`, `k` `↑`, `PgDn` `PgUp`, `Home` `End` | Move in the list; scroll the metadata |
| `1`…`5`, `]` `[` | Tabs: All, Favorites, Personal, Shared, Expired |
| `f` | The focused pane alone; `Esc` to come back |
| `g` `Enter`, `b` `Backspace` | In the folders: into the resources of the folder, back to the parent folder |
| `/` | Filter by name, username or URI in every folder; `Enter` keeps it, `Esc` clears it |
| `:` | Command line (below); `↑` `↓` bring the last commands back |
| `c` `Enter` | Copy the password |
| `u` | Copy the username |
| `a` | Copy the URI |
| `t` | Copy the current TOTP code |
| `o` | Open the URI in the browser (`http` and `https` only) |
| `s` | Show or hide the secret |
| `n` | New resource, in the selected folder |
| `e` | Edit the resource |
| `d` `Delete` | Delete the resource, after `y` |
| `r` | Reload from the server |
| `?` | Help: the keys and the commands |
| `q`, `Ctrl+C` | Quit |

## Commands

Press `:`, type the command, then press `Enter`:

| Command | Action |
|---|---|
| `copy [password\|username\|uri\|totp]` | Copy a field, the password by default. `c` is short for `copy`; `user` and `url` work too. |
| `open`, `show` | Open the URI, show or hide the secret |
| `new`, `edit`, `delete` | Create, edit or delete a resource |
| `filter <text>` | Filter; `filter` alone clears it |
| `tab <name\|number>` | Select a tab: `tab shared`, `tab 5` |
| `folder <name>` | Select the first folder whose name starts so: `folder data` |
| `fullscreen`, `f` | The focused pane alone |
| `reload`, `r` | Reload from the server |
| `help` | The help |
| `quit`, `q` | Quit |

## Create and edit a resource

`n` and `e` open a form over the panes:

| Key | Action |
|---|---|
| `Tab`, arrows | Move between the fields |
| `Ctrl+G` | Generate the password from the [password policies](commands/generate.md) of the organization |
| `Ctrl+R` | Show or hide the password |
| `Ctrl+S`, or `Enter` on the last field | Save |
| `Esc` | Cancel |

When you edit a resource, an empty password keeps the current one, and only the fields you
changed are sent.

## Clipboard

A password or a TOTP code you copy leaves the clipboard after 30 seconds, as in the browser
extension, unless something else was copied meanwhile. It also leaves when the UI quits. The
status line counts the seconds down.

Over SSH, or without a clipboard on the machine (a server without a desktop), the copy goes to
the clipboard of the terminal you type in, through its escape sequence (OSC 52).

- Most terminals accept it: iTerm2, kitty, WezTerm, Windows Terminal, Alacritty, foot.
- In tmux, set `set -g set-clipboard on`.
- Others ignore it: show the secret with `s` instead.

## Secrets

- The list holds the decrypted metadata only: names, usernames, URIs and the other metadata
  fields.
- A secret is decrypted when you copy or show it. It is kept in memory, zeroed once dropped, and
  never written to the disk. Selecting another resource hides it.
- The deadline of `--timeout` does not apply: the UI runs until you quit.

## Related

- [Commands](commands/README.md): the same actions from the command line.
- [Generate](commands/generate.md): the password policies.
- [Security](../security.md#the-terminal-ui): how the UI handles secrets.
- [Troubleshooting](troubleshooting.md#clipboard-in-the-terminal-ui): a copy that does nothing.
