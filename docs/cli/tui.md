---
title: Terminal UI
sidebar_position: 8
---

# Terminal UI

`passbolt tui` browses the vault from the keyboard, in the terminal: to find a password and
copy it without typing a command, over SSH too. It logs in as the other commands do (see
[configuration](configuration.md) and [authentication](authentication.md)), loads the folders
and the resources, then opens on all of them.

```bash
passbolt tui
```

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
  The focused pane has a thick green border and takes more room; `f` shows it alone, `Esc`
  brings the others back. A list shows `n of m` at the bottom, the resources their scope
  (`[All items]`, the folder, or `/filter`) at the top.
- **The resources** carry a coloured badge for their type: `PASS` a password, `PASS+` a password
  with a TOTP, `TOTP` a TOTP alone, `NOTE` a note, `PIN` a PIN code, `FIELDS` custom fields,
  `ERR` a resource that could not be decrypted.
- **Details** shows the URIs, the folder, the type, personal or shared, the expiry (red once
  expired) and the date of the last change; **Secret** the password, hidden until `s`, and the
  note; **Metadata** the decrypted metadata as JSON.
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
| `q` | Quit |

## Commands

After `:`, then `Enter`:

| Command | Action |
|---|---|
| `copy [password\|username\|uri\|totp]` | Copy a field, the password by default |
| `open`, `show` | Open the URI, show or hide the secret |
| `new`, `edit`, `delete` | Create, edit or delete a resource |
| `filter <text>` | Filter; `filter` alone clears it |
| `tab <name\|number>` | Select a tab: `tab shared`, `tab 5` |
| `folder <name>` | Select the first folder whose name starts so: `folder data` |
| `fullscreen`, `f` | The focused pane alone |
| `reload`, `r` | Reload from the server |
| `help` | The help |
| `quit`, `q` | Quit |

## Forms

`n` and `e` open a form over the panes: `Tab` and the arrows move between the fields, `Ctrl+G`
generates the password from the [password policies](commands/generate.md) of the organization,
`Ctrl+R` shows it, `Ctrl+S` (or `Enter` on the last field) saves, `Esc` cancels. When editing,
an empty password keeps the current one, and only the fields changed are sent.

## Clipboard

A password or a TOTP code copied leaves the clipboard after 30 seconds, as in the browser
extension, unless something else was copied meanwhile; and when the UI quits. The status line
counts the seconds down.

Over SSH, or without a clipboard on the machine (a server without a desktop), the copy goes to
the clipboard of the terminal you type in, through its escape sequence (OSC 52). Most terminals
accept it: iTerm2, kitty, WezTerm, Windows Terminal, Alacritty, foot; tmux with
`set -g set-clipboard on`. Others ignore it: show the secret with `s` then.

## Secrets

The list holds the decrypted metadata only: names, usernames, URIs and the other metadata
fields. A secret is decrypted when it is copied or shown, kept in memory zeroed once dropped,
never written to the disk; another resource selected hides it.

The deadline of `--timeout` does not apply: the UI runs until it quits. It is part of the
published binaries; a build from source leaves it out with `--no-default-features`.
