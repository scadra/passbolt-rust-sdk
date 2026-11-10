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
┌ Folders ───────────┐┌ Resources (42) ────────────────────┐┌ Details ──────────────────────┐
│All items           ││AWS Console  admin@example.com      ││Name: AWS Console              │
│Ops                 ││GitLab  ada                         ││Username: admin@example.com    │
│  Databases         ││Postgres prod  postgres             ││URI: https://console.aws.ama…  │
│Personal            ││…                                   ││Password: •••••••• (s to show) │
└────────────────────┘└────────────────────────────────────┘└───────────────────────────────┘
Password of AWS Console copied, cleared in 30s.  [clipboard cleared in 27s]  ? help  q quit
```

The folders are a tree on the left; a folder lists its own resources, `All items` lists them
all. The details of the selected resource are on the right, its password hidden.

## Keys

| Key | Action |
|---|---|
| `↑` `↓`, `j` `k`, `PgUp` `PgDn`, `g` `G` | Move in the panel |
| `Tab`, `←` `→` | Switch between the folders and the resources |
| `/` | Search the name, username and URI in every folder; `Enter` keeps it, `Esc` clears it |
| `c`, `Enter` | Copy the password |
| `u` | Copy the username |
| `l` | Copy the URI |
| `t` | Copy the current TOTP code |
| `o` | Open the URI in the browser (`http` and `https` only) |
| `s` | Show or hide the password |
| `n` | New resource, in the selected folder |
| `e` | Edit the resource |
| `d`, `Delete` | Delete the resource, after `y` |
| `r` | Reload from the server |
| `?` | Help |
| `q`, `Esc` | Quit (the first one clears a search) |

In the form of `n` and `e`: `Tab` and the arrows move between the fields, `Ctrl+G` generates the
password from the [password policies](commands/generate.md) of the organization, `Ctrl+R` shows
it, `Ctrl+S` (or `Enter` on the last field) saves, `Esc` cancels. When editing, an empty
password keeps the current one, and only the fields changed are sent.

## Clipboard

A password or a TOTP code copied leaves the clipboard after 30 seconds, as in the browser
extension, unless something else was copied meanwhile; and when the UI quits. The status line
counts the seconds down.

Over SSH, or without a clipboard on the machine (a server without a desktop), the copy goes to
the clipboard of the terminal you type in, through its escape sequence (OSC 52). Most terminals
accept it: iTerm2, kitty, WezTerm, Windows Terminal, Alacritty, foot; tmux with
`set -g set-clipboard on`. Others ignore it: copy from the details with `s` then.

## Secrets

The list holds the decrypted names, usernames and URIs only. A secret is decrypted when it is
copied or shown, kept in memory zeroed once dropped, never written to the disk; another
resource selected hides it.

The deadline of `--timeout` does not apply: the UI runs until it quits. It is part of the
published binaries; a build from source leaves it out with `--no-default-features`.
