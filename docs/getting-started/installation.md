---
title: Installation
sidebar_position: 1
---

# Installation

Install the `passbolt` CLI on Linux, macOS or Windows, or find the SDK package of your language.

The CLI is a single binary, `passbolt`, with nothing else to install: no OpenSSL, no runtime.

## 1. Pick your archive

Each [release](https://github.com/scadra/passbolt-rust-sdk/releases) holds one archive per
platform, named `passbolt-cli-<version>-<target>`:

| System | Processor | Target | Archive |
|---|---|---|---|
| Linux (glibc 2.35 or later: Ubuntu 22.04, Debian 12, RHEL 10…) | x86_64 | `x86_64-unknown-linux-gnu` | `.tar.gz` |
| Linux (glibc 2.35 or later) | ARM64 | `aarch64-unknown-linux-gnu` | `.tar.gz` |
| Any Linux: Alpine, older distributions, containers | x86_64 | `x86_64-unknown-linux-musl` (static) | `.tar.gz` |
| macOS 12 or later | Apple silicon | `aarch64-apple-darwin` | `.tar.gz` |
| macOS 12 or later | Intel | `x86_64-apple-darwin` | `.tar.gz` |
| Windows 10 or later | x86_64 | `x86_64-pc-windows-gnu` | `.zip` |

Run `uname -sm` to see your system and processor (`Linux x86_64`, `Darwin arm64`…). If there is
no binary for your platform (Windows on ARM, FreeBSD…), [build it from source](#build-from-source).
On Windows, follow [install on Windows](#install-on-windows) instead of steps 2 to 5.

## 2. Download the archive

On Linux and macOS, set the version and the target, then download the archive and the checksums:

```bash
VERSION=0.1.2
TARGET=x86_64-unknown-linux-gnu
BASE=https://github.com/scadra/passbolt-rust-sdk/releases/download/v$VERSION
curl -fLO "$BASE/passbolt-cli-$VERSION-$TARGET.tar.gz"
curl -fLO "$BASE/SHA256SUMS"
```

## 3. Check the checksum

`SHA256SUMS` lists the files of the release under `cli/` and `sdk/`. Compare the line of your
archive:

```bash
grep "passbolt-cli-$VERSION-$TARGET.tar.gz" SHA256SUMS | sed 's|  .*/|  |' | sha256sum --check
```

```text
passbolt-cli-…: OK
```

On macOS, use `shasum -a 256 --check` instead of `sha256sum --check`. If you get anything else
than `OK`, delete the archive and download it again.

## 4. Install the binary

Extract the archive and copy `passbolt` to a folder of your `PATH`, for every user:

```bash
tar xzf "passbolt-cli-$VERSION-$TARGET.tar.gz"
sudo install -m 755 "passbolt-cli-$VERSION-$TARGET/passbolt" /usr/local/bin/passbolt
```

Or install it for you only, without `sudo`:

```bash
mkdir -p ~/.local/bin
install -m 755 "passbolt-cli-$VERSION-$TARGET/passbolt" ~/.local/bin/passbolt
# If ~/.local/bin is not on your PATH yet (bash; zsh: ~/.zshrc):
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && . ~/.bashrc
```

:::note
On macOS, a binary downloaded with a browser (not `curl`) is quarantined, and macOS refuses to
open it. Lift the quarantine of that file:

```bash
xattr -d com.apple.quarantine /usr/local/bin/passbolt
```
:::

## 5. Check that it runs

```bash
passbolt --version
```

```text
passbolt version <version> (Built on <date> from Git SHA <sha>)
```

Then [configure it](quick-start.md): your server, your private key, and the server's identity.

## Install on Windows

1. In PowerShell, download, check and extract the archive:

   ```powershell
   $Version = "0.1.2"
   $Name = "passbolt-cli-$Version-x86_64-pc-windows-gnu"
   $Base = "https://github.com/scadra/passbolt-rust-sdk/releases/download/v$Version"
   Invoke-WebRequest "$Base/$Name.zip" -OutFile "$Name.zip"
   Invoke-WebRequest "$Base/SHA256SUMS" -OutFile SHA256SUMS
   # The two hashes must be the same:
   (Get-FileHash "$Name.zip" -Algorithm SHA256).Hash.ToLower()
   (Select-String "$Name.zip" SHA256SUMS).Line.Split(" ")[0]
   Expand-Archive "$Name.zip" -DestinationPath .
   ```

2. Put `passbolt.exe` in a folder of your own and add that folder to your user `PATH`:

   ```powershell
   $Bin = "$env:LOCALAPPDATA\Programs\passbolt"
   New-Item -ItemType Directory -Force $Bin | Out-Null
   Copy-Item "$Name\passbolt.exe" $Bin
   [Environment]::SetEnvironmentVariable("Path", "$([Environment]::GetEnvironmentVariable('Path', 'User'));$Bin", "User")
   ```

3. Open a new terminal and run `passbolt --version`. If Windows blocks a file downloaded with a
   browser, run `Unblock-File "$Bin\passbolt.exe"`.

:::caution
On Windows, the config file is not restricted to its owner as on Linux and macOS: it keeps the
permissions of your profile folder.
:::

## Shell completion

The completion script completes the commands, the entities and the options. Install it for your
shell:

```bash
# bash
passbolt completion bash | sudo tee /etc/bash_completion.d/passbolt > /dev/null
# zsh: a folder of your fpath, then compinit (restart the shell)
mkdir -p ~/.zfunc && passbolt completion zsh > ~/.zfunc/_passbolt
echo 'fpath=(~/.zfunc $fpath); autoload -Uz compinit && compinit' >> ~/.zshrc
# fish
passbolt completion fish > ~/.config/fish/completions/passbolt.fish
```

```powershell
# PowerShell: added to your profile
passbolt completion powershell >> $PROFILE
```

## Update or uninstall

To update, install the new archive over the old binary, as above. The configuration
(`~/.config/passbolt/config.toml`) is kept.

To uninstall, delete the binary. To also forget your settings and the private key they hold,
delete the configuration:

```bash
sudo rm /usr/local/bin/passbolt     # or ~/.local/bin/passbolt
rm -r ~/.config/passbolt
```

On macOS the configuration is in `~/Library/Application Support/passbolt`, on Windows in
`%APPDATA%\passbolt\config`. Run `passbolt --debug list resource` to print the file it uses.

## Build from source

Install Rust 1.88 or later with [rustup](https://rustup.rs), then build and install the CLI:

```bash
git clone https://github.com/scadra/passbolt-rust-sdk.git
cd passbolt-rust-sdk
cargo install --locked --path crates/passbolt-cli
```

`cargo install` puts `passbolt` in `~/.cargo/bin`, which is on your `PATH` once rustup is
installed.

- Add `--no-default-features` to leave the [terminal UI](../cli/tui.md) out.
- No OpenSSL or other system library is needed. On Linux, you need a C compiler (`gcc` or
  `clang`).

## Install the SDK

The CI builds the SDK packages for each release. The names below are those of the proof of
concept; each [language page](../sdk/README.md) tells how to use them.

| Language | Package |
|---|---|
| Rust | crates.io `switch-case-passbolt-sdk` (imported as `passbolt_sdk`) |
| JavaScript / TypeScript | npm `@switch-case/passbolt-sdk` |
| Python | PyPI `switch-case-passbolt-sdk` (imported as `passbolt`) |
| Java | Maven `io.github.scadra:passbolt-sdk` |
| Android | Maven `io.github.scadra:passbolt-sdk-android` (AAR) |
| .NET | NuGet `SwitchCase.Passbolt.Sdk` |
| Ruby | RubyGems `switch-case-passbolt-sdk` |
| Go | `github.com/scadra/passbolt-sdk-go` |
| Swift (iOS, macOS) | Swift package `https://github.com/scadra/passbolt-sdk-swift` |

## Next steps

- [Quick start](quick-start.md): connect the CLI to your server and read your first secret.
- [Configuration](../cli/configuration.md): every setting.
- [SDK overview](../sdk/README.md): call Passbolt from your application.
