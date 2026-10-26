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

use anyhow::Result;
use clap::{Args, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use std::path::PathBuf;

use crate::keepass::export::{export_keepass, KdbxVersion};
use crate::util::password::read_password;
use crate::Client;

#[derive(Args, Debug)]
pub struct ExportArgs {
    #[command(subcommand)]
    pub format: ExportFormat,
}

#[derive(Subcommand, Debug)]
pub enum ExportFormat {
    /// Exports Passbolt to a `KeePass` File
    Keepass(KeepassArgs),
}

#[derive(Args, Debug)]
pub struct KeepassArgs {
    /// File name of the `KeePass` File
    #[arg(
        short = 'f',
        long,
        alias = "output",
        short_alias = 'o',
        default_value = "passbolt-export.kdbx"
    )]
    pub file: PathBuf,
    /// Password for the `KeePass` File, if empty prompts interactively (reads stdin when it is
    /// not a terminal). An empty password is refused: the file would have no credentials
    #[arg(short = 'p', long)]
    pub password: Option<String>,
    /// KDBX format version: v3 (AES-KDF, KDBX 3.1) or v4 (Argon2, KDBX 4)
    #[arg(long, default_value = "v3", value_parser = KdbxVersion::parse)]
    pub kdbx_version: KdbxVersion,
    /// Export only this folder and its sub-folders (by ID); default: export all
    #[arg(long)]
    pub folder_id: Option<String>,
}

pub async fn run(args: &ExportArgs, client: &Client, workers: usize) -> Result<()> {
    match &args.format {
        ExportFormat::Keepass(keepass) => {
            let master_password = match keepass.password.as_deref() {
                Some(password) if !password.is_empty() => {
                    SecretString::new(password.to_owned().into())
                }
                _ => read_password("Enter KeePass Password:")?,
            };
            export_keepass(
                client,
                &keepass.file,
                master_password.expose_secret(),
                keepass.kdbx_version,
                keepass.folder_id.as_deref(),
                workers,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(subcommand)]
        format: ExportFormat,
    }

    fn parse(arguments: &[&str]) -> Result<KeepassArgs, clap::Error> {
        let command = Command::try_parse_from(std::iter::once(&"export").chain(arguments))?;
        let ExportFormat::Keepass(keepass) = command.format;
        Ok(keepass)
    }

    #[test]
    fn test_keepass_defaults_match_go_passbolt_cli() {
        let keepass = parse(&["keepass"]).unwrap();

        assert_eq!(keepass.file, PathBuf::from("passbolt-export.kdbx"));
        assert_eq!(keepass.kdbx_version, KdbxVersion::V3);
        assert_eq!(keepass.password, None);
        assert_eq!(keepass.folder_id, None);
    }

    #[test]
    fn test_keepass_reads_the_go_short_flags() {
        let keepass = parse(&["keepass", "-f", "x.kdbx", "-p", "pw"]).unwrap();

        assert_eq!(keepass.file, PathBuf::from("x.kdbx"));
        assert_eq!(keepass.password.as_deref(), Some("pw"));
    }

    #[rstest::rstest]
    #[case(&["keepass", "--output", "old.kdbx"])]
    #[case(&["keepass", "-o", "old.kdbx"])]
    fn test_keepass_keeps_output_as_an_alias_of_file(#[case] arguments: &[&str]) {
        assert_eq!(parse(arguments).unwrap().file, PathBuf::from("old.kdbx"));
    }

    #[test]
    fn test_keepass_reads_kdbx_version_four() {
        let keepass = parse(&["keepass", "--kdbx-version", "v4"]).unwrap();

        assert_eq!(keepass.kdbx_version, KdbxVersion::V4);
    }

    #[test]
    fn test_keepass_rejects_an_unknown_kdbx_version() {
        let error = parse(&["keepass", "--kdbx-version", "v5"]).unwrap_err();

        assert!(
            error
                .to_string()
                .contains(r#"invalid kdbx-version "v5": must be v3 or v4"#),
            "{error}"
        );
    }

    #[test]
    fn test_keepass_reads_the_folder_id() {
        let keepass = parse(&["keepass", "--folder-id", "folder"]).unwrap();

        assert_eq!(keepass.folder_id.as_deref(), Some("folder"));
    }
}
