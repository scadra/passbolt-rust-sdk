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

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use indicatif::ProgressBar;
use passbolt_sdk::exchange::{export, formats};
use passbolt_sdk::resource::list::list_resources;
use passbolt_sdk::resource::view::ResourceView;
use passbolt_sdk::types::Folder;
use secrecy::{ExposeSecret, SecretString};
use std::path::PathBuf;

use crate::keepass::export::{export_keepass, Credentials, KdbxVersion, TotpFormat};
use crate::util::output;
use crate::util::password::prompt_secret;
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
    /// Exports Passbolt to a CSV file of another password manager
    Csv(CsvArgs),
}

#[derive(Args, Debug)]
pub struct CsvArgs {
    /// The CSV format: csv-kdbx, csv-lastpass, csv-1password, csv-chromium, csv-bitwarden, csv-mozilla, csv-safari, csv-dashlane, csv-nordpass, csv-logmeonce, csv-netwrix
    #[arg(long, default_value = "csv-kdbx")]
    pub format: String,
    /// File name; default: passbolt-export-<date>.csv
    #[arg(short = 'f', long)]
    pub file: Option<PathBuf>,
    /// Export only this folder and its sub-folders (by ID); default: export all
    #[arg(long)]
    pub folder_id: Option<String>,
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
    /// not a terminal) unless a key file is given; an empty answer locks it without password
    #[arg(short = 'p', long)]
    pub password: Option<String>,
    /// Key file locking the `KeePass` File, with the password or alone
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    /// Where entries keep their TOTP: kdbx (the `TimeOtp` fields of `KeePass`) or kdbx-others
    /// (an otpauth URI in an otp field, as `KeePassXC`)
    #[arg(long, default_value = "kdbx-others", value_parser = TotpFormat::parse)]
    pub format: TotpFormat,
    /// KDBX format version: v3 (AES-KDF, KDBX 3.1) or v4 (Argon2, KDBX 4)
    #[arg(long, default_value = "v3", value_parser = KdbxVersion::parse)]
    pub kdbx_version: KdbxVersion,
    /// Export only this folder and its sub-folders (by ID); default: export all
    #[arg(long)]
    pub folder_id: Option<String>,
}

/// The resources to export, decrypted, and their folders: those of `folder_id` and below it,
/// else all.
pub async fn exported(
    client: &Client,
    folder_id: Option<&str>,
    workers: usize,
) -> Result<(Vec<ResourceView>, Vec<Folder>)> {
    let all_folders = client
        .get_folders(passbolt_sdk::FolderQuery::default())
        .await
        .context("Failed to fetch folders")?;
    let (query, folders) = match folder_id {
        Some(root_id) => {
            if !all_folders.iter().any(|folder| folder.id == root_id) {
                anyhow::bail!("folder {root_id} not found");
            }
            let subtree_ids = passbolt_sdk::collect_subtree_ids(root_id, &all_folders);
            let query = passbolt_sdk::ResourceQuery {
                folder_ids: subtree_ids.iter().cloned().collect(),
                ..Default::default()
            };
            let folders: Vec<Folder> = all_folders
                .into_iter()
                .filter(|folder| subtree_ids.contains(&folder.id))
                .collect();
            (query, folders)
        }
        None => (passbolt_sdk::ResourceQuery::default(), all_folders),
    };
    let progress = ProgressBar::new_spinner().with_message("Decrypting Resources");
    progress.enable_steady_tick(std::time::Duration::from_millis(100));
    let views = list_resources(client, query, &[], Some(workers))
        .await
        .context("getting Resources");
    progress.finish_and_clear();
    Ok((views?, folders))
}

/// Write the resources in a CSV file of `args.format`; those that do not decrypt are reported
/// and left out.
async fn export_csv(args: &CsvArgs, client: &Client, workers: usize, json: bool) -> Result<()> {
    let format = formats::named(&args.format)?;
    let file = args.file.clone().unwrap_or_else(|| {
        PathBuf::from(export::file_name(chrono::Local::now().date_naive(), "csv"))
    });
    let (views, folders) = exported(client, args.folder_id.as_deref(), workers).await?;
    let (readable, unreadable): (Vec<ResourceView>, Vec<ResourceView>) =
        views.into_iter().partition(|view| view.error.is_none());
    for view in &unreadable {
        eprintln!(
            "Skipping Export of Resource {} {} Because of: {}",
            view.id,
            view.name,
            view.error.as_deref().unwrap_or_default()
        );
    }
    let resources = export::external_resources(&readable, &folders);
    let content = zeroize::Zeroizing::new(export::write_csv(format, &resources));
    crate::keepass::export::save_replacing(&file, |handle| {
        std::io::Write::write_all(handle, content.as_bytes())
            .with_context(|| format!("Cannot write {}", file.display()))
    })?;
    if json {
        return output::print_json(&serde_json::json!({
            "file": file,
            "format": format.name,
            "resources": resources.len(),
        }));
    }
    println!(
        "Exported {} resources to {}",
        resources.len(),
        file.display()
    );
    Ok(())
}

pub async fn run(args: &ExportArgs, client: &Client, workers: usize, json: bool) -> Result<()> {
    match &args.format {
        ExportFormat::Csv(csv) => export_csv(csv, client, workers, json).await,
        ExportFormat::Keepass(keepass) => {
            let keyfile = keepass
                .keyfile
                .as_ref()
                .map(|path| {
                    std::fs::read(path).with_context(|| format!("Cannot read {}", path.display()))
                })
                .transpose()?
                .map(zeroize::Zeroizing::new);
            let master_password = match keepass.password.as_deref() {
                Some(password) if !password.is_empty() => {
                    SecretString::new(password.to_owned().into())
                }
                _ if keyfile.is_some() => SecretString::default(),
                // An empty answer locks the file without password; a closed stdin fails.
                _ => SecretString::new(prompt_secret("Enter KeePass Password:")?.into()),
            };
            let credentials = Credentials {
                password: Some(master_password.expose_secret())
                    .filter(|password| !password.is_empty()),
                keyfile: keyfile.as_deref().map(Vec::as_slice),
            };
            export_keepass(
                client,
                &keepass.file,
                &credentials,
                keepass.kdbx_version,
                keepass.format,
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
        let ExportFormat::Keepass(keepass) = command.format else {
            panic!("not a keepass export");
        };
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
