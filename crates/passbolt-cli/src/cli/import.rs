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

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use passbolt_sdk::exchange::import::{self, ImportOptions, ImportReport};

use crate::keepass;
use crate::util::output;
use crate::Client;

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// The CSV or KDBX file to import; a CSV format is recognised from its columns
    #[arg(short = 'f', long)]
    pub file: PathBuf,
    /// The password of the KDBX file
    #[arg(short = 'p', long)]
    pub password: Option<String>,
    /// The key file of the KDBX file
    #[arg(long)]
    pub keyfile: Option<PathBuf>,
    /// Put every resource at the root of the import folder, without the folders of the file
    #[arg(long)]
    pub no_folders: bool,
    /// Do not tag the imported resources with the name of the import
    #[arg(long)]
    pub no_tags: bool,
}

/// Import the file into a new `import-<date>` folder; fails when a row was not imported.
pub async fn run(args: &ImportArgs, client: &Client, json: bool) -> Result<()> {
    let file =
        std::fs::read(&args.file).with_context(|| format!("Cannot read {}", args.file.display()))?;
    let types = client.resource_types().await?;
    let v5 = client
        .metadata_settings()
        .await?
        .types
        .creates_v5_resources_by_default();
    let reference = import::reference(chrono::Utc::now());
    let is_kdbx = args
        .file
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("kdbx"));
    let parsed = if is_kdbx {
        let keyfile = args
            .keyfile
            .as_ref()
            .map(|path| {
                std::fs::read(path).with_context(|| format!("Cannot read {}", path.display()))
            })
            .transpose()?;
        let database = keepass::import::open(&file, args.password.as_deref(), keyfile.as_deref())?;
        let content = keepass::import::read(&database, v5);
        let mut parsed = import::assemble(
            content.resources.into_iter(),
            &content.folders,
            &types,
            v5,
            reference,
        );
        parsed.warnings.splice(0..0, content.warnings);
        parsed
    } else {
        let text = String::from_utf8(file).context("The CSV file is not UTF-8")?;
        import::parse_csv(&text, &types, v5, reference)?
    };
    let options = ImportOptions {
        folders: !args.no_folders,
        tags: !args.no_tags,
    };
    let report = import::import(client, parsed, options).await?;
    if json {
        output::print_json(&report)?;
    } else {
        print_report(&report);
    }
    if !report.errors.is_empty() {
        anyhow::bail!("{} items were not imported", report.errors.len());
    }
    Ok(())
}

fn print_report(report: &ImportReport) {
    println!(
        "Imported {} resources and {} folders in {}",
        report.resources, report.folders, report.reference
    );
    for warning in &report.warnings {
        eprintln!(
            "Warning: {}: {} ({})",
            warning.title, warning.item, warning.detail
        );
    }
    for error in &report.errors {
        eprintln!("{}: {} ({})", error.title, error.item, error.detail);
    }
}
