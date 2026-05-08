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

use crate::util::output;
use crate::Client;

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// The CSV file to import; its format is recognised from its columns
    #[arg(short = 'f', long)]
    pub file: PathBuf,
    /// Put every resource at the root of the import folder, without the folders of the file
    #[arg(long)]
    pub no_folders: bool,
    /// Do not tag the imported resources with the name of the import
    #[arg(long)]
    pub no_tags: bool,
}

/// Import the file into a new `import-<date>` folder; fails when a row was not imported.
pub async fn run(args: &ImportArgs, client: &Client, json: bool) -> Result<()> {
    let text = std::fs::read_to_string(&args.file)
        .with_context(|| format!("Cannot read {}", args.file.display()))?;
    let types = client.resource_types().await?;
    let v5 = client
        .metadata_settings()
        .await?
        .types
        .creates_v5_resources_by_default();
    let parsed = import::parse_csv(&text, &types, v5, import::reference(chrono::Utc::now()))?;
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
