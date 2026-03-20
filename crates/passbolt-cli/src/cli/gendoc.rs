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

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, CommandFactory};

use crate::cli::root::Cli;

/// Write the documentation of every command, as go-passbolt-cli's `gendoc` does: one markdown
/// file per command in `./doc`, or one man page per command in `./man`.
#[derive(Args, Debug)]
pub struct GendocArgs {
    /// What to generate: markdown or man
    #[arg(
        short = 't',
        long = "type",
        alias = "doc-type",
        default_value = "markdown",
        value_parser = ["markdown", "man"]
    )]
    pub doc_type: String,

    /// Directory to write into, created if absent [default: ./doc for markdown, ./man for man]
    #[arg(short = 'o', long)]
    pub output_dir: Option<PathBuf>,
}

pub fn run_gendoc(args: &GendocArgs) -> Result<()> {
    let default_directory = if args.doc_type == "man" { "man" } else { "doc" };
    let output_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(default_directory));
    std::fs::create_dir_all(&output_dir)?;
    let mut command = Cli::command();
    command.build();
    if args.doc_type == "man" {
        generate_man_recursive(&command, &output_dir, &[command.get_name().to_string()])
    } else {
        generate_markdown_recursive(&command, &output_dir, &[])
    }
}

/// clap's placeholder for the options section of a help.
#[allow(clippy::literal_string_with_formatting_args)]
const OPTIONS_TEMPLATE: &str = "{options}";

fn documented_subcommands(command: &clap::Command) -> impl Iterator<Item = &clap::Command> {
    command
        .get_subcommands()
        .filter(|subcommand| subcommand.get_name() != "help" && !subcommand.is_hide_set())
}

/// One page per command, as cobra's `GenMarkdownTree` writes it, links without `.md`.
fn generate_markdown_recursive(
    command: &clap::Command,
    output_dir: &Path,
    parents: &[&clap::Command],
) -> Result<()> {
    let path_names: Vec<&str> = parents
        .iter()
        .chain(std::iter::once(&command))
        .map(|command| command.get_name())
        .collect();
    std::fs::write(
        output_dir.join(format!("{}.md", path_names.join("_"))),
        markdown_page(command, parents, &path_names),
    )?;
    let mut lineage = parents.to_vec();
    lineage.push(command);
    for subcommand in documented_subcommands(command) {
        generate_markdown_recursive(subcommand, output_dir, &lineage)?;
    }
    Ok(())
}

fn markdown_page(
    command: &clap::Command,
    parents: &[&clap::Command],
    path_names: &[&str],
) -> String {
    let full_name = path_names.join(" ");
    let about = command
        .get_about()
        .map(ToString::to_string)
        .unwrap_or_default();
    let long_about = command
        .get_long_about()
        .map_or_else(|| about.clone(), ToString::to_string);
    let usage = command
        .clone()
        .bin_name(&full_name)
        .render_usage()
        .to_string();
    let options = command
        .clone()
        .help_template(OPTIONS_TEMPLATE)
        .render_help()
        .to_string();

    let mut page = format!("## {full_name}\n\n{about}\n\n### Synopsis\n\n{long_about}\n\n```\n");
    let _ = writeln!(page, "{}", usage.trim_start_matches("Usage: "));
    page.push_str("```\n\n");
    if !options.trim().is_empty() {
        let _ = write!(page, "### Options\n\n```\n{}\n```\n\n", options.trim_end());
    }
    page.push_str("### SEE ALSO\n\n");
    if let Some(parent) = parents.last() {
        let parent_names = &path_names[..path_names.len() - 1];
        let _ = writeln!(
            page,
            "* [{}]({})\t - {}",
            parent_names.join(" "),
            parent_names.join("_"),
            parent
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default()
        );
    }
    for subcommand in documented_subcommands(command) {
        let _ = writeln!(
            page,
            "* [{full_name} {}]({}_{})\t - {}",
            subcommand.get_name(),
            path_names.join("_"),
            subcommand.get_name(),
            subcommand
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default()
        );
    }
    page
}

fn generate_man_recursive(
    command: &clap::Command,
    output_dir: &Path,
    ancestors: &[String],
) -> Result<()> {
    let name = ancestors.join("-");
    let man = clap_mangen::Man::new(command.clone()).title(name.clone());
    let mut rendered = Vec::new();
    man.render(&mut rendered)?;
    std::fs::write(output_dir.join(format!("{name}.1")), &rendered)?;

    for subcommand in documented_subcommands(command) {
        let mut subcommand_ancestors = ancestors.to_vec();
        subcommand_ancestors.push(subcommand.get_name().to_string());
        generate_man_recursive(subcommand, output_dir, &subcommand_ancestors)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markdown_links_the_parent_and_the_children_without_extension() {
        let directory = tempfile::tempdir().unwrap();
        let args = GendocArgs {
            doc_type: "markdown".into(),
            output_dir: Some(directory.path().to_path_buf()),
        };

        run_gendoc(&args).unwrap();

        let root = std::fs::read_to_string(directory.path().join("passbolt.md")).unwrap();
        assert!(root.starts_with("## passbolt\n"), "{root}");
        assert!(root.contains("(passbolt_create)"), "{root}");
        let create = std::fs::read_to_string(directory.path().join("passbolt_create.md")).unwrap();
        assert!(create.contains("* [passbolt](passbolt)"), "{create}");
        assert!(create.contains("(passbolt_create_resource)"), "{create}");
        assert!(directory
            .path()
            .join("passbolt_create_resource.md")
            .exists());
    }
}
