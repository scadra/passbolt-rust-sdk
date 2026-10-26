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

mod cli;
mod config;
mod keepass;
mod util;

use std::io::Write;
use std::process::ExitCode;

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches};
use clap_complete::generate;

use cli::root::{
    Cli, Commands, CreateEntity, DeleteEntity, GetEntity, ListEntity, MoveEntity, ShareEntity,
    UpdateEntity,
};
use config::Config;
use util::{output, session};

/// Type alias for the concrete SDK client used by the CLI.
pub type Client = passbolt_sdk::PassboltSdk<passbolt_sdk::NativeHttpClient>;

/// As go-passbolt-cli: `Error: <message>` and exit code 1 for any error, usage errors included;
/// help, version, and no arguments at all print on stdout and exit 0.
#[tokio::main]
async fn main() -> ExitCode {
    let cli = match parse_arguments() {
        Ok(cli) => cli,
        Err(code) => return code,
    };
    match Box::pin(run(cli)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn parse_arguments() -> Result<Cli, ExitCode> {
    use clap::error::ErrorKind;

    let parsed = help_when_incomplete(Cli::command())
        .try_get_matches()
        .and_then(|matches| Cli::from_arg_matches(&matches));
    match parsed {
        Ok(cli) => Ok(cli),
        Err(error) => match error.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                let _ = error.print();
                Err(ExitCode::SUCCESS)
            }
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                print!("{}", error.render());
                Err(ExitCode::SUCCESS)
            }
            _ => {
                let _ = error.print();
                Err(ExitCode::FAILURE)
            }
        },
    }
}

/// A command with subcommands prints its help when given nothing, as cobra does.
fn help_when_incomplete(command: clap::Command) -> clap::Command {
    let names: Vec<String> = command
        .get_subcommands()
        .map(|subcommand| subcommand.get_name().to_string())
        .collect();
    let has_subcommands = !names.is_empty();
    let mut command = command;
    for name in names {
        command = command.mut_subcommand(name, help_when_incomplete);
    }
    command.arg_required_else_help(has_subcommands)
}

async fn run(cli: Cli) -> Result<()> {
    if let Some(path) = &cli.config {
        Config::set_path(path.into());
    }

    match &cli.command {
        Commands::Completion { shell } => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            let mut script = Vec::new();
            generate(*shell, &mut command, name, &mut script);
            return write_ignoring_closed_pipe(&script);
        }
        Commands::Gendoc(args) => return cli::gendoc::run_gendoc(args),
        _ => {}
    }

    let mut config = load_config(&cli)?;
    match &cli.command {
        Commands::Configure(args) => cli::configure::run(args, &config),
        Commands::Verify(args) => {
            session::require_credentials(&mut config)?;
            Box::pin(with_deadline(&config, cli::verify::run(args, &config))).await
        }
        command => {
            session::require_credentials(&mut config)?;
            let workers = config.worker_count();
            let work = async {
                let client = session::get_client(&config).await?;
                let result = dispatch(command, &client, cli.json, workers).await;
                session::finish(&client).await;
                result
            };
            // The command run by `exec` takes the time it needs.
            if matches!(command, Commands::Exec(_)) {
                work.await
            } else {
                with_deadline(&config, work).await
            }
        }
    }
}

/// Write to stdout; a reader that stopped reading (`| head`) is not an error.
fn write_ignoring_closed_pipe(bytes: &[u8]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        result => Ok(result?),
    }
}

/// `--timeout` bounds the whole command too, as go-passbolt-cli's context does.
async fn with_deadline(
    config: &Config,
    work: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    match config.timeout_duration()? {
        Some(limit) => tokio::time::timeout(limit, work).await.map_err(|_| {
            anyhow::anyhow!("context deadline exceeded (--timeout {})", config.timeout)
        })?,
        None => work.await,
    }
}

/// Load the config file and environment, then apply the command-line flags over them.
fn load_config(cli: &Cli) -> Result<Config> {
    Config::load_with(&apply_cli_overrides(cli))
}

/// The settings given as flags, by setting name.
fn apply_cli_overrides(cli: &Cli) -> Vec<(&'static str, String)> {
    for (given, flag, replacement) in [
        (cli.totp_token.is_some(), "totpToken", "mfaTotpToken"),
        (cli.totp_offset.is_some(), "totpOffset", "mfaTotpOffset"),
    ] {
        if given {
            eprintln!("Flag --{flag} has been deprecated, use --{replacement} instead");
        }
    }
    let texts = [
        ("server_address", cli.server_address.clone()),
        ("user_private_key", cli.user_private_key.clone()),
        ("user_private_key_file", cli.user_private_key_file.clone()),
        ("user_password", cli.user_password.clone()),
        ("mfa_mode", cli.mfa_mode.clone()),
        ("mfa_totp_token", cli.mfa_totp_token.clone()),
        ("totp_token", cli.totp_token.clone()),
        ("mfa_totp_offset", cli.mfa_totp_offset.clone()),
        ("totp_offset", cli.totp_offset.clone()),
        ("mfa_retrys", cli.mfa_retrys.map(|value| value.to_string())),
        ("mfa_delay", cli.mfa_delay.clone()),
        (
            "tls_skip_verify",
            cli.tls_skip_verify.map(|value| value.to_string()),
        ),
        ("tls_client_cert", cli.tls_client_cert.clone()),
        ("tls_client_private_key", cli.tls_client_private_key.clone()),
        ("tls_client_cert_file", cli.tls_client_cert_file.clone()),
        (
            "tls_client_private_key_file",
            cli.tls_client_private_key_file.clone(),
        ),
        ("proxy", cli.proxy.clone()),
        ("resolve", cli.resolve.clone()),
        ("timeout", cli.timeout.clone()),
        ("workers", cli.workers.map(|value| value.to_string())),
        ("debug", cli.debug.map(|value| value.to_string())),
    ];
    texts
        .into_iter()
        .filter_map(|(name, value)| Some((name, value?)))
        .collect()
}

fn parse_filters(expressions: &[String]) -> Result<Vec<passbolt_sdk::filter::Filter>> {
    expressions
        .iter()
        .map(|expression| passbolt_sdk::filter::Filter::parse(expression))
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

fn parse_expiry_opt(expiry: Option<&String>) -> Result<Option<serde_json::Value>> {
    expiry
        .map(String::as_str)
        .map(passbolt_sdk::resource::expiry::parse_expiry)
        .transpose()
        .map_err(Into::into)
}

#[allow(clippy::too_many_lines)]
async fn dispatch(
    command: &Commands,
    client: &Client,
    json_output: bool,
    workers: usize,
) -> Result<()> {
    match command {
        // ── Create ──────────────────────────────────────────────────────────
        Commands::Create(args) => match &args.entity {
            CreateEntity::Resource {
                resource_type,
                name,
                username,
                uri,
                password,
                description,
                note,
                pin_code,
                field,
                secret_field,
                folder_parent_id,
                expiry,
                totp_key,
                totp_algo,
                totp_digits,
                totp_period,
            } => {
                use passbolt_sdk::resource::create::NewResource;
                use secrecy::ExposeSecret;
                use util::password::read_password;

                let totp = totp_key.as_ref().map(|key| passbolt_sdk::types::TotpData {
                    secret_key: Some(key.clone()),
                    algorithm: totp_algo.clone(),
                    digits: *totp_digits,
                    period: *totp_period,
                    issuer: None,
                });

                let needs_password = resource_type.as_deref().map_or_else(
                    || {
                        totp.is_none()
                            && pin_code.is_none()
                            && note.is_none()
                            && secret_field.is_empty()
                    },
                    passbolt_sdk::resource::create::requires_password,
                );
                let resolved_password = match password {
                    Some(provided_password) => Some(provided_password.clone()),
                    None if needs_password => {
                        Some(read_password("Password: ")?.expose_secret().to_string())
                    }
                    None => None,
                };

                let new_resource = NewResource {
                    resource_type: resource_type.clone(),
                    name: name.clone(),
                    username: username.clone(),
                    uris: uri.clone(),
                    description: description.clone(),
                    note: note.clone(),
                    password: resolved_password,
                    totp,
                    pin_code: pin_code.clone(),
                    folder_parent_id: folder_parent_id.clone(),
                    expired: parse_expiry_opt(expiry.as_ref())?
                        .and_then(|expiry| expiry.as_str().map(String::from)),
                    metadata_fields: util::resources::parse_fields(field)?,
                    secret_fields: util::resources::parse_fields(secret_field)?,
                    ..NewResource::default()
                };
                let resource =
                    passbolt_sdk::resource::create::create_resource(client, &new_resource).await?;

                if json_output {
                    output::print_json(&resource)?;
                } else {
                    println!("Created resource: {name} ({})", resource.id);
                }
            }

            CreateEntity::Folder {
                name,
                folder_parent_id,
            } => {
                let folder = passbolt_sdk::folder::create::create_folder(
                    client,
                    name,
                    folder_parent_id.as_deref(),
                )
                .await?;
                if json_output {
                    output::print_json(&folder)?;
                } else {
                    println!("Created folder: {} ({})", folder.name, folder.id);
                }
            }

            CreateEntity::User {
                username,
                firstname,
                lastname,
                role,
            } => {
                let user = passbolt_sdk::user::create::create_user(
                    client, username, firstname, lastname, role,
                )
                .await?;
                if json_output {
                    output::print_json(&user)?;
                } else {
                    println!(
                        "Created user: {} ({})",
                        user.username.as_deref().unwrap_or(""),
                        user.id
                    );
                }
            }

            CreateEntity::Group {
                name,
                user,
                manager,
            } => {
                if manager.is_empty() {
                    anyhow::bail!("At least one --manager is required");
                }
                let group =
                    passbolt_sdk::group::create::create_group(client, name, user, manager).await?;
                if json_output {
                    output::print_json(&group)?;
                } else {
                    println!("Created group: {} ({})", group.name, group.id);
                }
            }
        },

        // ── Get ─────────────────────────────────────────────────────────────
        Commands::Get(args) => match &args.entity {
            GetEntity::Resource { id } => {
                let view = passbolt_sdk::resource::get::get_resource_view(client, id).await?;
                if json_output {
                    output::print_json(&view)?;
                } else {
                    let rows = util::resources::detail_rows(&view);
                    let pairs: Vec<(&str, &str)> = rows
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .collect();
                    output::print_kv(&pairs);
                }
            }

            GetEntity::ResourcePermissions { id, column } => {
                let permissions =
                    passbolt_sdk::resource::get::get_resource_permissions(client, id).await?;
                util::columns::print(
                    &permissions,
                    &util::columns::PERMISSION_COLUMNS,
                    column,
                    &util::columns::PERMISSION_DEFAULTS,
                    json_output,
                )?;
            }

            GetEntity::Folder { id } => {
                let folder = client.get_folder(id).await?;
                if json_output {
                    output::print_json(&folder)?;
                } else {
                    output::print_kv(&[
                        ("ID", &folder.id),
                        ("Name", &folder.name),
                        (
                            "Parent",
                            folder.folder_parent_id.as_deref().unwrap_or("(root)"),
                        ),
                    ]);
                }
            }

            GetEntity::FolderPermissions { id, column } => {
                let permissions = client.get_folder_permissions(id).await?;
                util::columns::print(
                    &permissions,
                    &util::columns::PERMISSION_COLUMNS,
                    column,
                    &util::columns::PERMISSION_DEFAULTS,
                    json_output,
                )?;
            }

            GetEntity::User { id } => {
                let user = client.get_user(id).await?;
                if json_output {
                    output::print_json(&user)?;
                } else {
                    output::print_kv(&[
                        ("ID", &user.id),
                        ("Username", user.username.as_deref().unwrap_or("")),
                        ("First Name", user.first_name()),
                        ("Last Name", user.last_name()),
                        ("Role", user.role_name()),
                    ]);
                }
            }

            GetEntity::Group { id, column } => {
                let group = client.get_group(id).await?;
                if json_output {
                    output::print_json(&group)?;
                } else {
                    output::print_kv(&[("ID", &group.id), ("Name", &group.name)]);
                    util::columns::print(
                        &group.groups_users,
                        &util::columns::GROUP_MEMBER_COLUMNS,
                        column,
                        &util::columns::GROUP_MEMBER_DEFAULTS,
                        false,
                    )?;
                }
            }

            GetEntity::Totp { id } => {
                let (code, ttl) = passbolt_sdk::resource::get::get_totp_code(client, id).await?;
                if json_output {
                    output::print_json(&serde_json::json!({ "code": code, "ttl": ttl }))?;
                } else {
                    println!("{code}  ({ttl}s remaining)");
                }
            }
        },

        // ── List ────────────────────────────────────────────────────────────
        Commands::List(args) => match &args.entity {
            ListEntity::Resource {
                favorite,
                own,
                group,
                folder,
                search,
                column,
                filter,
            } => {
                use util::resources::{column_name, column_text, needs_secrets, DEFAULT_COLUMNS};

                let columns: Vec<&str> = if column.is_empty() && !json_output {
                    DEFAULT_COLUMNS.to_vec()
                } else {
                    column
                        .iter()
                        .map(|column| column_name(column))
                        .collect::<Result<_>>()?
                };
                let filters = parse_filters(filter)?;
                let filter_names: Vec<&str> =
                    filters.iter().map(|filter| filter.field.as_str()).collect();
                let secret_workers =
                    (needs_secrets(&columns) || needs_secrets(&filter_names)).then_some(workers);

                let query = passbolt_sdk::ResourceQuery {
                    favorites_only: *favorite,
                    owned_by_me: *own,
                    group_ids: group.clone(),
                    folder_ids: folder.clone(),
                    search: search.clone(),
                    ..Default::default()
                };
                let views = passbolt_sdk::resource::list::list_resources(
                    client,
                    query,
                    &filters,
                    secret_workers,
                )
                .await?;
                for view in &views {
                    if let Some(error) = &view.error {
                        eprintln!(
                            "Warning: resource {} could not be decrypted: {error}",
                            view.id
                        );
                    }
                }

                if json_output {
                    if columns.is_empty() {
                        output::print_json(&views)?;
                    } else {
                        output::print_json(&util::resources::select_columns(&views, &columns)?)?;
                    }
                } else {
                    let rows = views
                        .iter()
                        .map(|view| {
                            columns
                                .iter()
                                .map(|name| column_text(view, name))
                                .collect::<Result<Vec<_>>>()
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let headers: Vec<&str> = column.iter().map(String::as_str).collect();
                    let headers = if headers.is_empty() {
                        columns.clone()
                    } else {
                        headers
                    };
                    output::print_table(&headers, rows);
                }
            }

            ListEntity::Folder {
                search,
                folder,
                group,
                column,
                filter,
            } => {
                let filters = parse_filters(filter)?;

                let folders = passbolt_sdk::folder::list::list_folders(
                    client,
                    search.clone(),
                    group.clone(),
                    folder.clone(),
                    &filters,
                )
                .await?;

                util::columns::print(
                    &folders,
                    &util::columns::FOLDER_COLUMNS,
                    column,
                    &util::columns::FOLDER_DEFAULTS,
                    json_output,
                )?;
            }

            ListEntity::User {
                group,
                resource,
                search,
                admin,
                column,
                filter,
            } => {
                let filters = parse_filters(filter)?;

                let users = passbolt_sdk::user::list::list_users(
                    client,
                    search.clone(),
                    group.clone(),
                    resource.clone(),
                    *admin,
                    &filters,
                )
                .await?;

                util::columns::print(
                    &users,
                    &util::columns::USER_COLUMNS,
                    column,
                    &util::columns::USER_DEFAULTS,
                    json_output,
                )?;
            }

            ListEntity::Group {
                user,
                manager,
                column,
                filter,
            } => {
                let filters = parse_filters(filter)?;

                let groups = passbolt_sdk::group::list::list_groups(
                    client,
                    user.clone(),
                    manager.clone(),
                    &filters,
                )
                .await?;

                util::columns::print(
                    &groups,
                    &util::columns::GROUP_COLUMNS,
                    column,
                    &util::columns::GROUP_DEFAULTS,
                    json_output,
                )?;
            }
        },

        // ── Update ──────────────────────────────────────────────────────────
        Commands::Update(args) => match &args.entity {
            UpdateEntity::Resource {
                id,
                name,
                username,
                uri,
                password,
                description,
                note,
                pin_code,
                field,
                secret_field,
                expiry,
                totp_key,
                totp_algo,
                totp_digits,
                totp_period,
                remove_totp,
            } => {
                use passbolt_sdk::resource::update::ResourceChanges;

                let totp_changed = totp_key.is_some()
                    || totp_algo.is_some()
                    || totp_digits.is_some()
                    || totp_period.is_some();
                let changes = ResourceChanges {
                    name: name.clone(),
                    username: username.clone(),
                    uris: (!uri.is_empty()).then(|| uri.clone()),
                    description: description.clone(),
                    note: note.clone(),
                    password: password.clone(),
                    pin_code: pin_code.clone(),
                    totp: totp_changed.then(|| passbolt_sdk::types::TotpData {
                        secret_key: totp_key.clone(),
                        algorithm: totp_algo.clone(),
                        digits: *totp_digits,
                        period: *totp_period,
                        issuer: None,
                    }),
                    remove_totp: *remove_totp,
                    expired: parse_expiry_opt(expiry.as_ref())?
                        .map(|expiry| expiry.as_str().map(String::from)),
                    metadata_fields: util::resources::parse_fields(field)?,
                    secret_fields: util::resources::parse_fields(secret_field)?,
                };
                let resource =
                    passbolt_sdk::resource::update::update_resource(client, id, &changes).await?;

                if json_output {
                    output::print_json(&resource)?;
                } else {
                    println!("Updated resource: {}", resource.id);
                }
            }

            UpdateEntity::Folder { id, name } => {
                let payload = passbolt_sdk::types::UpdateFolderPayload { name: name.clone() };
                let folder = client.update_folder(id, &payload).await?;
                if json_output {
                    output::print_json(&folder)?;
                } else {
                    println!("Updated folder: {} ({})", folder.name, folder.id);
                }
            }

            UpdateEntity::User {
                id,
                firstname,
                lastname,
                role,
            } => {
                let user = passbolt_sdk::user::update::update_user(
                    client,
                    id,
                    firstname.as_deref(),
                    lastname.as_deref(),
                    role.as_deref(),
                )
                .await?;
                if json_output {
                    output::print_json(&user)?;
                } else {
                    println!("Updated user: {}", user.id);
                }
            }

            UpdateEntity::Group {
                id,
                name,
                user,
                manager,
                delete,
            } => {
                let group = passbolt_sdk::group::update::update_group(
                    client,
                    id,
                    name.as_deref(),
                    user,
                    manager,
                    delete,
                )
                .await?;
                if json_output {
                    output::print_json(&group)?;
                } else {
                    println!("Updated group: {} ({})", group.name, group.id);
                }
            }
        },

        // ── Delete ──────────────────────────────────────────────────────────
        Commands::Delete(args) => match &args.entity {
            DeleteEntity::Resource { id } => {
                client.delete_resource(id).await?;
                output::print_done(json_output, "deleted", "resource", id)?;
            }
            DeleteEntity::Folder { id, cascade } => {
                if *cascade {
                    client.delete_folder_with_content(id).await?;
                } else {
                    client.delete_folder(id).await?;
                }
                output::print_done(json_output, "deleted", "folder", id)?;
            }
            DeleteEntity::User {
                id,
                dry_run,
                transfer_to,
            } => {
                let blockers = client.user_delete_blockers(id).await?;
                if *dry_run {
                    return print_blockers(json_output, "user", &blockers);
                }
                match transfer_to {
                    _ if blockers.is_empty() => client.delete_user(id).await?,
                    Some(successor) => {
                        let transfer = blockers.transfer_to(successor)?;
                        client.delete_user_with_transfer(id, &transfer).await?;
                    }
                    None => refuse_blocked_delete("user", &blockers)?,
                }
                output::print_done(json_output, "deleted", "user", id)?;
            }
            DeleteEntity::Group {
                id,
                dry_run,
                transfer_to,
            } => {
                let blockers = client.group_delete_blockers(id).await?;
                if *dry_run {
                    return print_blockers(json_output, "group", &blockers);
                }
                match transfer_to {
                    _ if blockers.is_empty() => client.delete_group(id).await?,
                    Some(successor) => {
                        let transfer = blockers.transfer_to(successor)?;
                        client.delete_group_with_transfer(id, &transfer).await?;
                    }
                    None => refuse_blocked_delete("group", &blockers)?,
                }
                output::print_done(json_output, "deleted", "group", id)?;
            }
        },

        // ── Share ───────────────────────────────────────────────────────────
        Commands::Share(args) => match &args.entity {
            ShareEntity::Resource {
                id,
                r#type,
                user,
                group,
            } => {
                passbolt_sdk::resource::share::share_resource(client, id, user, group, *r#type)
                    .await?;
                output::print_done(json_output, "shared", "resource", id)?;
            }
            ShareEntity::Folder {
                id,
                r#type,
                user,
                group,
                with_content,
            } => {
                passbolt_sdk::folder::share::share_folder(
                    client,
                    id,
                    user,
                    group,
                    *r#type,
                    *with_content,
                )
                .await?;
                output::print_done(json_output, "shared", "folder", id)?;
            }
        },

        // ── Move ────────────────────────────────────────────────────────────
        Commands::Move(args) => match &args.entity {
            MoveEntity::Resource {
                id,
                folder_parent_id,
                with_folder_permissions,
            } => {
                // An empty folder id is the root, as the help says.
                let folder_parent_id = folder_parent_id.as_deref().filter(|id| !id.is_empty());
                if *with_folder_permissions {
                    passbolt_sdk::resource::share::move_with_folder_permissions(
                        client,
                        id,
                        folder_parent_id,
                    )
                    .await?;
                } else {
                    client.move_resource(id, folder_parent_id).await?;
                }
                output::print_done(json_output, "moved", "resource", id)?;
            }
            MoveEntity::Folder {
                id,
                folder_parent_id,
                with_folder_permissions,
            } => {
                let folder_parent_id = folder_parent_id.as_deref().filter(|id| !id.is_empty());
                if *with_folder_permissions {
                    passbolt_sdk::folder::share::move_with_folder_permissions(
                        client,
                        id,
                        folder_parent_id,
                    )
                    .await?;
                } else {
                    client.move_folder(id, folder_parent_id).await?;
                }
                output::print_done(json_output, "moved", "folder", id)?;
            }
        },

        // ── Exec ────────────────────────────────────────────────────────────
        Commands::Exec(args) => {
            cli::exec::run(args, client).await?;
        }

        // ── Export ──────────────────────────────────────────────────────────
        Commands::Export(args) => {
            cli::export::run(args, client, workers).await?;
        }

        // ── Migrate metadata ────────────────────────────────────────────────
        Commands::MigrateMetadata { shared_only } => {
            let upgraded =
                passbolt_sdk::resource::upgrade::upgrade_resources(client, *shared_only).await?;
            if json_output {
                output::print_json(&serde_json::json!({ "upgraded": upgraded }))?;
            } else {
                println!("{upgraded} resources upgraded to v5.");
            }
        }

        Commands::Configure(_)
        | Commands::Verify(_)
        | Commands::Completion { .. }
        | Commands::Gendoc(_) => {
            unreachable!("handled above")
        }
    }

    Ok(())
}

/// What blocks deleting a user or group, as JSON or one line per item.
fn print_blockers(
    json_output: bool,
    entity: &str,
    blockers: &passbolt_sdk::transfer::DeleteBlockers,
) -> Result<()> {
    if json_output {
        return output::print_json(blockers);
    }
    if blockers.is_empty() {
        println!("Nothing blocks deleting the {entity}.");
    }
    for (kind, items) in [
        ("resource", &blockers.resources),
        ("folder", &blockers.folders),
    ] {
        for item in items {
            println!("{kind} {} is only owned by the {entity}", item.id);
        }
    }
    for group in &blockers.groups {
        println!(
            "group {} ({}) is only managed by the {entity}",
            group.id, group.name
        );
    }
    for group_id in &blockers.groups_to_delete {
        println!("group {group_id} has no other member: deleted with the {entity}");
    }
    Ok(())
}

fn refuse_blocked_delete(
    entity: &str,
    blockers: &passbolt_sdk::transfer::DeleteBlockers,
) -> Result<()> {
    anyhow::bail!(
        "The {entity} alone owns {} resources and {} folders and alone manages {} groups: give \
         them to someone with --transfer-to <user or group id> (list them with --dry-run)",
        blockers.resources.len(),
        blockers.folders.len(),
        blockers.groups.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn flags(arguments: &[&str]) -> Vec<(&'static str, String)> {
        let arguments = std::iter::once("passbolt")
            .chain(arguments.iter().copied())
            .chain(["list", "resource"]);
        apply_cli_overrides(&Cli::try_parse_from(arguments).unwrap())
    }

    fn flag(arguments: &[&str], name: &str) -> Option<String> {
        flags(arguments)
            .into_iter()
            .find(|(flag_name, _)| *flag_name == name)
            .map(|(_, value)| value)
    }

    #[test]
    fn test_no_flag_gives_no_setting() {
        assert_eq!(flags(&[]), Vec::new());
    }

    #[rstest::rstest]
    #[case(&["--serverAddress", "https://go"], "server_address", "https://go")]
    #[case(&["--server-address", "https://ours"], "server_address", "https://ours")]
    #[case(&["--userPrivateKey", "key"], "user_private_key", "key")]
    #[case(&["--userPrivateKeyFile", "key.asc"], "user_private_key_file", "key.asc")]
    #[case(&["--userPassword", "secret"], "user_password", "secret")]
    #[case(&["--mfaMode", "none"], "mfa_mode", "none")]
    #[case(&["--mfaTotpToken", "T"], "mfa_totp_token", "T")]
    #[case(&["--totpToken", "T"], "totp_token", "T")]
    #[case(&["--mfaTotpOffset", "-1m"], "mfa_totp_offset", "-1m")]
    #[case(&["--totpOffset", "30s"], "totp_offset", "30s")]
    #[case(&["--mfaRetrys", "2"], "mfa_retrys", "2")]
    #[case(&["--mfaDelay", "5s"], "mfa_delay", "5s")]
    #[case(&["--tlsSkipVerify"], "tls_skip_verify", "true")]
    #[case(&["--tlsSkipVerify=false"], "tls_skip_verify", "false")]
    #[case(&["--tls-skip-verify=true"], "tls_skip_verify", "true")]
    #[case(&["--tlsClientCert", "C"], "tls_client_cert", "C")]
    #[case(&["--tlsClientPrivateKey", "K"], "tls_client_private_key", "K")]
    #[case(&["--tlsClientCertFile", "c.pem"], "tls_client_cert_file", "c.pem")]
    #[case(&["--tlsClientPrivateKeyFile", "k.pem"], "tls_client_private_key_file", "k.pem")]
    #[case(&["--timeout", "1m30s"], "timeout", "1m30s")]
    #[case(&["--workers", "4"], "workers", "4")]
    #[case(&["--debug"], "debug", "true")]
    #[case(&["--debug=1"], "debug", "true")]
    #[case(&["--debug=false"], "debug", "false")]
    fn test_flags_of_both_spellings(
        #[case] arguments: &[&str],
        #[case] name: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(flag(arguments, name).as_deref(), Some(expected));
    }

    #[test]
    fn test_a_bool_flag_does_not_take_the_next_argument() {
        let cli = Cli::try_parse_from(["passbolt", "--debug", "list", "resource"]).unwrap();

        assert_eq!(cli.debug, Some(true));
    }

    #[test]
    fn test_a_bool_flag_refuses_a_value_that_is_not_a_bool() {
        assert!(Cli::try_parse_from(["passbolt", "--debug=maybe", "list", "resource"]).is_err());
    }

    #[test]
    fn test_global_flags_are_taken_after_the_subcommand() {
        let cli =
            Cli::try_parse_from(["passbolt", "configure", "--serverAddress", "https://x"]).unwrap();

        assert_eq!(cli.server_address.as_deref(), Some("https://x"));
    }

    #[tokio::test]
    async fn test_with_deadline_stops_a_command_that_takes_too_long() {
        let mut config = Config::default();
        config.timeout = "50ms".into();

        let error = with_deadline(&config, async {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            Ok(())
        })
        .await
        .unwrap_err();

        assert!(
            error.to_string().contains("context deadline exceeded"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn test_with_deadline_zero_is_no_limit() {
        let mut config = Config::default();
        config.timeout = "0s".into();

        let result = with_deadline(&config, async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            Ok(())
        })
        .await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_help_when_incomplete_asks_for_help_without_arguments() {
        let error = help_when_incomplete(Cli::command())
            .try_get_matches_from(["passbolt"])
            .unwrap_err();

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn test_migrate_metadata_takes_shared_only() {
        let cli = Cli::try_parse_from(["passbolt", "migrate-metadata", "--shared-only"]).unwrap();

        assert!(matches!(
            cli.command,
            Commands::MigrateMetadata { shared_only: true }
        ));
    }

    #[rstest::rstest]
    #[case::unknown_permission_type(&["share", "resource", "--id", "x", "-u", "u", "-t", "3"])]
    #[case::no_recipient(&["share", "resource", "--id", "x", "-t", "1"])]
    #[case::folder_without_recipient(&["share", "folder", "--id", "x"])]
    fn test_share_refuses(#[case] arguments: &[&str]) {
        let arguments = std::iter::once("passbolt").chain(arguments.iter().copied());

        assert!(Cli::try_parse_from(arguments).is_err());
    }

    #[rstest::rstest]
    #[case::revoke("-1")]
    #[case::read("1")]
    #[case::owner("15")]
    fn test_share_takes_the_permission_types(#[case] permission_type: &str) {
        let cli = Cli::try_parse_from([
            "passbolt",
            "share",
            "resource",
            "--id",
            "x",
            "-g",
            "g",
            "-t",
            permission_type,
        ]);

        assert!(cli.is_ok());
    }
}
