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

use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches};
use clap_complete::generate;

use cli::root::{
    Cli, Commands, CreateEntity, DeleteEntity, GetEntity, ListEntity, MoveEntity,
    PermissionCommand, ShareEntity, UpdateEntity,
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
                let result = dispatch(command, &client, cli.json, workers, config.debug).await;
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

fn parse_expiry_opt(expiry: Option<&String>) -> Result<Option<serde_json::Value>> {
    expiry
        .map(String::as_str)
        .map(passbolt_sdk::resource::expiry::parse_expiry)
        .transpose()
        .map_err(Into::into)
}

/// `None` for an empty value: go-passbolt-cli leaves a field unchanged when given empty.
fn given(value: Option<&String>) -> Option<String> {
    value.filter(|value| !value.is_empty()).cloned()
}

/// The `--filter` texts: CEL expressions, applied to the listed rows, and field conditions of the
/// older syntax, which the SDK applies. An empty text filters nothing, as in go-passbolt-cli.
fn split_filters(
    texts: &[String],
    variables: &[util::cel::Variable],
) -> Result<(
    Vec<passbolt_sdk::filter::Filter>,
    Vec<util::cel::Expression>,
)> {
    use util::cel::FilterExpression;

    let mut legacy = Vec::new();
    let mut expressions = Vec::new();
    for text in texts.iter().filter(|text| !text.trim().is_empty()) {
        match FilterExpression::parse(text, variables)? {
            FilterExpression::Cel(expression) => expressions.push(expression),
            FilterExpression::Legacy(filter) => legacy.push(filter),
        }
    }
    Ok((legacy, expressions))
}

/// `items` kept by every CEL expression; nothing kept is an error, as in go-passbolt-cli.
fn cel_filtered<T>(
    items: Vec<T>,
    columns: &util::columns::Columns<T>,
    variables: &[util::cel::Variable],
    expressions: &[util::cel::Expression],
) -> Result<Vec<T>> {
    expressions.iter().try_fold(items, |items, expression| {
        let read = expression.columns();
        expression.filter(items, columns.noun, |item| {
            columns.cel_row(variables, &read, item)
        })
    })
}

/// A filter matching nothing is an error, as in go-passbolt-cli.
fn found<T>(items: Vec<T>, noun: &str, filter: &[String]) -> Result<Vec<T>> {
    if items.is_empty() && !filter.is_empty() {
        anyhow::bail!("no such {noun} found with filter {}", filter.join(" "));
    }
    Ok(items)
}

/// The secret-only fields a legacy filter reads.
fn filters_need_secrets(filters: &[passbolt_sdk::filter::Filter]) -> bool {
    filters.iter().any(|filter| {
        matches!(
            filter.field.as_str(),
            "password" | "description" | "note" | "secret"
        )
    })
}

/// The id of `delete`, which go-passbolt-cli reads before or after the entity.
fn delete_id(id: Option<&String>) -> Result<&str> {
    id.map(String::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| anyhow::anyhow!("no ID provided"))
}

async fn print_permissions(
    client: &Client,
    entity: &str,
    args: &cli::root::PermissionArgs,
    json_output: bool,
) -> Result<()> {
    let permissions = if entity == "Resource" {
        passbolt_sdk::resource::get::get_resource_permissions(client, &args.id).await
    } else {
        client.get_folder_permissions(&args.id).await
    }
    .with_context(|| format!("listing Permission for {entity} {}", args.id))?;
    if json_output {
        let shapes: Vec<_> = permissions.iter().map(util::shapes::permission).collect();
        return output::print_json(&shapes);
    }
    util::columns::print_named(
        &permissions,
        &util::columns::PERMISSIONS,
        &args.column,
        &util::columns::PERMISSION_DEFAULTS,
    )
}

#[allow(clippy::too_many_lines)]
async fn dispatch(
    command: &Commands,
    client: &Client,
    json_output: bool,
    workers: usize,
    debug: bool,
) -> Result<()> {
    use util::columns::{FOLDERS, GROUPS, RESOURCES, USERS};
    use util::shapes;

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
                use std::io::IsTerminal;
                use util::password::read_password;

                let from_fields =
                    resource_type.is_some() || !field.is_empty() || !secret_field.is_empty();
                let name = given(name.as_ref());
                if name.is_none() && !from_fields {
                    anyhow::bail!("required flag \"name\" not set");
                }
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
                let resolved_password = match given(password.as_ref()) {
                    Some(provided_password) => Some(provided_password),
                    // Asked only in a terminal: a script gets go-passbolt-cli's error.
                    None if needs_password && std::io::stdin().is_terminal() => {
                        Some(read_password("Password: ")?.expose_secret().to_string())
                    }
                    None if needs_password => anyhow::bail!("required flag \"password\" not set"),
                    None => None,
                };

                let new_resource = NewResource {
                    resource_type: resource_type.clone(),
                    name: name.unwrap_or_default(),
                    username: given(username.as_ref()),
                    uris: uri.iter().filter(|uri| !uri.is_empty()).cloned().collect(),
                    description: given(description.as_ref()),
                    note: note.clone(),
                    password: resolved_password,
                    totp,
                    pin_code: pin_code.clone(),
                    folder_parent_id: given(folder_parent_id.as_ref()),
                    expired: parse_expiry_opt(expiry.as_ref())?
                        .and_then(|expiry| expiry.as_str().map(String::from)),
                    metadata_fields: util::resources::parse_fields(field)?,
                    secret_fields: util::resources::parse_fields(secret_field)?,
                    ..NewResource::default()
                };
                let resource =
                    passbolt_sdk::resource::create::create_resource(client, &new_resource)
                        .await
                        .context("creating resource")?;
                print_created(json_output, "ResourceID", &resource.id)?;
            }

            CreateEntity::Folder {
                name,
                folder_parent_id,
            } => {
                let folder = passbolt_sdk::folder::create::create_folder(
                    client,
                    name,
                    given(folder_parent_id.as_ref()).as_deref(),
                )
                .await
                .context("creating Folder")?;
                print_created(json_output, "FolderID", &folder.id)?;
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
                .await
                .context("creating User")?;
                print_created(json_output, "UserID", &user.id)?;
            }

            CreateEntity::Group {
                name,
                user,
                manager,
            } => {
                if manager.is_empty() {
                    anyhow::bail!("required flag(s) \"manager\" not set");
                }
                let group = passbolt_sdk::group::create::create_group(client, name, user, manager)
                    .await
                    .context("creating Group")?;
                print_created(json_output, "GroupID", &group.id)?;
            }
        },

        // ── Get ─────────────────────────────────────────────────────────────
        Commands::Get(args) => match &args.entity {
            GetEntity::Resource(get) => {
                if let Some(PermissionCommand::Permission(permission)) = &get.permission {
                    return print_permissions(client, "Resource", permission, json_output).await;
                }
                let id = get.id.as_deref().unwrap_or_default();
                let view = passbolt_sdk::resource::get::get_resource_view(client, id)
                    .await
                    .context("getting resource")?;
                if json_output {
                    output::print_json(&shapes::got_resource(&view))?;
                } else {
                    let rows = util::resources::detail_rows(&view);
                    let pairs: Vec<(&str, &str)> = rows
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .collect();
                    output::print_kv(&pairs);
                }
            }

            GetEntity::ResourcePermissions(permission) => {
                return print_permissions(client, "Resource", permission, json_output).await;
            }

            GetEntity::Folder(get) => {
                if let Some(PermissionCommand::Permission(permission)) = &get.permission {
                    return print_permissions(client, "Folder", permission, json_output).await;
                }
                let id = get.id.as_deref().unwrap_or_default();
                let folder = client.get_folder(id).await.context("getting Folder")?;
                if json_output {
                    output::print_json(&shapes::got_folder(&folder))?;
                } else {
                    output::print_kv(&[
                        (
                            "FolderParentID",
                            folder.folder_parent_id.as_deref().unwrap_or_default(),
                        ),
                        ("Name", &folder.name),
                    ]);
                }
            }

            GetEntity::FolderPermissions(permission) => {
                return print_permissions(client, "Folder", permission, json_output).await;
            }

            GetEntity::User { id } => {
                let user = client.get_user(id).await.context("getting User")?;
                if json_output {
                    output::print_json(&shapes::got_user(&user))?;
                } else {
                    output::print_kv(&[
                        ("Username", user.username.as_deref().unwrap_or_default()),
                        ("FirstName", user.first_name()),
                        ("LastName", user.last_name()),
                        ("Role", user.role_name()),
                    ]);
                }
            }

            GetEntity::Group { id, column } => {
                let group = client.get_group(id).await.context("getting Group")?;
                if json_output {
                    output::print_json(&shapes::got_group(&group))?;
                } else {
                    output::print_kv(&[("Name", &group.name)]);
                    util::columns::print_named(
                        &group.groups_users,
                        &util::columns::GROUP_MEMBERS,
                        column,
                        &util::columns::GROUP_MEMBER_DEFAULTS,
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
        Commands::List(args) => {
            use util::cel::{
                FOLDER_VARIABLES, GROUP_VARIABLES, RESOURCE_SECRET_COLUMNS, RESOURCE_VARIABLES,
                USER_VARIABLES,
            };
            let filter = &args.filter;
            match &args.entity {
                ListEntity::Resource {
                    favorite,
                    own,
                    group,
                    folder,
                    search,
                    column,
                } => {
                    let (filters, expressions) = split_filters(filter, RESOURCE_VARIABLES)?;
                    let selected = RESOURCES.select(column)?;
                    let needs_secrets = selected.iter().any(|column| column.secret)
                        || filters_need_secrets(&filters)
                        || expressions
                            .iter()
                            .any(|expression| expression.reads_any(RESOURCE_SECRET_COLUMNS));
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
                        needs_secrets.then_some(workers),
                    )
                    .await
                    .context("listing Resource")?;
                    let views: Vec<_> = views
                        .into_iter()
                        .filter(|view| {
                            view.error.as_ref().is_none_or(|error| {
                                eprintln!("Warning: resource {} skipped: {error}", view.id);
                                false
                            })
                        })
                        .collect();
                    let views = found(views, RESOURCES.noun, filter)?;
                    let views = cel_filtered(views, &RESOURCES, RESOURCE_VARIABLES, &expressions)?;
                    RESOURCES.print(&views, column, shapes::listed_resource, json_output)?;
                }

                ListEntity::Folder {
                    search,
                    folder,
                    group,
                    column,
                } => {
                    let (filters, expressions) = split_filters(filter, FOLDER_VARIABLES)?;
                    let folders = passbolt_sdk::folder::list::list_folders(
                        client,
                        search.clone(),
                        group.clone(),
                        folder.clone(),
                        &filters,
                    )
                    .await
                    .context("listing Folder")?;
                    let folders = found(folders, FOLDERS.noun, filter)?;
                    let folders = cel_filtered(folders, &FOLDERS, FOLDER_VARIABLES, &expressions)?;
                    FOLDERS.print(&folders, column, shapes::listed_folder, json_output)?;
                }

                ListEntity::User {
                    group,
                    resource,
                    search,
                    admin,
                    column,
                } => {
                    let (filters, expressions) = split_filters(filter, USER_VARIABLES)?;
                    let users = passbolt_sdk::user::list::list_users(
                        client,
                        search.clone(),
                        group.clone(),
                        resource.clone(),
                        *admin,
                        &filters,
                    )
                    .await
                    .context("listing User")?;
                    let users = found(users, USERS.noun, filter)?;
                    let users = cel_filtered(users, &USERS, USER_VARIABLES, &expressions)?;
                    USERS.print(&users, column, shapes::listed_user, json_output)?;
                }

                ListEntity::Group {
                    user,
                    manager,
                    column,
                } => {
                    let (filters, expressions) = split_filters(filter, GROUP_VARIABLES)?;
                    let groups = passbolt_sdk::group::list::list_groups(
                        client,
                        user.clone(),
                        manager.clone(),
                        &filters,
                    )
                    .await
                    .context("listing Group")?;
                    let groups = found(groups, GROUPS.noun, filter)?;
                    let groups = cel_filtered(groups, &GROUPS, GROUP_VARIABLES, &expressions)?;
                    GROUPS.print(&groups, column, shapes::listed_group, json_output)?;
                }
            }
        }

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
                let uris: Vec<String> = uri.iter().filter(|uri| !uri.is_empty()).cloned().collect();
                let changes = ResourceChanges {
                    name: given(name.as_ref()),
                    username: given(username.as_ref()),
                    uris: (!uris.is_empty()).then_some(uris),
                    description: given(description.as_ref()),
                    note: given(note.as_ref()),
                    password: given(password.as_ref()),
                    pin_code: given(pin_code.as_ref()),
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
                passbolt_sdk::resource::update::update_resource(client, id, &changes)
                    .await
                    .context("updating resource")?;
                output::print_done(json_output, "updated", id)?;
            }

            UpdateEntity::Folder { id, name } => {
                let payload = passbolt_sdk::types::UpdateFolderPayload { name: name.clone() };
                client
                    .update_folder(id, &payload)
                    .await
                    .context("updating Folder")?;
                output::print_done(json_output, "updated", id)?;
            }

            UpdateEntity::User {
                id,
                firstname,
                lastname,
                role,
            } => {
                passbolt_sdk::user::update::update_user(
                    client,
                    id,
                    given(firstname.as_ref()).as_deref(),
                    given(lastname.as_ref()).as_deref(),
                    given(role.as_ref()).as_deref(),
                )
                .await
                .context("updating User")?;
                output::print_done(json_output, "updated", id)?;
            }

            UpdateEntity::Group {
                id,
                name,
                user,
                manager,
                delete,
            } => {
                passbolt_sdk::group::update::update_group(
                    client,
                    id,
                    name.as_deref(),
                    user,
                    manager,
                    *delete,
                )
                .await
                .context("updating Group")?;
                output::print_done(json_output, "updated", id)?;
            }
        },

        // ── Delete ──────────────────────────────────────────────────────────
        Commands::Delete(args) => {
            let id = delete_id(args.id.as_ref())?;
            match &args.entity {
                DeleteEntity::Resource => {
                    client
                        .delete_resource(id)
                        .await
                        .with_context(|| format!("deleting Resource {id}"))?;
                }
                DeleteEntity::Folder { cascade } => {
                    if *cascade {
                        client.delete_folder_with_content(id).await
                    } else {
                        client.delete_folder(id).await
                    }
                    .with_context(|| format!("deleting Folder {id}"))?;
                }
                DeleteEntity::User {
                    dry_run,
                    transfer_to,
                } => {
                    let blockers = client.user_delete_blockers(id).await?;
                    if *dry_run {
                        return print_blockers(json_output, "user", &blockers);
                    }
                    match transfer_to {
                        _ if blockers.is_empty() => client.delete_user(id).await,
                        Some(successor) => {
                            let transfer = blockers.transfer_to(successor)?;
                            client.delete_user_with_transfer(id, &transfer).await
                        }
                        None => return refuse_blocked_delete("user", &blockers),
                    }
                    .with_context(|| format!("deleting User {id}"))?;
                }
                DeleteEntity::Group {
                    dry_run,
                    transfer_to,
                } => {
                    let blockers = client.group_delete_blockers(id).await?;
                    if *dry_run {
                        return print_blockers(json_output, "group", &blockers);
                    }
                    match transfer_to {
                        _ if blockers.is_empty() => client.delete_group(id).await,
                        Some(successor) => {
                            let transfer = blockers.transfer_to(successor)?;
                            client.delete_group_with_transfer(id, &transfer).await
                        }
                        None => return refuse_blocked_delete("group", &blockers),
                    }
                    .with_context(|| format!("deleting Group {id}"))?;
                }
            }
            output::print_done(json_output, "deleted", id)?;
        }

        // ── Share ───────────────────────────────────────────────────────────
        Commands::Share(args) => match &args.entity {
            ShareEntity::Resource {
                id,
                r#type,
                user,
                group,
            } => {
                passbolt_sdk::resource::share::share_resource(client, id, user, group, *r#type)
                    .await
                    .context("sharing Resource")?;
                output::print_done(json_output, "shared", id)?;
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
                .await
                .context("sharing Folder")?;
                output::print_done(json_output, "shared", id)?;
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
                    .await
                } else {
                    client.move_resource(id, folder_parent_id).await
                }
                .context("moving Resource")?;
                output::print_done(json_output, "moved", id)?;
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
                    .await
                } else {
                    client.move_folder(id, folder_parent_id).await
                }
                .context("moving Folder")?;
                output::print_done(json_output, "moved", id)?;
            }
        },

        // ── Exec ────────────────────────────────────────────────────────────
        Commands::Exec(args) => {
            cli::exec::run(args, client, debug).await?;
        }

        // ── Export ──────────────────────────────────────────────────────────
        Commands::Export(args) => {
            Box::pin(cli::export::run(args, client, workers, json_output)).await?;
        }

        Commands::Import(args) => {
            Box::pin(cli::import::run(args, client, json_output)).await?;
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

/// What `create` prints: `ResourceID: <id>`, or `{"id": <id>}` with `--json`.
fn print_created(json_output: bool, label: &str, id: &str) -> Result<()> {
    if json_output {
        return output::print_json(&serde_json::json!({ "id": id }));
    }
    println!("{label}: {id}");
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

    #[test]
    fn test_share_refuses_an_unknown_permission_type() {
        let cli = Cli::try_parse_from([
            "passbolt", "share", "resource", "--id", "x", "-u", "u", "-t", "3",
        ]);

        assert!(cli.is_err());
    }

    #[rstest::rstest]
    #[case::alias_new(&["new", "folder", "-n", "x"])]
    #[case::alias_read(&["read", "user", "--id", "x"])]
    #[case::alias_ls(&["ls", "resources"])]
    #[case::alias_search(&["search", "users", "-a"])]
    #[case::alias_index(&["index", "groups", "-u", "a", "-u", "b"])]
    #[case::alias_filter(&["filter", "folders"])]
    #[case::alias_change(&["change", "group", "--id", "x", "-d", "-u", "a"])]
    #[case::alias_remove(&["remove", "resource", "--id", "x"])]
    #[case::delete_id_first(&["delete", "--id", "x", "folder"])]
    #[case::list_filter_first(&["list", "--filter", "name == \"x\"", "resource"])]
    #[case::resource_permission(&["get", "resource", "permission", "--id", "x", "-c", "Aco"])]
    #[case::folder_permissions(&["get", "folder", "permissions", "--id", "x"])]
    #[case::old_permissions_command(&["get", "resource-permissions", "--id", "x"])]
    #[case::folder_parent_id(&["create", "resource", "-n", "x", "--folderParentID", "f"])]
    #[case::move_folder_parent_id(&["move", "folder", "--id", "x", "--folderParentID", "f"])]
    #[case::name_from_a_field(&["create", "resource", "--field", "name=x"])]
    #[case::share_without_recipient(&["share", "folder", "--id", "x", "-t", "7"])]
    #[case::users_of_two_groups(&["list", "user", "-g", "a", "-g", "b", "-r", "c"])]
    fn test_go_passbolt_cli_command_lines_are_read(#[case] arguments: &[&str]) {
        let arguments = std::iter::once("passbolt").chain(arguments.iter().copied());

        let parsed = Cli::try_parse_from(arguments);

        assert!(parsed.is_ok(), "{:?}", parsed.err());
    }

    #[test]
    fn test_get_resource_needs_an_id_without_permission() {
        assert!(Cli::try_parse_from(["passbolt", "get", "resource"]).is_err());
    }

    #[test]
    fn test_update_group_delete_is_a_switch() {
        let cli = Cli::try_parse_from([
            "passbolt", "update", "group", "--id", "g", "-d", "-u", "a", "-m", "b",
        ])
        .unwrap();

        let Commands::Update(update) = cli.command else {
            panic!("not an update");
        };
        assert!(matches!(
            update.entity,
            UpdateEntity::Group { delete: true, ref user, ref manager, .. }
                if user == &["a"] && manager == &["b"]
        ));
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
