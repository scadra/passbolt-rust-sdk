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

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use clap_complete::generate;

use cli::root::{
    Cli, Commands, CreateEntity, DeleteEntity, GetEntity, ListEntity, MoveEntity,
    PermissionCommand, ShareEntity, UpdateEntity,
};
use config::Config;
use util::{output, session};

/// Type alias for the concrete SDK client used by the CLI.
pub type Client = passbolt_sdk::PassboltSdk<passbolt_sdk::NativeHttpClient>;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(path) = &cli.config {
        Config::set_path(path.into());
    }

    match &cli.command {
        // ── Configure ──────────────────────────────────────────────────────
        Commands::Configure(args) => {
            cli::configure::run(args)?;
        }

        // ── Shell completions ──────────────────────────────────────────────
        Commands::Completion { shell } => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            generate(*shell, &mut command, name, &mut std::io::stdout());
        }

        // ── Documentation generation ───────────────────────────────────────
        Commands::Gendoc(args) => {
            cli::gendoc::run_gendoc(args)?;
        }

        // ── Verify ─────────────────────────────────────────────────────────
        Commands::Verify(args) => {
            let config = load_config(&cli)?;
            cli::verify::run(args, &config).await?;
        }

        // All other commands require a connected client
        command => {
            let config = load_config(&cli)?;
            let client = session::get_client(&config).await?;
            let result = dispatch(command, &client, cli.json, config.workers).await;
            client.logout().await;
            result?;
        }
    }

    Ok(())
}

/// Load the config file and environment, then apply the command-line flags over them.
fn load_config(cli: &Cli) -> Result<Config> {
    let mut config = Config::load()?;
    apply_cli_overrides(cli, &mut config)?;
    if cli.debug {
        eprintln!("[debug] server: {}", config.server_address);
    }
    Ok(config)
}

/// Apply CLI flag overrides on top of loaded config.
fn apply_cli_overrides(cli: &Cli, config: &mut Config) -> Result<()> {
    if let Some(value) = &cli.server_address {
        config.server_address.clone_from(value);
    }
    if let Some(value) = &cli.user_private_key {
        config.user_private_key.clone_from(value);
    }
    if let Some(value) = &cli.user_private_key_file {
        config.user_private_key_file.clone_from(value);
    }
    if let Some(value) = &cli.user_password {
        config.user_password.clone_from(value);
    }
    if let Some(value) = &cli.mfa_mode {
        config.mfa_mode.clone_from(value);
    }
    if let Some(value) = &cli.mfa_totp_token {
        config.mfa_totp_token.clone_from(value);
    }
    if let Some(value) = cli.mfa_totp_offset {
        config.mfa_totp_offset = value;
    }
    if let Some(value) = cli.mfa_retrys {
        config.mfa_retrys = value;
    }
    if let Some(value) = &cli.mfa_delay {
        config.mfa_delay.clone_from(value);
    }
    if cli.tls_skip_verify {
        config.tls_skip_verify = true;
    }
    if let Some(value) = &cli.tls_client_cert {
        config.tls_client_cert.clone_from(value);
    }
    if let Some(value) = &cli.tls_client_private_key {
        config.tls_client_private_key.clone_from(value);
    }
    if let Some(path) = &cli.tls_client_cert_file {
        config.tls_client_cert = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read TLS client cert file: {path}"))?;
    }
    if let Some(path) = &cli.tls_client_private_key_file {
        config.tls_client_private_key = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read TLS client private key file: {path}"))?;
    }
    if let Some(value) = &cli.proxy {
        config.proxy.clone_from(value);
    }
    if let Some(value) = &cli.resolve {
        config.resolve.clone_from(value);
    }
    if let Some(value) = &cli.timeout {
        config.timeout.clone_from(value);
    }
    if let Some(value) = cli.workers {
        config.workers = value;
    }
    if cli.debug {
        config.debug = true;
    }
    Ok(())
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

    fn config_from_file(text: &str) -> Config {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, text).unwrap();
        Config::load_from(&path).unwrap()
    }

    fn overridden(arguments: &[&str], mut config: Config) -> Config {
        let cli = Cli::try_parse_from(arguments).unwrap();
        apply_cli_overrides(&cli, &mut config).unwrap();
        config
    }

    #[test]
    fn test_overrides_keep_the_file_settings_without_flags() {
        let config = config_from_file(
            "mfa_mode = \"none\"\nmfa_totp_offset = 5\nmfa_retrys = 7\n\
             mfa_delay = \"2s\"\ntimeout = \"30s\"\nworkers = 4\n",
        );

        let config = overridden(&["passbolt", "list", "resource"], config);

        assert_eq!(config.mfa_mode, "none");
        assert_eq!(config.mfa_totp_offset, 5);
        assert_eq!(config.mfa_retrys, 7);
        assert_eq!(config.mfa_delay, "2s");
        assert_eq!(config.timeout, "30s");
        assert_eq!(config.workers, 4);
    }

    #[test]
    fn test_overrides_put_the_flags_over_the_file() {
        let config = config_from_file("mfa_retrys = 7\nworkers = 4\ntimeout = \"30s\"\n");

        let config = overridden(
            &[
                "passbolt",
                "--mfa-retrys",
                "2",
                "--workers",
                "0",
                "--timeout",
                "5s",
                "list",
                "resource",
            ],
            config,
        );

        assert_eq!(config.mfa_retrys, 2);
        assert_eq!(config.workers, 0);
        assert_eq!(config.timeout, "5s");
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
