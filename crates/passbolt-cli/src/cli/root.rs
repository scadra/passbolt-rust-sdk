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

use clap::{Parser, Subcommand};

/// passbolt-rs — Passbolt CLI
#[derive(Parser, Debug)]
#[command(
    name = "passbolt",
    version,
    about = "Passbolt CLI — manage your Passbolt password manager",
    long_about = None
)]
pub struct Cli {
    /// Path to config file (default: ~/.config/passbolt/config.toml)
    #[arg(long, global = true, env = "PASSBOLT_CONFIG")]
    pub config: Option<String>,

    /// Passbolt server URL
    #[arg(long, global = true, env = "PASSBOLT_SERVER_ADDRESS")]
    pub server_address: Option<String>,

    /// PGP private key (armored, inline)
    #[arg(long, global = true, env = "PASSBOLT_USER_PRIVATE_KEY")]
    pub user_private_key: Option<String>,

    /// Path to PGP private key file
    #[arg(long, global = true, env = "PASSBOLT_USER_PRIVATE_KEY_FILE")]
    pub user_private_key_file: Option<String>,

    /// Master password (passphrase for the private key); also read from
    /// `PASSBOLT_USER_PASSWORD`, which `configure` never saves
    #[arg(long, global = true)]
    pub user_password: Option<String>,

    /// MFA mode: interactive-totp | non-interactive-totp | none [default: interactive-totp]
    #[arg(long, global = true, env = "PASSBOLT_MFA_MODE")]
    pub mfa_mode: Option<String>,

    /// TOTP token for non-interactive MFA; also read from `PASSBOLT_MFA_TOTP_TOKEN`, which
    /// `configure` never saves
    #[arg(long, global = true)]
    pub mfa_totp_token: Option<String>,

    /// TOTP clock offset in seconds [default: 0]
    #[arg(long, global = true, env = "PASSBOLT_MFA_TOTP_OFFSET")]
    pub mfa_totp_offset: Option<i64>,

    /// Number of MFA attempts, at most 3: the server disables the account after too many wrong
    /// codes [default: 3]
    #[arg(long, global = true, env = "PASSBOLT_MFA_RETRYS")]
    pub mfa_retrys: Option<u32>,

    /// Minimum delay between MFA attempts (e.g. 10s); a new attempt also waits for a new TOTP
    /// code [default: 10s]
    #[arg(long, global = true, env = "PASSBOLT_MFA_DELAY")]
    pub mfa_delay: Option<String>,

    /// Skip TLS certificate verification (insecure)
    #[arg(long, global = true, env = "PASSBOLT_TLS_SKIP_VERIFY")]
    pub tls_skip_verify: bool,

    /// TLS client certificate (PEM, inline)
    #[arg(long, global = true, env = "PASSBOLT_TLS_CLIENT_CERT")]
    pub tls_client_cert: Option<String>,

    /// TLS client private key (PEM, inline)
    #[arg(long, global = true, env = "PASSBOLT_TLS_CLIENT_PRIVATE_KEY")]
    pub tls_client_private_key: Option<String>,

    /// Path to TLS client certificate file
    #[arg(long, global = true, env = "PASSBOLT_TLS_CLIENT_CERT_FILE")]
    pub tls_client_cert_file: Option<String>,

    /// Path to TLS client private key file
    #[arg(long, global = true, env = "PASSBOLT_TLS_CLIENT_PRIVATE_KEY_FILE")]
    pub tls_client_private_key_file: Option<String>,

    /// HTTP proxy URL (e.g. `http://localhost:8080`)
    #[arg(long, global = true, env = "PASSBOLT_PROXY")]
    pub proxy: Option<String>,

    /// Pin a host name to an address: `host:port:address` (like `curl --resolve`)
    #[arg(long, global = true, env = "PASSBOLT_RESOLVE")]
    pub resolve: Option<String>,

    /// Request timeout (e.g. 1m, 30s) [default: 1m]
    #[arg(long, global = true, env = "PASSBOLT_TIMEOUT")]
    pub timeout: Option<String>,

    /// Number of parallel workers (0 = auto) [default: 0]
    #[arg(long, global = true, env = "PASSBOLT_WORKERS")]
    pub workers: Option<usize>,

    /// Enable debug output
    #[arg(long, global = true, env = "PASSBOLT_DEBUG")]
    pub debug: bool,

    /// Output JSON instead of a table
    #[arg(short = 'j', long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Configure passbolt-rs settings
    Configure(crate::cli::configure::ConfigureArgs),

    /// Verify server identity and persist tokens
    Verify(crate::cli::verify::VerifyArgs),

    /// Create resources, folders, users, groups
    #[command(visible_alias = "new")]
    Create(CreateArgs),

    /// Get a resource, folder, user, group or permissions
    #[command(visible_alias = "read")]
    Get(GetArgs),

    /// List resources, folders, users, groups
    #[command(visible_aliases = ["index", "ls", "filter", "search"])]
    List(ListArgs),

    /// Update resources, folders, users, groups
    #[command(visible_alias = "change")]
    Update(UpdateArgs),

    /// Delete resources, folders, users, groups
    #[command(visible_alias = "remove")]
    Delete(DeleteArgs),

    /// Share resources and folders
    Share(ShareArgs),

    /// Move resources and folders
    Move(MoveArgs),

    /// Exec a command with secrets injected via env vars
    Exec(crate::cli::exec::ExecArgs),

    /// Export to external formats
    Export(crate::cli::export::ExportArgs),

    /// Upgrade v4 resources to v5: their name, username, URI and description get encrypted
    /// (administrators)
    MigrateMetadata {
        /// Upgrade only the resources shared with other users or groups
        #[arg(long)]
        shared_only: bool,
    },

    /// Generate shell completions
    Completion {
        /// Shell type: bash | zsh | fish | powershell
        shell: clap_complete::Shell,
    },

    /// Generate CLI documentation (markdown or man pages)
    Gendoc(crate::cli::gendoc::GendocArgs),
}

// ── Create ────────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
pub struct CreateArgs {
    #[command(subcommand)]
    pub entity: CreateEntity,
}

// Parsed once per run: the size of the resource variant does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum CreateEntity {
    /// Create a resource (password entry)
    Resource {
        /// Resource type slug (v5-default, v5-note, password-and-description…).
        /// Default: from the fields given and the server's default version
        #[arg(short = 't', long = "type")]
        resource_type: Option<String>,
        /// Resource name; required unless given by --field name=… (or --type / --secret-field)
        #[arg(short = 'n', long)]
        name: Option<String>,
        /// Username / login
        #[arg(short = 'u', long)]
        username: Option<String>,
        /// URL / URI; repeat for several (v5 types)
        #[arg(long)]
        uri: Vec<String>,
        /// Password (prompted when the type needs one and it is not given)
        #[arg(short = 'p', long)]
        password: Option<String>,
        /// Description
        #[arg(short = 'd', long)]
        description: Option<String>,
        /// Secret note, the content of a v5-note
        #[arg(long)]
        note: Option<String>,
        /// PIN code, for v5-pin-code (4 to 12 digits)
        #[arg(long)]
        pin_code: Option<String>,
        /// Field of the v5 metadata (or v4 resource) as key=value, a value starting with [ or {
        /// read as JSON: --field 'icon={"type":"keepass-icon-set","value":42}'
        #[arg(long = "field")]
        field: Vec<String>,
        /// Secret field as key=value, a value starting with [ or { read as JSON
        #[arg(long = "secret-field")]
        secret_field: Vec<String>,
        /// Parent folder ID
        #[arg(short = 'f', long, alias = "folderParentID")]
        folder_parent_id: Option<String>,
        /// Expiry (RFC3339, duration "7d"/"48h", or "none")
        #[arg(long)]
        expiry: Option<String>,
        /// TOTP secret key (base32); enables TOTP for this resource
        #[arg(long)]
        totp_key: Option<String>,
        /// TOTP algorithm: SHA1 | SHA256 | SHA512 (default: SHA1)
        #[arg(long, default_value = "SHA1")]
        totp_algo: Option<String>,
        /// TOTP digits (default: 6)
        #[arg(long, default_value = "6")]
        totp_digits: Option<u32>,
        /// TOTP period in seconds (default: 30)
        #[arg(long, default_value = "30")]
        totp_period: Option<u64>,
    },
    /// Create a folder
    Folder {
        #[arg(short = 'n', long)]
        name: String,
        #[arg(short = 'f', long, alias = "folderParentID")]
        folder_parent_id: Option<String>,
    },
    /// Invite / create a user
    User {
        #[arg(short = 'u', long)]
        username: String,
        #[arg(short = 'f', long)]
        firstname: String,
        #[arg(short = 'l', long)]
        lastname: String,
        #[arg(short = 'r', long, default_value = "user")]
        role: String,
    },
    /// Create a group
    Group {
        #[arg(short = 'n', long)]
        name: String,
        /// Member user IDs
        #[arg(short = 'u', long)]
        user: Vec<String>,
        /// Manager user IDs (required)
        #[arg(short = 'm', long)]
        manager: Vec<String>,
    },
}

// ── Get ───────────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
pub struct GetArgs {
    #[command(subcommand)]
    pub entity: GetEntity,
}

#[derive(Subcommand, Debug)]
pub enum GetEntity {
    Resource(GetWithPermissions),
    #[command(hide = true)]
    ResourcePermissions(PermissionArgs),
    Folder(GetWithPermissions),
    #[command(hide = true)]
    FolderPermissions(PermissionArgs),
    User {
        #[arg(long)]
        id: String,
    },
    Group {
        #[arg(long)]
        id: String,
        #[arg(short = 'c', long)]
        column: Vec<String>,
    },
    /// Generate TOTP code for a resource
    Totp {
        #[arg(long)]
        id: String,
    },
}

/// `get resource --id X` or `get resource permission --id X`.
#[derive(clap::Args, Debug)]
#[command(subcommand_negates_reqs = true)]
pub struct GetWithPermissions {
    #[arg(long, required = true)]
    pub id: Option<String>,
    #[command(subcommand)]
    pub permission: Option<PermissionCommand>,
}

#[derive(Subcommand, Debug)]
pub enum PermissionCommand {
    /// Get the permissions
    #[command(visible_alias = "permissions")]
    Permission(PermissionArgs),
}

#[derive(clap::Args, Debug)]
pub struct PermissionArgs {
    #[arg(long)]
    pub id: String,
    /// Columns: `ID`, `Aco`, `AcoForeignKey`, `Aro`, `AroForeignKey`, `Type`,
    /// `CreatedTimestamp`, `ModifiedTimestamp`
    #[arg(short = 'c', long)]
    pub column: Vec<String>,
}

// ── List ──────────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
pub struct ListArgs {
    /// A CEL expression on the columns (see -c), e.g.
    /// `name == "x" && created_timestamp > timestamp("2024-01-01T00:00:00Z")`, or field
    /// conditions: field=value, field!=value, field~=contains, field^=prefix, field$=suffix
    #[arg(long, global = true)]
    pub filter: Vec<String>,
    #[command(subcommand)]
    pub entity: ListEntity,
}

#[derive(Subcommand, Debug)]
pub enum ListEntity {
    #[command(visible_alias = "resources")]
    Resource {
        #[arg(long)]
        favorite: bool,
        #[arg(long)]
        own: bool,
        /// Only the resources shared with this group (one: the server filters on one group)
        #[arg(short = 'g', long)]
        group: Vec<String>,
        /// Filter by folder ID(s) — may be repeated
        #[arg(short = 'f', long)]
        folder: Vec<String>,
        /// Search by name (case-insensitive substring)
        #[arg(short = 's', long)]
        search: Option<String>,
        /// Columns to display
        #[arg(short = 'c', long)]
        column: Vec<String>,
    },
    #[command(visible_alias = "folders")]
    Folder {
        #[arg(short = 's', long)]
        search: Option<String>,
        /// Filter by parent folder ID(s) — may be repeated
        #[arg(short = 'f', long)]
        folder: Vec<String>,
        /// Only the folders shared with one of these groups — may be repeated
        #[arg(short = 'g', long)]
        group: Vec<String>,
        #[arg(short = 'c', long)]
        column: Vec<String>,
    },
    #[command(visible_alias = "users")]
    User {
        /// Users in one of these groups — may be repeated
        #[arg(short = 'g', long)]
        group: Vec<String>,
        /// Users with access to this resource
        #[arg(short = 'r', long)]
        resource: Vec<String>,
        #[arg(short = 's', long)]
        search: Option<String>,
        /// Only administrators
        #[arg(short = 'a', long)]
        admin: bool,
        #[arg(short = 'c', long)]
        column: Vec<String>,
    },
    #[command(visible_alias = "groups")]
    Group {
        /// Groups with one of these members — may be repeated
        #[arg(short = 'u', long)]
        user: Vec<String>,
        /// Groups with one of these managers — may be repeated
        #[arg(short = 'm', long)]
        manager: Vec<String>,
        #[arg(short = 'c', long)]
        column: Vec<String>,
    },
}

// ── Update ────────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
pub struct UpdateArgs {
    #[command(subcommand)]
    pub entity: UpdateEntity,
}

// Parsed once per run: the size of the resource variant does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub enum UpdateEntity {
    Resource {
        #[arg(long)]
        id: String,
        #[arg(short = 'n', long)]
        name: Option<String>,
        #[arg(short = 'u', long)]
        username: Option<String>,
        /// URL / URI; repeat for several (v5 types), replaces the current ones
        #[arg(long)]
        uri: Vec<String>,
        #[arg(short = 'p', long)]
        password: Option<String>,
        #[arg(short = 'd', long)]
        description: Option<String>,
        /// Secret note (v5 types)
        #[arg(long)]
        note: Option<String>,
        /// PIN code, for v5-pin-code (4 to 12 digits)
        #[arg(long)]
        pin_code: Option<String>,
        /// Field of the v5 metadata (or v4 resource) as key=value, the value read as JSON if it is
        /// JSON: --field 'icon={"type":"keepass-icon-set","value":42}'
        #[arg(long = "field")]
        field: Vec<String>,
        /// Secret field as key=value, the value read as JSON if it is JSON
        #[arg(long = "secret-field")]
        secret_field: Vec<String>,
        #[arg(long)]
        expiry: Option<String>,
        /// TOTP secret key (base32); adds/replaces TOTP for this resource
        #[arg(long)]
        totp_key: Option<String>,
        /// TOTP algorithm: SHA1 | SHA256 | SHA512
        #[arg(long)]
        totp_algo: Option<String>,
        /// TOTP digits
        #[arg(long)]
        totp_digits: Option<u32>,
        /// TOTP period in seconds
        #[arg(long)]
        totp_period: Option<u64>,
        /// Remove TOTP from this resource
        #[arg(long)]
        remove_totp: bool,
    },
    Folder {
        #[arg(long)]
        id: String,
        #[arg(short = 'n', long)]
        name: String,
    },
    User {
        #[arg(long)]
        id: String,
        #[arg(short = 'f', long)]
        firstname: Option<String>,
        #[arg(short = 'l', long)]
        lastname: Option<String>,
        #[arg(short = 'r', long)]
        role: Option<String>,
    },
    Group {
        #[arg(long)]
        id: String,
        #[arg(short = 'n', long)]
        name: Option<String>,
        /// Members: added, or made members if they manage it
        #[arg(short = 'u', long)]
        user: Vec<String>,
        /// Managers: added, or made managers if they are members
        #[arg(short = 'm', long)]
        manager: Vec<String>,
        /// Remove the given users and managers instead
        #[arg(short = 'd', long)]
        delete: bool,
    },
}

// ── Delete ────────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
pub struct DeleteArgs {
    /// ID of what to delete
    #[arg(long, global = true)]
    pub id: Option<String>,
    #[command(subcommand)]
    pub entity: DeleteEntity,
}

#[derive(Subcommand, Debug)]
pub enum DeleteEntity {
    Resource,
    Folder {
        /// Also delete its sub-folders and the resources in them; without it, they move to the
        /// root
        #[arg(long)]
        cascade: bool,
    },
    /// Delete a user (administrators); what they alone own or manage blocks it until given to
    /// someone with --transfer-to
    User {
        /// Only list what blocks the deletion
        #[arg(long, conflicts_with = "transfer_to")]
        dry_run: bool,
        /// User (or group) who becomes owner of what the user alone owns, and manager of the
        /// groups they alone manage; they must already have access to it
        #[arg(long)]
        transfer_to: Option<String>,
    },
    /// Delete a group; what it alone owns blocks it until given to someone with --transfer-to
    Group {
        /// Only list what blocks the deletion
        #[arg(long, conflicts_with = "transfer_to")]
        dry_run: bool,
        /// User (or group) who becomes owner of what the group alone owns; they must already
        /// have access to it
        #[arg(long)]
        transfer_to: Option<String>,
    },
}

// ── Share ─────────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
pub struct ShareArgs {
    #[command(subcommand)]
    pub entity: ShareEntity,
}

#[derive(Subcommand, Debug)]
pub enum ShareEntity {
    Resource {
        #[arg(long)]
        id: String,
        /// Permission type: 1=Read, 7=Update, 15=Owner, -1=Revoke
        #[arg(
            short = 't',
            long,
            default_value = "1",
            allow_negative_numbers = true,
            value_parser = parse_permission_type
        )]
        r#type: i32,
        /// User IDs to share with
        #[arg(short = 'u', long)]
        user: Vec<String>,
        /// Group IDs to share with
        #[arg(short = 'g', long)]
        group: Vec<String>,
    },
    Folder {
        #[arg(long)]
        id: String,
        /// Permission type: 1=Read, 7=Update, 15=Owner, -1=Revoke
        #[arg(
            short = 't',
            long,
            default_value = "1",
            allow_negative_numbers = true,
            value_parser = parse_permission_type
        )]
        r#type: i32,
        #[arg(short = 'u', long)]
        user: Vec<String>,
        #[arg(short = 'g', long)]
        group: Vec<String>,
        /// Also change the sub-folders and resources you own, as the browser extension does
        #[arg(long)]
        with_content: bool,
    },
}

// ── Move ──────────────────────────────────────────────────────────────────────

#[derive(clap::Args, Debug)]
pub struct MoveArgs {
    #[command(subcommand)]
    pub entity: MoveEntity,
}

#[derive(Subcommand, Debug)]
pub enum MoveEntity {
    Resource {
        #[arg(long)]
        id: String,
        /// Target folder ID (empty = root)
        #[arg(short = 'f', long, alias = "folderParentID")]
        folder_parent_id: Option<String>,
        /// Also change its permissions as the browser extension does: drop those it got from the
        /// folder it leaves, add the target folder's, the higher level winning (owners only)
        #[arg(long, requires = "folder_parent_id")]
        with_folder_permissions: bool,
    },
    Folder {
        #[arg(long)]
        id: String,
        /// Target folder ID (empty = root)
        #[arg(short = 'f', long, alias = "folderParentID")]
        folder_parent_id: Option<String>,
        /// Also change its permissions as for a resource, then copy that change onto the content
        /// the user owns (owners only)
        #[arg(long, requires = "folder_parent_id")]
        with_folder_permissions: bool,
    },
}

/// A permission type the server knows: 1 (read), 7 (update), 15 (owner), or -1 to revoke.
fn parse_permission_type(value: &str) -> Result<i32, String> {
    match value.parse::<i32>() {
        Ok(permission_type @ (1 | 7 | 15 | -1)) => Ok(permission_type),
        _ => Err(format!(
            "{value} is not a permission type: 1 (read), 7 (update), 15 (owner) or -1 (revoke)"
        )),
    }
}
