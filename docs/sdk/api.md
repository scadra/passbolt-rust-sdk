---
title: API reference
sidebar_position: 11
---

# API reference

The API of the FFI bindings (Python, Java, Android/Kotlin, .NET, Go, Ruby, Swift), from
`crates/passbolt-ffi/src`. Every binding has these clients, methods, functions and records, under
the names of its language: see [Names in each language](#names-in-each-language). The JavaScript
API is close, with its own shape: see [JavaScript](#javascript).

The names below are the Rust ones, in snake_case. The types are written this way:

| Notation | |
|---|---|
| `string`, `bool` | A string, a boolean |
| `u16`, `u32`, `u64`, `i32`, `f64` | Unsigned, signed and floating-point numbers, of 16, 32 or 64 bits |
| `T?` | Optional: `None`, `null`, `nil` or the value |
| `[T]` | A list |
| `bytes` | A byte array |
| `nothing` | No value |
| `= value` | The default, in the languages that have default arguments |

Every method of the clients can fail with a [`PassboltError`](#passbolterror), and so can the
functions, except `default_password_policies`, `generate_pin_code`, `secret_entropy` and
`secret_strength`. Dates are RFC 3339 strings.

## Clients

`PassboltClient` blocks on each call. `AsyncPassboltClient` has the same constructors and methods,
awaited: see [The async client](#the-async-client).

| Constructor or method | Arguments | Returns | Description |
|---|---|---|---|
| `login` (constructor) | `server_url: string`, `private_key_armored: string`, `passphrase: string` | client | Authenticate against a Passbolt server and return a client session. |
| `login_with_config` (constructor) | `server_url: string`, `private_key_armored: string`, `passphrase: string`, `options: LoginOptions` | client | Authenticate with `options`, the pinned server and metadata keys among them. |
| `user_id` | none | `string` | Get the current user's ID. Does not fail, and is not awaited on the async client. |
| `base_url` | none | `string` | Get the server base URL. Does not fail, and is not awaited on the async client. |

`login` is `login_with_config` with the default [`LoginOptions`](#loginoptions). A request waits
60 seconds by default (`timeout_seconds`).

## Methods

The methods of both clients, from the `client_methods!` list of `crates/passbolt-ffi/src/lib.rs`.
Permission types are Passbolt's: `1` read, `7` update, `15` owner, `-1` to revoke.

### Session

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `logout` | none | `nothing` | Terminate the server-side session. |
| `check_auth` | none | `bool` | Check if the session is still valid. |
| `keep_alive` | none | `nothing` | Keep the session alive, as the browser extension does every few minutes. |

### Resources

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `list_resources` | `search: string? = none`, `favorites_only: bool = false`, `owned_by_me: bool = false` | `[Resource]` | List resources with optional search and filters. |
| `list_resource_views` | `search: string? = none`, `with_secrets: bool = false` | `[ResourceView]` | Resources with their v5 metadata decrypted, searched by their decrypted name; their secrets too with `with_secrets`. One that does not decrypt has an `error`. |
| `get_resource_view` | `id: string` | `ResourceView` | A resource with its v5 metadata and its secret decrypted, for every resource type. |
| `get_resource` | `id: string` | `Resource` | Get a single resource by ID. |
| `get_resources_by_ids` | `ids: [string]` | `[Resource]` | Get multiple resources by IDs. |
| `decrypt_resource_secret` | `resource_id: string` | `SecretData` | Decrypt a resource's secret. Pass the resource obtained from `get_resource`. |
| `create_resource` | `resource: NewResource` | `Resource` | Create a resource of any type. Returns the created resource. |
| `update_resource` | `id: string`, `changes: ResourceChanges` | `Resource` | Update a resource; the fields left out keep their value. |
| `move_resource` | `id: string`, `folder_id: string? = none` | `nothing` | Move a resource into a folder, or to the root without one. |
| `delete_resource` | `id: string` | `nothing` | Delete a resource. |
| `delete_resources` | `ids: [string]` | `nothing` | Bulk delete resources. |
| `get_resource_permissions` | `id: string` | `[Permission]` | Get permissions for a resource. |

### Folders

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `list_folders` | `search: string? = none` | `[Folder]` | List all folders. |
| `get_folder` | `id: string` | `Folder` | Get a single folder by ID. |
| `get_folder_tree` | none | `[FolderTreeNode]` | Build a folder tree from the flat folder list. |
| `create_folder` | `name: string`, `folder_parent_id: string? = none` | `Folder` | Create a folder, at the root or in `folder_parent_id`; in a parent folder it gets the parent's permissions. |
| `rename_folder` | `id: string`, `name: string` | `Folder` | Rename a folder. |
| `move_folder` | `id: string`, `folder_id: string? = none` | `nothing` | Move a folder into another one, or to the root without one. |
| `delete_folder` | `id: string` | `nothing` | Delete a folder; its content moves to the root. |
| `delete_folder_with_content` | `id: string` | `nothing` | Delete a folder with its sub-folders and the resources the user may delete in them. |
| `get_folder_permissions` | `id: string` | `[Permission]` | Get permissions for a folder. |

### Sharing

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `share_resource` | `id: string`, `permission_type: i32`, `user_ids: [string] = []`, `group_ids: [string] = []` | `nothing` | Share a resource with users and groups (`permission_type` 1, 7 or 15), or revoke with -1. |
| `share_folder` | `id: string`, `permission_type: i32`, `user_ids: [string] = []`, `group_ids: [string] = []`, `with_content: bool = false` | `nothing` | Share a folder, and with `with_content` the sub-folders and resources the user owns. |
| `search_aros` | `search: string` | `[Aro]` | Search for users and groups (AROs) for sharing. |

### Users

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `list_users` | `search: string? = none`, `group_id: string? = none`, `admin_only: bool = false` | `[User]` | List all users. |
| `get_me` | none | `User` | Get the currently logged-in user. |
| `get_user` | `id: string` | `User` | Get a user by ID. |
| `create_user` | `username: string`, `first_name: string`, `last_name: string`, `role: string` | `User` | Create a user with the role named `role` (`user` or `admin`). |
| `update_user` | `id: string`, `first_name: string? = none`, `last_name: string? = none`, `role: string? = none` | `User` | Update a user's names or role; `None` keeps the value. |
| `delete_user` | `id: string` | `nothing` | Delete a user. |
| `delete_user_dry_run` | `id: string` | `UserDeleteDryRun` | Preview the impact of deleting a user. |
| `user_delete_blockers` | `id: string` | `DeleteBlockers` | What blocks deleting the user: what they alone own or manage. |
| `delete_user_with_transfer` | `id: string`, `successor_id: string` | `nothing` | Delete a user, giving what they alone own or manage to `successor_id`, a user or a group that already has access to it. |

### Groups

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `list_groups` | none | `[Group]` | List all groups. |
| `get_group` | `id: string` | `Group` | Get a group by ID. |
| `create_group` | `name: string`, `member_ids: [string] = []`, `manager_ids: [string] = []` | `Group` | Create a group; a manager is also a member. |
| `update_group` | `id: string`, `name: string? = none`, `add_member_ids: [string] = []`, `add_manager_ids: [string] = []`, `remove_member_ids: [string] = []` | `Group` | Rename a group and change its members: the removed ones first, then the added ones, who get the secrets of the group's resources. Giving a user the role they have, or removing a non-member, is an error. |
| `delete_group` | `id: string` | `nothing` | Delete a group. |
| `delete_group_dry_run` | `id: string` | `GroupDeleteDryRun` | Preview the impact of deleting a group. |
| `group_delete_blockers` | `id: string` | `DeleteBlockers` | What blocks deleting the group: what it alone owns. |
| `delete_group_with_transfer` | `id: string`, `successor_id: string` | `nothing` | Delete a group, giving what it alone owns to `successor_id`, a user or a group that already has access to it. |

### Tags

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `get_tags` | none | `[Tag]` | List all tags. |
| `add_tag_to_resource` | `resource_id: string`, `slug: string` | `[Tag]` | Add a tag to a resource, keeping its other tags; returns the resource's tags. |
| `set_resource_tags` | `resource_id: string`, `slugs: [string]` | `[Tag]` | Replace all the tags of a resource; returns its tags. |
| `rename_tag` | `id: string`, `slug: string` | `Tag` | Rename a tag. |
| `delete_tag` | `id: string` | `nothing` | Delete a tag. |

### Comments

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `get_comments` | `resource_id: string` | `[Comment]` | Get comments for a resource. |
| `create_comment` | `resource_id: string`, `content: string`, `parent_id: string? = none` | `Comment` | Create a comment on a resource. |
| `delete_comment` | `id: string` | `nothing` | Delete a comment. |

### Favorites

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `add_favorite` | `resource_id: string` | `Favorite` | Add a resource to favorites. |
| `remove_favorite` | `favorite_id: string` | `nothing` | Remove a favorite. |

### Password expiry

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `get_password_expiry_settings` | none | `PasswordExpirySettings` | Get password expiry settings. |
| `save_password_expiry_settings` | `settings: PasswordExpirySettings` | `PasswordExpirySettings` | Create or update the password expiry settings (admin). |
| `delete_password_expiry_settings` | `id: string` | `nothing` | Delete the password expiry settings (admin): the defaults apply again. |

### Password policies

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `get_password_policies` | none | `PasswordPolicies` | The password policies of the organization, for `generate_secret`. |
| `save_password_policies` | `policies: PasswordPolicies` | `PasswordPolicies` | Save the password policies of the organization (administrator, Passbolt Pro). |

### Metadata and resource types

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `metadata_key_fingerprint` | none | `string?` | The fingerprint of the active shared metadata key, to pin in `LoginOptions.metadata_key_fingerprint`; `None` without one. |
| `list_resource_types` | none | `[ResourceType]` | The resource types of the server. |
| `get_metadata_types_settings` | none | `MetadataTypesSettings` | Which metadata versions the organization creates and allows. |
| `save_metadata_types_settings` | `settings: MetadataTypesSettings` | `MetadataTypesSettings` | Save the metadata types settings (admin). |
| `get_metadata_keys_settings` | none | `MetadataKeysSettings` | How metadata keys are used in the organization. |
| `save_metadata_keys_settings` | `settings: MetadataKeysSettings` | `MetadataKeysSettings` | Save the metadata keys settings (admin). |

### Have I Been Pwned

| Method | Arguments | Returns | Description |
|---|---|---|---|
| `check_password_pwned` | `password: string` | `u64` | Check if a password has been exposed in data breaches. Returns the number of times found (0 = not breached). |

## Functions

Exported functions, outside any client: they need no session. In Java and C# they are static
methods of `PassboltFfi`.

| Function | Arguments | Returns | Description |
|---|---|---|---|
| `fetch_server_key` | `server_url: string`, `tls_skip_verify: bool = false` | `ServerKey` | The server public key, to pin in `LoginOptions.server_public_key` once the user confirmed its fingerprint. |
| `decrypt_message` | `armored_message: string`, `private_key_armored: string`, `passphrase: string` | `bytes` | Decrypt a PGP-armored message with a private key. |
| `encrypt_message` | `plaintext: bytes`, `public_keys_armored: [string]` | `string` | Encrypt a plaintext message for one or more PGP public keys. Returns the PGP-armored ciphertext. |
| `get_key_fingerprint` | `private_key_armored: string` | `string` | Parse a PGP private key and return its fingerprint (hex uppercase). |
| `default_password_policies` | none | `PasswordPolicies` | The policies of a server without settings: passwords of 18 characters by default. |
| `generate_password` | `settings: PasswordGeneratorSettings` | `string` | A password following `settings`, as the extension generates it. |
| `generate_passphrase` | `settings: PassphraseGeneratorSettings` | `string` | A passphrase of words of the EFF list following `settings`. |
| `generate_secret` | `policies: PasswordPolicies` | `string` | A secret from the default generator of `policies`, those of `PassboltClient.get_password_policies` for instance. |
| `generate_pin_code` | `length: u32 = 4` | `string` | A PIN code of `length` digits, brought within 4 to 12. |
| `secret_entropy` | `secret: string` | `f64` | The entropy of `secret` in bits, measured as the extension does: as a passphrase when it is words of the list joined by one separator. |
| `secret_strength` | `secret: string` | `Strength` | The strength the extension shows for `secret`. |

## Records and enums

Records are plain values. A field with a default can be left out where the language has default
arguments; Java builds the records it writes with builders.

### Login

#### LoginOptions

How to log in, beyond the credentials.

| Field | Type | Default | |
|---|---|---|---|
| `tls_skip_verify` | `bool` | `false` |  |
| `proxy` | `string?` | `none` |  |
| `mfa_totp_token` | `string?` | `none` | The base32 TOTP secret answering the MFA challenge without prompting. |
| `server_public_key` | `string?` | `none` | The armored server public key pinned with `fetch_server_key`: each login then checks the server holds its private key. |
| `metadata_key_fingerprint` | `string?` | `none` | The shared metadata key fingerprint pinned with `PassboltClient.metadata_key_fingerprint`: shared metadata is then only encrypted for that key. |
| `timeout_seconds` | `u64?` | `none` | Seconds a request may take; `None` is 60, `0` waits forever. |
| `client_certificate_pem` | `string?` | `none` | PEM certificate and private key, for a server asking for a client certificate (mTLS). |
| `client_key_pem` | `string?` | `none` |  |

#### ServerKey

The server public key, to pin.

| Field | Type | |
|---|---|---|
| `fingerprint` | `string` | Computed from the key, checked against the one the server announces. |
| `armored_key` | `string` |  |

### Resources

#### ResourceView

A resource with its v5 metadata decrypted, and its secret when it was asked for.

| Field | Type | |
|---|---|---|
| `id` | `string` |  |
| `name` | `string` |  |
| `username` | `string` |  |
| `uri` | `string` | The first of `uris`. |
| `uris` | `[string]` |  |
| `description` | `string` | The v5 metadata description, else the v4 one. |
| `folder_parent_id` | `string?` |  |
| `resource_type` | `string?` | The type slug; `None` for a type the server does not list. |
| `resource_type_id` | `string?` |  |
| `personal` | `bool?` |  |
| `metadata_key_type` | `string?` | `user_key` (personal) or `shared_key` for v5 resources. |
| `created` | `string?` |  |
| `modified` | `string?` |  |
| `expired` | `string?` |  |
| `password` | `string?` |  |
| `totp` | `TotpData?` |  |
| `metadata_json` | `string` | The decrypted v5 metadata, or the v4 fields, as a JSON object: the icon and custom fields among them. |
| `secret_json` | `string?` | The decrypted secret as a JSON object, when it was asked for and decrypted. |
| `error` | `string?` | Why the metadata or the secret could not be decrypted. |

#### NewResource

A resource to create. Its type comes from the fields set and the server's default version, unless `resource_type` names it; fields the type does not have are refused.

| Field | Type | Default | |
|---|---|---|---|
| `name` | `string` | required |  |
| `resource_type` | `string?` | `none` | The type slug: `password-and-description`, `v5-default`, `v5-totp-standalone`… |
| `username` | `string?` | `none` |  |
| `uris` | `[string]` | `[]` | v4 types have a single URI. |
| `description` | `string?` | `none` |  |
| `note` | `string?` | `none` | The secret note of v5 types. |
| `password` | `string?` | `none` |  |
| `totp` | `TotpData?` | `none` |  |
| `pin_code` | `string?` | `none` |  |
| `folder_parent_id` | `string?` | `none` |  |
| `expired` | `string?` | `none` | Expiry date, RFC 3339. |
| `metadata_fields_json` | `string?` | `none` | A JSON object of fields set as given, last: the v5 metadata or v4 resource fields. |
| `secret_fields_json` | `string?` | `none` | A JSON object of secret fields set as given, last. |

#### ResourceChanges

Changes to a resource; `None` keeps the current value.

| Field | Type | Default | |
|---|---|---|---|
| `name` | `string?` | `none` |  |
| `username` | `string?` | `none` |  |
| `uris` | `[string]?` | `none` | v4 types have a single URI. |
| `description` | `string?` | `none` |  |
| `note` | `string?` | `none` | The secret note of v5 types. |
| `password` | `string?` | `none` |  |
| `pin_code` | `string?` | `none` |  |
| `totp` | `TotpData?` | `none` | The TOTP fields to change. Adding a TOTP switches to the type with a TOTP. |
| `remove_totp` | `bool` | `false` | Switches to the type without TOTP. |
| `expired` | `string?` | `none` | The new expiry date, RFC 3339. |
| `clear_expiry` | `bool` | `false` | Clears the expiry. |
| `metadata_fields_json` | `string?` | `none` | A JSON object of fields set as given, last: the v5 metadata or v4 resource fields. |
| `secret_fields_json` | `string?` | `none` | A JSON object of secret fields set as given, last. |

#### TotpData

| Field | Type | |
|---|---|---|
| `secret_key` | `string?` |  |
| `algorithm` | `string?` |  |
| `digits` | `u32?` |  |
| `period` | `u64?` |  |
| `issuer` | `string?` |  |

#### Resource

| Field | Type | Default | |
|---|---|---|---|
| `id` | `string` | required |  |
| `name` | `string` | required |  |
| `username` | `string?` | required |  |
| `uri` | `string?` | required |  |
| `description` | `string?` | required |  |
| `folder_parent_id` | `string?` | required |  |
| `resource_type_id` | `string?` | required |  |
| `created` | `string?` | required |  |
| `modified` | `string?` | required |  |
| `created_by` | `string?` | required |  |
| `modified_by` | `string?` | required |  |
| `personal` | `bool?` | required |  |
| `favorite` | `Favorite?` | required |  |
| `secrets` | `[Secret]` | required |  |
| `permissions` | `[Permission]` | required |  |
| `expired` | `string?` | required |  |
| `metadata` | `string?` | `none` | v5 only: PGP-armored encrypted metadata. |
| `metadata_key_id` | `string?` | `none` |  |
| `metadata_key_type` | `string?` | `none` |  |

#### Secret

| Field | Type | |
|---|---|---|
| `id` | `string?` |  |
| `resource_id` | `string?` |  |
| `user_id` | `string?` |  |
| `data` | `string?` |  |
| `created` | `string?` |  |
| `modified` | `string?` |  |

#### SecretData

| Field | Type | |
|---|---|---|
| `password` | `string?` |  |
| `description` | `string?` |  |
| `totp` | `TotpData?` |  |
| `raw` | `string?` |  |

#### Permission

| Field | Type | |
|---|---|---|
| `id` | `string?` |  |
| `aco` | `string?` |  |
| `aco_foreign_key` | `string?` |  |
| `aro` | `string?` |  |
| `aro_foreign_key` | `string?` |  |
| `permission_type` | `i32?` |  |
| `created` | `string?` |  |
| `modified` | `string?` |  |
| `user` | `User?` |  |
| `group` | `Group?` |  |

#### Favorite

| Field | Type | |
|---|---|---|
| `id` | `string?` |  |
| `foreign_model` | `string?` |  |
| `foreign_key` | `string?` |  |
| `created` | `string?` |  |

#### ResourceType

A resource type of the server; `definition` is its JSON Schema, as JSON.

| Field | Type | |
|---|---|---|
| `id` | `string` |  |
| `slug` | `string` |  |
| `name` | `string?` |  |
| `definition` | `string?` |  |

### Folders

#### Folder

| Field | Type | |
|---|---|---|
| `id` | `string` |  |
| `name` | `string` |  |
| `folder_parent_id` | `string?` |  |
| `created` | `string?` |  |
| `modified` | `string?` |  |
| `created_by` | `string?` |  |
| `modified_by` | `string?` |  |
| `personal` | `bool?` |  |
| `permissions` | `[Permission]` |  |

#### FolderTreeNode

| Field | Type | |
|---|---|---|
| `folder` | `Folder` |  |
| `children` | `[FolderTreeNode]` |  |

### Users and groups

#### User

| Field | Type | |
|---|---|---|
| `id` | `string` |  |
| `username` | `string?` |  |
| `role_id` | `string?` |  |
| `created` | `string?` |  |
| `modified` | `string?` |  |
| `active` | `bool?` |  |
| `deleted` | `bool?` |  |
| `profile` | `UserProfile?` |  |
| `role` | `Role?` |  |
| `gpg_key` | `GpgKey?` |  |

#### UserProfile

| Field | Type | |
|---|---|---|
| `first_name` | `string?` |  |
| `last_name` | `string?` |  |

#### Role

| Field | Type | |
|---|---|---|
| `id` | `string?` |  |
| `name` | `string?` |  |

#### GpgKey

| Field | Type | |
|---|---|---|
| `id` | `string?` |  |
| `user_id` | `string?` |  |
| `armored_key` | `string?` |  |
| `bits` | `u32?` |  |
| `fingerprint` | `string?` |  |
| `key_created` | `string?` |  |

#### Group

| Field | Type | |
|---|---|---|
| `id` | `string` |  |
| `name` | `string` |  |
| `created` | `string?` |  |
| `modified` | `string?` |  |
| `created_by` | `string?` |  |
| `modified_by` | `string?` |  |
| `deleted` | `bool?` |  |
| `groups_users` | `[GroupUser]` |  |

#### GroupUser

| Field | Type | |
|---|---|---|
| `id` | `string?` |  |
| `group_id` | `string?` |  |
| `user_id` | `string?` |  |
| `is_admin` | `bool?` |  |
| `created` | `string?` |  |

#### Aro

| Field | Type | |
|---|---|---|
| `id` | `string` |  |
| `aro_type` | `string?` |  |
| `username` | `string?` |  |
| `profile` | `UserProfile?` |  |
| `name` | `string?` |  |

#### UserDeleteDryRun

| Field | Type | |
|---|---|---|
| `resources_sole_owner_count` | `u32` |  |
| `folders_sole_owner_count` | `u32` |  |
| `groups_sole_manager_count` | `u32` |  |

#### GroupDeleteDryRun

| Field | Type | |
|---|---|---|
| `resources_sole_group_count` | `u32` |  |
| `folders_sole_group_count` | `u32` |  |

#### DeleteBlockers

What blocks deleting a user or a group: each item needs a new owner, each group a new manager.

| Field | Type | |
|---|---|---|
| `resources` | `[OwnedItem]` |  |
| `folders` | `[OwnedItem]` |  |
| `groups` | `[ManagedGroup]` |  |
| `groups_to_delete` | `[string]` | Groups the deleted user is the only member of: deleted with them. |

#### OwnedItem

A shared resource or folder only the deleted user or group owns, with its permissions.

| Field | Type | |
|---|---|---|
| `id` | `string` |  |
| `permissions` | `[Permission]` |  |

#### ManagedGroup

A group with other members that only the deleted user manages, with its memberships.

| Field | Type | |
|---|---|---|
| `id` | `string` |  |
| `name` | `string` |  |
| `groups_users` | `[GroupUser]` |  |

### Tags and comments

#### Tag

| Field | Type | |
|---|---|---|
| `id` | `string` |  |
| `slug` | `string` |  |
| `is_shared` | `bool?` |  |
| `created` | `string?` |  |
| `modified` | `string?` |  |

#### Comment

| Field | Type | |
|---|---|---|
| `id` | `string` |  |
| `parent_id` | `string?` |  |
| `foreign_key` | `string?` |  |
| `foreign_model` | `string?` |  |
| `content` | `string` |  |
| `created` | `string?` |  |
| `modified` | `string?` |  |
| `created_by` | `string?` |  |
| `modified_by` | `string?` |  |
| `creator` | `User?` |  |

### Settings

#### PasswordExpirySettings

| Field | Type | |
|---|---|---|
| `id` | `string?` |  |
| `default_expiry_period_days` | `u32?` |  |
| `policy_override` | `bool?` |  |
| `automatic_expiry` | `bool?` |  |
| `automatic_update` | `bool?` |  |

#### MetadataTypesSettings

Which metadata versions the organization creates and allows (admin settings).

| Field | Type | |
|---|---|---|
| `default_resource_types` | `string?` |  |
| `default_folder_type` | `string?` |  |
| `default_tag_type` | `string?` |  |
| `default_comment_type` | `string?` |  |
| `allow_creation_of_v5_resources` | `bool?` |  |
| `allow_creation_of_v5_folders` | `bool?` |  |
| `allow_creation_of_v5_tags` | `bool?` |  |
| `allow_creation_of_v5_comments` | `bool?` |  |
| `allow_creation_of_v4_resources` | `bool?` |  |
| `allow_creation_of_v4_folders` | `bool?` |  |
| `allow_creation_of_v4_tags` | `bool?` |  |
| `allow_creation_of_v4_comments` | `bool?` |  |

#### MetadataKeysSettings

How metadata keys are used in the organization (admin settings).

| Field | Type | |
|---|---|---|
| `allow_usage_of_personal_keys` | `bool?` |  |
| `zero_knowledge_key_share` | `bool?` |  |

### Password generator

#### PasswordPolicies

The password policies of the organization: the generator to use and its settings.

| Field | Type | Default | |
|---|---|---|---|
| `default_generator` | `GeneratorType` | required |  |
| `password_generator_settings` | `PasswordGeneratorSettings` | required |  |
| `passphrase_generator_settings` | `PassphraseGeneratorSettings` | required |  |
| `external_dictionary_check` | `bool` | `true` | Check new passwords against Have I Been Pwned. |
| `source` | `string?` | `none` | Where the server read them: `default`, `file`, `env`, `db`… |
| `id` | `string?` | `none` | Set once an administrator saved them (Passbolt Pro). |

#### PasswordGeneratorSettings

How passwords are generated; the defaults are the server's and the extension's: 18 characters of every set but emoji, without look-alike characters.

| Field | Type | Default | |
|---|---|---|---|
| `length` | `u32` | `18` |  |
| `min_length` | `u32` | `8` |  |
| `max_length` | `u32` | `128` |  |
| `mask_upper` | `bool` | `true` | `A-Z` |
| `mask_lower` | `bool` | `true` | `a-z` |
| `mask_digit` | `bool` | `true` | `0-9` |
| `mask_parenthesis` | `bool` | `true` | `{ [ ( \| ) ] }` |
| `mask_emoji` | `bool` | `false` | The emoticons of Unicode 6. |
| `mask_char1` | `bool` | `true` | `# $ % & @ ^ ~` |
| `mask_char2` | `bool` | `true` | `. , : ;` |
| `mask_char3` | `bool` | `true` | `'`, `"` and the backtick |
| `mask_char4` | `bool` | `true` | `/ \ _ -` |
| `mask_char5` | `bool` | `true` | `< * + ! ? =` |
| `exclude_look_alike_chars` | `bool` | `true` | Leaves out `O l \| I 0 1`. |

#### PassphraseGeneratorSettings

How passphrases are generated; the defaults are the server's and the extension's: 9 lowercase words of the EFF list joined by spaces.

| Field | Type | Default | |
|---|---|---|---|
| `words` | `u32` | `9` |  |
| `word_separator` | `string` | `" "` |  |
| `word_case` | `WordCase?` | `none` | `None` is lowercase. |
| `min_words` | `u32` | `4` |  |
| `max_words` | `u32` | `40` |  |

#### GeneratorType

What the generator makes by default.

| Variant | |
|---|---|
| `Password` |  |
| `Passphrase` |  |

#### WordCase

The case of the words of a passphrase.

| Variant | |
|---|---|
| `Lowercase` |  |
| `Uppercase` |  |
| `Camelcase` | The first letter of each word in capital. |

#### Strength

The strength the extension shows for a secret.

| Variant | |
|---|---|
| `NotAvailable` | No secret. |
| `VeryWeak` | Under 60 bits. |
| `Weak` | From 60 bits. |
| `Fair` | From 80 bits. |
| `Strong` | From 112 bits. |
| `VeryStrong` | From 128 bits. |

### Error type

The error of every call; see [Errors](#errors) for its name in each language.

#### PassboltError

FFI-safe error type exposed to all target languages.

| Variant | Fields |
|---|---|
| `Transport` | `reason: string` |
| `Auth` | `reason: string` |
| `Crypto` | `reason: string` |
| `Api` | `status: u16, reason: string` |
| `NotFound` | `reason: string` |
| `Config` | `reason: string` |
| `InvalidArgument` | `reason: string` |
| `Other` | `reason: string` |

### Not taken by any method

Exported with the records, but no method takes them: the list methods take their fields as
arguments.

#### ResourceQuery

| Field | Type | |
|---|---|---|
| `search` | `string?` |  |
| `favorites_only` | `bool` |  |
| `owned_by_me` | `bool` |  |

#### FolderQuery

| Field | Type | |
|---|---|---|
| `search` | `string?` |  |

#### UserQuery

| Field | Type | |
|---|---|---|
| `search` | `string?` |  |
| `group_id` | `string?` |  |
| `admin_only` | `bool` |  |

## Names in each language

The generators of UniFFI name everything after the Rust names, in the case of the language:

| Language | Methods and functions | Fields | Enum cases | Example |
|---|---|---|---|---|
| Python | snake_case | snake_case | `WordCase.CAMELCASE` | `client.get_resources_by_ids(ids)`, `server_key.armored_key` |
| Ruby | snake_case | snake_case | `Passbolt::WordCase::CAMELCASE` | `client.get_resources_by_ids(ids)` |
| Kotlin | camelCase | camelCase | `WordCase.CAMELCASE` | `client.getResourcesByIds(ids)`, `serverKey.armoredKey` |
| Swift | camelCase, with argument labels | camelCase | `.camelcase` | `client.getResourcesByIds(ids: ids)` |
| Java | camelCase | camelCase accessors | `WordCase.CAMELCASE` | `client.getResourcesByIds(ids)`, `serverKey.armoredKey()` |
| C# | PascalCase | camelCase | `WordCase.Camelcase` | `client.GetResourcesByIds(ids)`, `serverKey.armoredKey` |
| Go | PascalCase, Go initialisms | PascalCase, Go initialisms | `WordCaseCamelcase` | `client.GetResourcesByIDs(ids)`, `serverKey.ArmoredKey` |

Where the functions live:

| Language | Constructors | Functions |
|---|---|---|
| Python | `passbolt.Client.login(...)`, `passbolt.Client.login_with_config(...)` | `passbolt.fetch_server_key(...)` |
| Ruby | `Passbolt::Client.login(...)` | `Passbolt.fetch_server_key(...)` |
| Kotlin | `PassboltClient.login(...)`, `PassboltClient.loginWithConfig(...)` | functions of the package `com.passbolt.sdk`: `fetchServerKey(...)` |
| Swift | `PassboltClient.login(serverUrl:privateKeyArmored:passphrase:)` | global functions: `fetchServerKey(serverUrl:)` |
| Java | `PassboltClient.login(...)`, `PassboltClient.loginWithConfig(...)` | static methods of `PassboltFfi`: `PassboltFfi.fetchServerKey(url, false)` |
| C# | `PassboltClient.Login(...)`, `PassboltClient.LoginWithConfig(...)` | static methods of `PassboltFfi`: `PassboltFfi.FetchServerKey(url)` |
| Go | `passbolt.PassboltClientLogin(...)`, `passbolt.PassboltClientLoginWithConfig(...)` | `passbolt.FetchServerKey(url, false)` |

What each binding adds or changes:

- **Python.** `passbolt.Client.login` takes the fields of `LoginOptions` as keywords
  (`server_public_key=`, `mfa_totp_token=`…), and the client is a context manager that logs out.
  `generate_password`, `generate_passphrase` and `generate_secret` take their settings as an
  optional argument. `passbolt.PermissionType` names the permission types (`READ`, `UPDATE`,
  `OWNER`, `REVOKE`). See [Python](python.md).
- **Ruby.** `Passbolt::Client.login` takes the login options as keywords and a block that logs
  out. Flags and optional arguments are keywords (`list_resources(search = nil, favorites_only:
  false, owned_by_me: false)`, `share_resource(id, permission_type:, user_ids: [], group_ids:
  [])`); `Passbolt.generate_password` and `Passbolt.generate_passphrase` take the fields of
  their settings as keywords. `Passbolt::PermissionType` names the permission types. See
  [Ruby](ruby.md).
- **Kotlin, Swift, C#.** The arguments and record fields with a default can be left out,
  by name: `listResourceViews(search = "github")`, `NewResource(name: "GitHub")`,
  `new ResourceChanges(password: "new")`. The numbers are unsigned where Rust's are (`UInt`,
  `ULong` in Kotlin).
- **Java.** No default arguments: a method takes all its arguments, `null` for an optional value,
  `false` for a flag, `List.of()` for no ID. The records you write have builders that start from
  their defaults: `NewResourceBuilder`, `ResourceChangesBuilder`, `LoginOptionsBuilder`,
  `TotpDataBuilder`, `PasswordGeneratorSettingsBuilder`, `PassphraseGeneratorSettingsBuilder`.
  See [Java](java.md).
- **Go.** The initialisms are capitals: `ID`, `URL`, `URI`, `JSON`, `API`, `TLS`, `HTTP`
  (`GetResourcesByIDs`, `BaseURL()`, `MetadataJSON`). The methods with optional arguments take
  an option struct, whose zero value is the default:

  | Method | Option struct |
  |---|---|
  | `ListResources` | `*ResourceListOptions`: `Search`, `FavoritesOnly`, `OwnedByMe` |
  | `ListResourceViews` | `*ResourceViewListOptions`: `Search`, `WithSecrets` |
  | `ListFolders` | `*FolderListOptions`: `Search` |
  | `ListUsers` | `*UserListOptions`: `Search`, `GroupID`, `AdminOnly` |
  | `UpdateGroup` | `GroupChanges`: `Name`, `AddMemberIDs`, `AddManagerIDs`, `RemoveMemberIDs` |
  | `UpdateUser` | `UserChanges`: `FirstName`, `LastName`, `Role` |
  | `ShareResource` | `Share`: `Permission`, `UserIDs`, `GroupIDs` |
  | `ShareFolder` | `FolderShare`: `Permission`, `UserIDs`, `GroupIDs`, `WithContent` |

  The other methods take every argument, `nil` for an optional one (`CreateFolder(name, nil)`).
  `PermissionRead`, `PermissionUpdate`, `PermissionOwner` and `PermissionRevoke` name the
  permission types. `Close` logs out and releases the client; `Call` and `Run` stop waiting on a
  `context.Context`. See [Go](go.md).

## The async client

`AsyncPassboltClient` has the constructors and methods of `PassboltClient`, awaited in the way of
each language. The SDK's own threads do the network work: the caller's thread or event loop goes
on meanwhile.

| Language | Async client | A call returns |
|---|---|---|
| Python | `passbolt.AsyncClient` (`async with`) | a coroutine |
| Kotlin | `AsyncPassboltClient` | `suspend` functions |
| Swift | `AsyncPassboltClient` | `async throws` methods |
| Java | `AsyncPassboltClient` | a `CompletableFuture` |
| C# | `AsyncPassboltClient` | a `Task` (the names have no `Async` suffix) |
| Go | none: the calls block, use goroutines | |
| Ruby | none: the UniFFI generator of Ruby has no async support | |

`user_id` and `base_url` are not awaited. The functions (`fetch_server_key`, the generator, the
OpenPGP helpers) block in every language.

## Errors

Every failure is a `PassboltError` with one of the variants of [`PassboltError`](#passbolterror),
each with its `reason`; `Api` also has the HTTP `status`.

| Language | Error | Variants |
|---|---|---|
| Python | `passbolt.PassboltError` | subclasses `TransportError`, `AuthError`, `CryptoError`, `ApiError`, `NotFoundError`, `ConfigError`, `InvalidArgumentError` |
| Ruby | `Passbolt::Error`, a module every error includes | `Passbolt::TransportError`, `AuthError`, `CryptoError`, `ApiError`, `NotFoundError`, `ConfigError`, `InvalidArgumentError` |
| Kotlin | `PassboltException`, a sealed class | `PassboltException.Auth`, `.Api`… |
| Java | `PassboltException`, checked | nested classes `PassboltException.Auth`, `.Api`… |
| C# | `PassboltException` | nested classes `PassboltException.Auth`, `.Api`… |
| Swift | `PassboltError`, an `Error` enum | `.Auth`, `.Api(status, reason)`… |
| Go | `*passbolt.PassboltError` | `*PassboltErrorAuth`, `*PassboltErrorAPI`…, matched with `errors.As`, or `errors.Is` and `ErrPassboltErrorNotFound`… |

## JavaScript

The npm package, built from `crates/passbolt-wasm`, has the same operations on a
`PassboltSession` whose methods return promises. Its names are camelCase, the methods with
optional arguments take an options object (`listResourceViews({ search, withSecrets })`,
`shareResource(id, { userIds, permissionType })`), the objects keep the field names of the
Passbolt API, and its errors have a `code`. Its methods, options, types and error codes are on
the [JavaScript](javascript.md) page.
