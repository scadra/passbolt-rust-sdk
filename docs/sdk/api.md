---
title: API reference
sidebar_position: 11
---

# API reference

Look up every client, method, function and record of the SDK bindings, with its parameters and
what it returns.

This page covers the FFI bindings (Python, Java, Android/Kotlin, .NET, Go, Ruby, Swift), built
from `crates/passbolt-ffi/src`. Every binding has these clients, methods, functions and records,
under the names of its language: see [Names in each language](#names-in-each-language). The
JavaScript API is close, with its own shape: see [JavaScript](#javascript).

## Read this reference

The names are the Rust ones, in snake_case. The examples are in Python, whose `passbolt` package
keeps those names; `client` is a logged-in `passbolt.Client`.

The types are written this way:

| Notation | Meaning |
|---|---|
| `string`, `bool` | A string, a boolean |
| `u16`, `u32`, `u64`, `i32`, `f64` | Unsigned, signed and floating-point numbers, of 16, 32 or 64 bits |
| `T?` | Optional: `None`, `null`, `nil` or the value |
| `[T]` | A list |
| `bytes` | A byte array |
| `nothing` | No value |
| `= value` | The default, in the languages that have default arguments |

- Every method of the clients can fail with a [`PassboltError`](#passbolterror), and so can the
  functions, except `default_password_policies`, `generate_pin_code`, `secret_entropy` and
  `secret_strength`.
- Dates are RFC 3339 strings.

## Clients

`PassboltClient` blocks on each call. `AsyncPassboltClient` has the same constructors and methods,
awaited: see [The async client](#the-async-client).

### login

Authenticate against a Passbolt server and return a client session. A constructor.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `server_url` | `string` | Yes | Address of the Passbolt server. |
| `private_key_armored` | `string` | Yes | The armored OpenPGP private key of the account. |
| `passphrase` | `string` | Yes | The passphrase of the private key. |

Returns the client.

`login` is `login_with_config` with the default [`LoginOptions`](#loginoptions). A request waits
60 seconds by default (`timeout_seconds`).

#### Log in and log out

```python
with passbolt.Client.login("https://passbolt.example.com", private_key, passphrase) as client:
    print(client.user_id())
```

### login_with_config

Authenticate with `options`, the pinned server and metadata keys among them. A constructor.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `server_url` | `string` | Yes | Address of the Passbolt server. |
| `private_key_armored` | `string` | Yes | The armored OpenPGP private key of the account. |
| `passphrase` | `string` | Yes | The passphrase of the private key. |
| `options` | [`LoginOptions`](#loginoptions) | Yes | Pinned keys, MFA, timeout, proxy, TLS and client certificate. |

Returns the client.

#### Log in with a pinned server key

```python
options = passbolt.LoginOptions(server_public_key=server_key.armored_key)
client = passbolt.Client.login_with_config(
    "https://passbolt.example.com", private_key, passphrase, options
)
```

### user_id

Get the current user's ID. Does not fail, and is not awaited on the async client.

No parameters.

Returns `string`.

#### Print your user ID

```python
print(client.user_id())
```

### base_url

Get the server base URL. Does not fail, and is not awaited on the async client.

No parameters.

Returns `string`.

#### Print the server address

```python
print(client.base_url())
```

## Methods

The methods of both clients, from the `client_methods!` list of `crates/passbolt-ffi/src/lib.rs`,
grouped by area:

- [Session](#session)
- [Resources](#resources)
- [Folders](#folders)
- [Sharing](#sharing)
- [Users](#users)
- [Groups](#groups)
- [Tags](#tags)
- [Comments](#comments)
- [Favorites](#favorites)
- [Password expiry](#password-expiry)
- [Password policies](#password-policies)
- [Metadata and resource types](#metadata-and-resource-types)
- [Have I Been Pwned](#have-i-been-pwned)

Permission types are Passbolt's: `1` read, `7` update, `15` owner, `-1` to revoke.

## Session

### logout

Terminate the server-side session.

No parameters.

Returns `nothing`.

#### Log out

```python
client.logout()
```

### check_auth

Check if the session is still valid.

No parameters.

Returns `bool`.

#### Log in again when the session ended

```python
if not client.check_auth():
    client = passbolt.Client.login("https://passbolt.example.com", private_key, passphrase)
```

### keep_alive

Keep the session alive, as the browser extension does every few minutes.

No parameters.

Returns `nothing`.

#### Keep the session open

```python
client.keep_alive()
```

## Resources

### list_resources

List resources with optional search and filters.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `search` | `string?` | No | A search term. Default: `none`. |
| `favorites_only` | `bool` | No | Only your favorites. Default: `false`. |
| `owned_by_me` | `bool` | No | Only the resources you own. Default: `false`. |

Returns `[Resource]`.

#### List your favorites

```python
favorites = client.list_resources(favorites_only=True)
```

### list_resource_views

Resources with their v5 metadata decrypted, searched by their decrypted name; their secrets too
with `with_secrets`. One that does not decrypt has an `error`.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `search` | `string?` | No | A search term, matched on the decrypted name. Default: `none`. |
| `with_secrets` | `bool` | No | Also decrypt the secrets. Default: `false`. |

Returns [`[ResourceView]`](#resourceview).

#### Search by name

```python
for view in client.list_resource_views("github"):
    print(view.id, view.name, view.username)
```

### get_resource_view

A resource with its v5 metadata and its secret decrypted, for every resource type.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the resource. |

Returns [`ResourceView`](#resourceview).

#### Read a password

```python
view = client.get_resource_view("<RESOURCE_UUID>")
print(view.password)
```

### get_resource

Get a single resource by ID.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the resource. |

Returns [`Resource`](#resource).

#### Get a resource

```python
resource = client.get_resource("<RESOURCE_UUID>")
```

### get_resources_by_ids

Get multiple resources by IDs.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `ids` | `[string]` | Yes | IDs of the resources. |

Returns `[Resource]`.

#### Get two resources

```python
resources = client.get_resources_by_ids(["<RESOURCE_UUID>", "<OTHER_RESOURCE_UUID>"])
```

### decrypt_resource_secret

Decrypt a resource's secret. The method fetches the resource by its ID, then decrypts its secret.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `resource_id` | `string` | Yes | ID of the resource. |

Returns [`SecretData`](#secretdata).

#### Decrypt a secret

```python
secret = client.decrypt_resource_secret("<RESOURCE_UUID>")
print(secret.password)
```

### create_resource

Create a resource of any type. Returns the created resource.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `resource` | [`NewResource`](#newresource) | Yes | The resource to create. |

Returns [`Resource`](#resource).

#### Create a password

```python
created = client.create_resource(
    passbolt.NewResource(name="GitHub", username="ada", password="…")
)
```

### update_resource

Update a resource; the fields left out keep their value.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the resource. |
| `changes` | [`ResourceChanges`](#resourcechanges) | Yes | The fields to change. |

Returns [`Resource`](#resource).

#### Change a password and clear its expiry

```python
client.update_resource(
    "<RESOURCE_UUID>", passbolt.ResourceChanges(password="new", clear_expiry=True)
)
```

### move_resource

Move a resource into a folder, or to the root without one.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the resource. |
| `folder_id` | `string?` | No | The destination folder. Default: `none`, the root. |

Returns `nothing`.

#### Move a resource into a folder

```python
client.move_resource("<RESOURCE_UUID>", "<FOLDER_UUID>")
```

### delete_resource

Delete a resource.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the resource. |

Returns `nothing`.

#### Delete a resource

```python
client.delete_resource("<RESOURCE_UUID>")
```

### delete_resources

Bulk delete resources.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `ids` | `[string]` | Yes | IDs of the resources. |

Returns `nothing`.

#### Delete several resources

```python
client.delete_resources(["<RESOURCE_UUID>", "<OTHER_RESOURCE_UUID>"])
```

### get_resource_permissions

Get permissions for a resource.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the resource. |

Returns [`[Permission]`](#permission).

#### List who can read a resource

```python
for permission in client.get_resource_permissions("<RESOURCE_UUID>"):
    print(permission.aro, permission.aro_foreign_key, permission.permission_type)
```

## Folders

### list_folders

List all folders.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `search` | `string?` | No | A search term. Default: `none`. |

Returns [`[Folder]`](#folder).

#### List every folder

```python
folders = client.list_folders()
```

### get_folder

Get a single folder by ID.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the folder. |

Returns [`Folder`](#folder).

#### Get a folder

```python
folder = client.get_folder("<FOLDER_UUID>")
```

### get_folder_tree

Build a folder tree from the flat folder list.

No parameters.

Returns [`[FolderTreeNode]`](#foldertreenode).

#### Print the tree

```python
def show(nodes, depth=0):
    for node in nodes:
        print("  " * depth + node.folder.name)
        show(node.children, depth + 1)

show(client.get_folder_tree())
```

### create_folder

Create a folder, at the root or in `folder_parent_id`; in a parent folder it gets the parent's
permissions.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `name` | `string` | Yes | Name of the folder. |
| `folder_parent_id` | `string?` | No | The parent folder. Default: `none`, the root. |

Returns [`Folder`](#folder).

#### Create a sub-folder

```python
folder = client.create_folder("Ops", "<FOLDER_UUID>")
```

### rename_folder

Rename a folder.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the folder. |
| `name` | `string` | Yes | The new name. |

Returns [`Folder`](#folder).

#### Rename a folder

```python
client.rename_folder("<FOLDER_UUID>", "Operations")
```

### move_folder

Move a folder into another one, or to the root without one.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the folder. |
| `folder_id` | `string?` | No | The destination folder. Default: `none`, the root. |

Returns `nothing`.

#### Move a folder to the root

```python
client.move_folder("<FOLDER_UUID>")
```

### delete_folder

Delete a folder; its content moves to the root.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the folder. |

Returns `nothing`.

#### Delete a folder and keep its content

```python
client.delete_folder("<FOLDER_UUID>")
```

### delete_folder_with_content

Delete a folder with its sub-folders and the resources the user may delete in them.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the folder. |

Returns `nothing`.

#### Delete a folder and its content

```python
client.delete_folder_with_content("<FOLDER_UUID>")
```

### get_folder_permissions

Get permissions for a folder.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the folder. |

Returns [`[Permission]`](#permission).

#### List the permissions of a folder

```python
permissions = client.get_folder_permissions("<FOLDER_UUID>")
```

## Sharing

### share_resource

Share a resource with users and groups (`permission_type` 1, 7 or 15), or revoke with -1.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the resource. |
| `permission_type` | `i32` | Yes | `1` read, `7` update, `15` owner, `-1` to revoke. |
| `user_ids` | `[string]` | No | The users. Default: `[]`. |
| `group_ids` | `[string]` | No | The groups. Default: `[]`. |

Returns `nothing`.

#### Give a user the update permission

```python
client.share_resource("<RESOURCE_UUID>", passbolt.PermissionType.UPDATE, user_ids=["<USER_UUID>"])
```

#### Revoke a group's access

```python
client.share_resource("<RESOURCE_UUID>", passbolt.PermissionType.REVOKE, group_ids=["<GROUP_UUID>"])
```

### share_folder

Share a folder, and with `with_content` the sub-folders and resources the user owns.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the folder. |
| `permission_type` | `i32` | Yes | `1` read, `7` update, `15` owner, `-1` to revoke. |
| `user_ids` | `[string]` | No | The users. Default: `[]`. |
| `group_ids` | `[string]` | No | The groups. Default: `[]`. |
| `with_content` | `bool` | No | Also share the sub-folders and resources the user owns. Default: `false`. |

Returns `nothing`.

#### Share a folder and its content with a group

```python
client.share_folder(
    "<FOLDER_UUID>", passbolt.PermissionType.READ, group_ids=["<GROUP_UUID>"], with_content=True
)
```

### search_aros

Search for users and groups (AROs) for sharing.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `search` | `string` | Yes | A search term. |

Returns [`[Aro]`](#aro).

#### Find whom to share with

```python
for aro in client.search_aros("ada"):
    print(aro.id, aro.aro_type, aro.username or aro.name)
```

## Users

### list_users

List all users.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `search` | `string?` | No | A search term. Default: `none`. |
| `group_id` | `string?` | No | Only the members of this group. Default: `none`. |
| `admin_only` | `bool` | No | Only the administrators. Default: `false`. |

Returns [`[User]`](#user).

#### List the members of a group

```python
members = client.list_users(group_id="<GROUP_UUID>")
```

### get_me

Get the currently logged-in user.

No parameters.

Returns [`User`](#user).

#### Get your profile

```python
me = client.get_me()
print(me.username)
```

### get_user

Get a user by ID.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the user. |

Returns [`User`](#user).

#### Get a user

```python
user = client.get_user("<USER_UUID>")
```

### create_user

Create a user with the role named `role` (`user` or `admin`).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `username` | `string` | Yes | The username, an email address. |
| `first_name` | `string` | Yes | First name. |
| `last_name` | `string` | Yes | Last name. |
| `role` | `string` | Yes | `user` or `admin`. |

Returns [`User`](#user).

#### Create a user

```python
user = client.create_user("ada@example.com", "Ada", "Lovelace", "user")
```

### update_user

Update a user's names or role; `None` keeps the value.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the user. |
| `first_name` | `string?` | No | The new first name. Default: `none`. |
| `last_name` | `string?` | No | The new last name. Default: `none`. |
| `role` | `string?` | No | The new role. Default: `none`. |

Returns [`User`](#user).

#### Make a user an administrator

```python
client.update_user("<USER_UUID>", role="admin")
```

### delete_user

Delete a user.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the user. |

Returns `nothing`.

#### Delete a user

```python
client.delete_user("<USER_UUID>")
```

### delete_user_dry_run

Preview the impact of deleting a user.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the user. |

Returns [`UserDeleteDryRun`](#userdeletedryrun).

#### Count what the user alone owns

```python
impact = client.delete_user_dry_run("<USER_UUID>")
print(impact.resources_sole_owner_count, impact.groups_sole_manager_count)
```

### user_delete_blockers

What blocks deleting the user: what they alone own or manage.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the user. |

Returns [`DeleteBlockers`](#deleteblockers).

#### List what needs a new owner

```python
blockers = client.user_delete_blockers("<USER_UUID>")
print([item.id for item in blockers.resources], [group.name for group in blockers.groups])
```

### delete_user_with_transfer

Delete a user, giving what they alone own or manage to `successor_id`, a user or a group that
already has access to it.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the user. |
| `successor_id` | `string` | Yes | The user or group that gets what the deleted user alone owns or manages. |

Returns `nothing`.

#### Hand over and delete

```python
client.delete_user_with_transfer("<USER_UUID>", "<OTHER_USER_UUID>")
```

## Groups

### list_groups

List all groups.

No parameters.

Returns [`[Group]`](#group).

#### List the groups

```python
for group in client.list_groups():
    print(group.id, group.name)
```

### get_group

Get a group by ID.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the group. |

Returns [`Group`](#group).

#### Get a group

```python
group = client.get_group("<GROUP_UUID>")
```

### create_group

Create a group; a manager is also a member.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `name` | `string` | Yes | Name of the group. |
| `member_ids` | `[string]` | No | The members. Default: `[]`. |
| `manager_ids` | `[string]` | No | The managers. Default: `[]`. |

Returns [`Group`](#group).

#### Create a group with a manager

```python
group = client.create_group("DevOps", manager_ids=["<USER_UUID>"])
```

### update_group

Rename a group and change its members: the removed ones first, then the added ones, who get the
secrets of the group's resources. Giving a user the role they have, or removing a non-member, is
an error.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the group. |
| `name` | `string?` | No | The new name. Default: `none`. |
| `add_member_ids` | `[string]` | No | Users to add as members. Default: `[]`. |
| `add_manager_ids` | `[string]` | No | Users to add as managers. Default: `[]`. |
| `remove_member_ids` | `[string]` | No | Users to remove. Default: `[]`. |

Returns [`Group`](#group).

#### Add a member

```python
client.update_group("<GROUP_UUID>", add_member_ids=["<USER_UUID>"])
```

### delete_group

Delete a group.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the group. |

Returns `nothing`.

#### Delete a group

```python
client.delete_group("<GROUP_UUID>")
```

### delete_group_dry_run

Preview the impact of deleting a group.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the group. |

Returns [`GroupDeleteDryRun`](#groupdeletedryrun).

#### Count what the group alone owns

```python
impact = client.delete_group_dry_run("<GROUP_UUID>")
print(impact.resources_sole_group_count, impact.folders_sole_group_count)
```

### group_delete_blockers

What blocks deleting the group: what it alone owns.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the group. |

Returns [`DeleteBlockers`](#deleteblockers).

#### List what needs a new owner

```python
blockers = client.group_delete_blockers("<GROUP_UUID>")
```

### delete_group_with_transfer

Delete a group, giving what it alone owns to `successor_id`, a user or a group that already has
access to it.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the group. |
| `successor_id` | `string` | Yes | The user or group that gets what the deleted group alone owns. |

Returns `nothing`.

#### Hand over and delete

```python
client.delete_group_with_transfer("<GROUP_UUID>", "<USER_UUID>")
```

## Tags

### get_tags

List all tags.

No parameters.

Returns [`[Tag]`](#tag).

#### List the tags

```python
slugs = [tag.slug for tag in client.get_tags()]
```

### add_tag_to_resource

Add a tag to a resource, keeping its other tags; returns the resource's tags.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `resource_id` | `string` | Yes | ID of the resource. |
| `slug` | `string` | Yes | The tag. |

Returns [`[Tag]`](#tag).

#### Tag a resource

```python
client.add_tag_to_resource("<RESOURCE_UUID>", "production")
```

### set_resource_tags

Replace all the tags of a resource; returns its tags.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `resource_id` | `string` | Yes | ID of the resource. |
| `slugs` | `[string]` | Yes | The tags the resource keeps. |

Returns [`[Tag]`](#tag).

#### Replace the tags of a resource

```python
client.set_resource_tags("<RESOURCE_UUID>", ["production", "database"])
```

### rename_tag

Rename a tag.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the tag. |
| `slug` | `string` | Yes | The new name. |

Returns [`Tag`](#tag).

#### Rename a tag

```python
client.rename_tag("<TAG_UUID>", "prod")
```

### delete_tag

Delete a tag.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the tag. |

Returns `nothing`.

#### Delete a tag

```python
client.delete_tag("<TAG_UUID>")
```

## Comments

### get_comments

Get comments for a resource.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `resource_id` | `string` | Yes | ID of the resource. |

Returns [`[Comment]`](#comment).

#### Read the comments of a resource

```python
for comment in client.get_comments("<RESOURCE_UUID>"):
    print(comment.created, comment.content)
```

### create_comment

Create a comment on a resource.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `resource_id` | `string` | Yes | ID of the resource. |
| `content` | `string` | Yes | The text of the comment. |
| `parent_id` | `string?` | No | The comment this one answers. Default: `none`. |

Returns [`Comment`](#comment).

#### Answer a comment

```python
client.create_comment("<RESOURCE_UUID>", "Rotated today.", parent_id="<COMMENT_UUID>")
```

### delete_comment

Delete a comment.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the comment. |

Returns `nothing`.

#### Delete a comment

```python
client.delete_comment("<COMMENT_UUID>")
```

## Favorites

### add_favorite

Add a resource to favorites.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `resource_id` | `string` | Yes | ID of the resource. |

Returns [`Favorite`](#favorite).

#### Mark a resource as favorite

```python
favorite = client.add_favorite("<RESOURCE_UUID>")
```

### remove_favorite

Remove a favorite.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `favorite_id` | `string` | Yes | ID of the favorite, not of the resource. |

Returns `nothing`.

#### Remove a favorite

```python
client.remove_favorite(favorite.id)
```

## Password expiry

### get_password_expiry_settings

Get password expiry settings.

No parameters.

Returns [`PasswordExpirySettings`](#passwordexpirysettings).

#### Read the expiry period

```python
settings = client.get_password_expiry_settings()
print(settings.default_expiry_period_days)
```

### save_password_expiry_settings

Create or update the password expiry settings (admin).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `settings` | [`PasswordExpirySettings`](#passwordexpirysettings) | Yes | The settings to save. |

Returns [`PasswordExpirySettings`](#passwordexpirysettings).

#### Expire passwords after 90 days

```python
settings = client.get_password_expiry_settings()
settings.default_expiry_period_days = 90
client.save_password_expiry_settings(settings)
```

### delete_password_expiry_settings

Delete the password expiry settings (admin): the defaults apply again.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `id` | `string` | Yes | ID of the settings. |

Returns `nothing`.

#### Go back to the defaults

```python
client.delete_password_expiry_settings(client.get_password_expiry_settings().id)
```

## Password policies

### get_password_policies

The password policies of the organization, for [`generate_secret`](#generate_secret).

No parameters.

Returns [`PasswordPolicies`](#passwordpolicies).

#### Generate a secret the organization's way

```python
secret = passbolt.generate_secret(client.get_password_policies())
```

### save_password_policies

Save the password policies of the organization (administrator, Passbolt Pro).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `policies` | [`PasswordPolicies`](#passwordpolicies) | Yes | The policies to save. |

Returns [`PasswordPolicies`](#passwordpolicies).

#### Generate passphrases by default

```python
policies = client.get_password_policies()
policies.default_generator = passbolt.GeneratorType.PASSPHRASE
client.save_password_policies(policies)
```

## Metadata and resource types

### metadata_key_fingerprint

The fingerprint of the active shared metadata key, to pin in
`LoginOptions.metadata_key_fingerprint`; `None` without one.

No parameters.

Returns `string?`.

#### Pin the metadata key

```python
fingerprint = client.metadata_key_fingerprint()
# Save it, then at each login:
client = passbolt.Client.login(
    "https://passbolt.example.com", private_key, passphrase, metadata_key_fingerprint=fingerprint
)
```

### list_resource_types

The resource types of the server.

No parameters.

Returns [`[ResourceType]`](#resourcetype).

#### List the type slugs

```python
slugs = [resource_type.slug for resource_type in client.list_resource_types()]
```

### get_metadata_types_settings

Which metadata versions the organization creates and allows.

No parameters.

Returns [`MetadataTypesSettings`](#metadatatypessettings).

#### Check whether v5 resources are allowed

```python
print(client.get_metadata_types_settings().allow_creation_of_v5_resources)
```

### save_metadata_types_settings

Save the metadata types settings (admin).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `settings` | [`MetadataTypesSettings`](#metadatatypessettings) | Yes | The settings to save. |

Returns [`MetadataTypesSettings`](#metadatatypessettings).

#### Allow v5 resources

```python
settings = client.get_metadata_types_settings()
settings.allow_creation_of_v5_resources = True
client.save_metadata_types_settings(settings)
```

### get_metadata_keys_settings

How metadata keys are used in the organization.

No parameters.

Returns [`MetadataKeysSettings`](#metadatakeyssettings).

#### Check whether personal keys are allowed

```python
print(client.get_metadata_keys_settings().allow_usage_of_personal_keys)
```

### save_metadata_keys_settings

Save the metadata keys settings (admin).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `settings` | [`MetadataKeysSettings`](#metadatakeyssettings) | Yes | The settings to save. |

Returns [`MetadataKeysSettings`](#metadatakeyssettings).

#### Allow personal keys

```python
settings = client.get_metadata_keys_settings()
settings.allow_usage_of_personal_keys = True
client.save_metadata_keys_settings(settings)
```

## Have I Been Pwned

### check_password_pwned

Check if a password has been exposed in data breaches. Returns the number of times found
(0 = not breached).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `password` | `string` | Yes | The password to check. |

Returns `u64`.

#### Refuse a breached password

```python
if client.check_password_pwned(password) > 0:
    print("This password appeared in a data breach.")
```

## Functions

Exported functions, outside any client: they need no session. In Java and C# they are static
methods of `PassboltFfi`.

## Server key and OpenPGP

### fetch_server_key

The server public key, to pin in `LoginOptions.server_public_key` once the user confirmed its
fingerprint.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `server_url` | `string` | Yes | Address of the Passbolt server. |
| `tls_skip_verify` | `bool` | No | Skip the check of the TLS certificate. Default: `false`. |

Returns [`ServerKey`](#serverkey).

#### Fetch the key to pin

```python
server_key = passbolt.fetch_server_key("https://passbolt.example.com")
print("Check this fingerprint with your administrator:", server_key.fingerprint)
```

### decrypt_message

Decrypt a PGP-armored message with a private key.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `armored_message` | `string` | Yes | The PGP-armored message. |
| `private_key_armored` | `string` | Yes | The armored private key. |
| `passphrase` | `string` | Yes | The passphrase of the private key. |

Returns `bytes`.

#### Decrypt a message

```python
plaintext = passbolt.decrypt_message(armored_message, private_key, passphrase)
```

### encrypt_message

Encrypt a plaintext message for one or more PGP public keys. Returns the PGP-armored ciphertext.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `plaintext` | `bytes` | Yes | The message. |
| `public_keys_armored` | `[string]` | Yes | The armored public keys to encrypt for. |

Returns `string`.

#### Encrypt for two keys

```python
armored = passbolt.encrypt_message(b"hello", [public_key, other_public_key])
```

### get_key_fingerprint

Parse a PGP private key and return its fingerprint (hex uppercase).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `private_key_armored` | `string` | Yes | The armored private key. |

Returns `string`.

#### Print the fingerprint of your key

```python
print(passbolt.get_key_fingerprint(private_key))
```

### openpgp_engine

The name of the OpenPGP engine the native library runs: `gopenpgp` in the released packages,
`openpgpjs` in the Go module. See
[OpenPGP engines](../security.md#openpgp-engines). Does not fail.

No parameters.

Returns `string`.

#### Print the engine

```python
print(passbolt.openpgp_engine())
```

## Password generator

### default_password_policies

The policies of a server without settings: passwords of 18 characters by default. Does not fail.

No parameters.

Returns [`PasswordPolicies`](#passwordpolicies).

#### Generate a secret without a server

```python
secret = passbolt.generate_secret(passbolt.default_password_policies())
```

### generate_password

A password following `settings`, as the extension generates it.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `settings` | [`PasswordGeneratorSettings`](#passwordgeneratorsettings) | Yes | Length and character sets. |

Returns `string`.

#### Generate a 24-character password

```python
password = passbolt.generate_password(passbolt.PasswordGeneratorSettings(length=24))
```

### generate_passphrase

A passphrase of words of the EFF list following `settings`.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `settings` | [`PassphraseGeneratorSettings`](#passphrasegeneratorsettings) | Yes | Words, separator and case. |

Returns `string`.

#### Generate a passphrase of six words

```python
passphrase = passbolt.generate_passphrase(
    passbolt.PassphraseGeneratorSettings(words=6, word_case=passbolt.WordCase.CAMELCASE)
)
```

### generate_secret

A secret from the default generator of `policies`, those of
`PassboltClient.get_password_policies` for instance.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `policies` | [`PasswordPolicies`](#passwordpolicies) | Yes | The generator to use and its settings. |

Returns `string`.

#### Generate a secret from the organization's policies

```python
secret = passbolt.generate_secret(client.get_password_policies())
```

### generate_pin_code

A PIN code of `length` digits, brought within 4 to 12. Does not fail.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `length` | `u32` | No | Number of digits. Default: `4`. |

Returns `string`.

#### Generate a 6-digit PIN code

```python
pin_code = passbolt.generate_pin_code(6)
```

### secret_entropy

The entropy of `secret` in bits, measured as the extension does: as a passphrase when it is words
of the list joined by one separator. Does not fail.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `secret` | `string` | Yes | The secret to measure. |

Returns `f64`.

#### Measure a password

```python
print(passbolt.secret_entropy(password))
```

### secret_strength

The strength the extension shows for `secret`. Does not fail.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `secret` | `string` | Yes | The secret to rate. |

Returns [`Strength`](#strength).

#### Rate a password

```python
print(passbolt.secret_strength(password))
```

## Records and enums

Records are plain values. A field with a default can be left out where the language has default
arguments; Java builds the records it writes with builders.

### Login records

#### LoginOptions

How to log in, beyond the credentials.

| Field | Type | Default | Description |
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

| Field | Type | Description |
|---|---|---|
| `fingerprint` | `string` | Computed from the key, checked against the one the server announces. |
| `armored_key` | `string` |  |

### Resource records

#### ResourceView

A resource with its v5 metadata decrypted, and its secret when it was asked for.

| Field | Type | Description |
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

A resource to create. Its type comes from the fields set and the server's default version, unless
`resource_type` names it; fields the type does not have are refused.

| Field | Type | Default | Description |
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

| Field | Type | Default | Description |
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

| Field | Type |
|---|---|
| `secret_key` | `string?` |
| `algorithm` | `string?` |
| `digits` | `u32?` |
| `period` | `u64?` |
| `issuer` | `string?` |

#### Resource

| Field | Type | Default | Description |
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

| Field | Type |
|---|---|
| `id` | `string?` |
| `resource_id` | `string?` |
| `user_id` | `string?` |
| `data` | `string?` |
| `created` | `string?` |
| `modified` | `string?` |

#### SecretData

| Field | Type |
|---|---|
| `password` | `string?` |
| `description` | `string?` |
| `totp` | `TotpData?` |
| `raw` | `string?` |

#### Permission

| Field | Type |
|---|---|
| `id` | `string?` |
| `aco` | `string?` |
| `aco_foreign_key` | `string?` |
| `aro` | `string?` |
| `aro_foreign_key` | `string?` |
| `permission_type` | `i32?` |
| `created` | `string?` |
| `modified` | `string?` |
| `user` | `User?` |
| `group` | `Group?` |

#### Favorite

| Field | Type |
|---|---|
| `id` | `string?` |
| `foreign_model` | `string?` |
| `foreign_key` | `string?` |
| `created` | `string?` |

#### ResourceType

A resource type of the server; `definition` is its JSON Schema, as JSON.

| Field | Type |
|---|---|
| `id` | `string` |
| `slug` | `string` |
| `name` | `string?` |
| `definition` | `string?` |

### Folder records

#### Folder

| Field | Type |
|---|---|
| `id` | `string` |
| `name` | `string` |
| `folder_parent_id` | `string?` |
| `created` | `string?` |
| `modified` | `string?` |
| `created_by` | `string?` |
| `modified_by` | `string?` |
| `personal` | `bool?` |
| `permissions` | `[Permission]` |

#### FolderTreeNode

| Field | Type |
|---|---|
| `folder` | `Folder` |
| `children` | `[FolderTreeNode]` |

### User and group records

#### User

| Field | Type |
|---|---|
| `id` | `string` |
| `username` | `string?` |
| `role_id` | `string?` |
| `created` | `string?` |
| `modified` | `string?` |
| `active` | `bool?` |
| `deleted` | `bool?` |
| `profile` | `UserProfile?` |
| `role` | `Role?` |
| `gpg_key` | `GpgKey?` |

#### UserProfile

| Field | Type |
|---|---|
| `first_name` | `string?` |
| `last_name` | `string?` |

#### Role

| Field | Type |
|---|---|
| `id` | `string?` |
| `name` | `string?` |

#### GpgKey

| Field | Type |
|---|---|
| `id` | `string?` |
| `user_id` | `string?` |
| `armored_key` | `string?` |
| `bits` | `u32?` |
| `fingerprint` | `string?` |
| `key_created` | `string?` |

#### Group

| Field | Type |
|---|---|
| `id` | `string` |
| `name` | `string` |
| `created` | `string?` |
| `modified` | `string?` |
| `created_by` | `string?` |
| `modified_by` | `string?` |
| `deleted` | `bool?` |
| `groups_users` | `[GroupUser]` |

#### GroupUser

| Field | Type |
|---|---|
| `id` | `string?` |
| `group_id` | `string?` |
| `user_id` | `string?` |
| `is_admin` | `bool?` |
| `created` | `string?` |

#### Aro

| Field | Type |
|---|---|
| `id` | `string` |
| `aro_type` | `string?` |
| `username` | `string?` |
| `profile` | `UserProfile?` |
| `name` | `string?` |

#### UserDeleteDryRun

| Field | Type |
|---|---|
| `resources_sole_owner_count` | `u32` |
| `folders_sole_owner_count` | `u32` |
| `groups_sole_manager_count` | `u32` |

#### GroupDeleteDryRun

| Field | Type |
|---|---|
| `resources_sole_group_count` | `u32` |
| `folders_sole_group_count` | `u32` |

#### DeleteBlockers

What blocks deleting a user or a group: each item needs a new owner, each group a new manager.

| Field | Type | Description |
|---|---|---|
| `resources` | `[OwnedItem]` |  |
| `folders` | `[OwnedItem]` |  |
| `groups` | `[ManagedGroup]` |  |
| `groups_to_delete` | `[string]` | Groups the deleted user is the only member of: deleted with them. |

#### OwnedItem

A shared resource or folder only the deleted user or group owns, with its permissions.

| Field | Type |
|---|---|
| `id` | `string` |
| `permissions` | `[Permission]` |

#### ManagedGroup

A group with other members that only the deleted user manages, with its memberships.

| Field | Type |
|---|---|
| `id` | `string` |
| `name` | `string` |
| `groups_users` | `[GroupUser]` |

### Tag and comment records

#### Tag

| Field | Type |
|---|---|
| `id` | `string` |
| `slug` | `string` |
| `is_shared` | `bool?` |
| `created` | `string?` |
| `modified` | `string?` |

#### Comment

| Field | Type |
|---|---|
| `id` | `string` |
| `parent_id` | `string?` |
| `foreign_key` | `string?` |
| `foreign_model` | `string?` |
| `content` | `string` |
| `created` | `string?` |
| `modified` | `string?` |
| `created_by` | `string?` |
| `modified_by` | `string?` |
| `creator` | `User?` |

### Settings records

#### PasswordExpirySettings

| Field | Type |
|---|---|
| `id` | `string?` |
| `default_expiry_period_days` | `u32?` |
| `policy_override` | `bool?` |
| `automatic_expiry` | `bool?` |
| `automatic_update` | `bool?` |

#### MetadataTypesSettings

Which metadata versions the organization creates and allows (admin settings).

| Field | Type |
|---|---|
| `default_resource_types` | `string?` |
| `default_folder_type` | `string?` |
| `default_tag_type` | `string?` |
| `default_comment_type` | `string?` |
| `allow_creation_of_v5_resources` | `bool?` |
| `allow_creation_of_v5_folders` | `bool?` |
| `allow_creation_of_v5_tags` | `bool?` |
| `allow_creation_of_v5_comments` | `bool?` |
| `allow_creation_of_v4_resources` | `bool?` |
| `allow_creation_of_v4_folders` | `bool?` |
| `allow_creation_of_v4_tags` | `bool?` |
| `allow_creation_of_v4_comments` | `bool?` |

#### MetadataKeysSettings

How metadata keys are used in the organization (admin settings).

| Field | Type |
|---|---|
| `allow_usage_of_personal_keys` | `bool?` |
| `zero_knowledge_key_share` | `bool?` |

### Password generator records

#### PasswordPolicies

The password policies of the organization: the generator to use and its settings.

| Field | Type | Default | Description |
|---|---|---|---|
| `default_generator` | `GeneratorType` | required |  |
| `password_generator_settings` | `PasswordGeneratorSettings` | required |  |
| `passphrase_generator_settings` | `PassphraseGeneratorSettings` | required |  |
| `external_dictionary_check` | `bool` | `true` | Check new passwords against Have I Been Pwned. |
| `source` | `string?` | `none` | Where the server read them: `default`, `file`, `env`, `db`… |
| `id` | `string?` | `none` | Set once an administrator saved them (Passbolt Pro). |

#### PasswordGeneratorSettings

How passwords are generated; the defaults are the server's and the extension's: 18 characters of
every set but emoji, without look-alike characters.

| Field | Type | Default | Description |
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

How passphrases are generated; the defaults are the server's and the extension's: 9 lowercase
words of the EFF list joined by spaces.

| Field | Type | Default | Description |
|---|---|---|---|
| `words` | `u32` | `9` |  |
| `word_separator` | `string` | `" "` |  |
| `word_case` | `WordCase?` | `none` | `None` is lowercase. |
| `min_words` | `u32` | `4` |  |
| `max_words` | `u32` | `40` |  |

#### GeneratorType

What the generator makes by default.

| Variant | Description |
|---|---|
| `Password` |  |
| `Passphrase` |  |

#### WordCase

The case of the words of a passphrase.

| Variant | Description |
|---|---|
| `Lowercase` |  |
| `Uppercase` |  |
| `Camelcase` | The first letter of each word in capital. |

#### Strength

The strength the extension shows for a secret.

| Variant | Description |
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

### Records no method takes

Exported with the records, but no method takes them: the list methods take their fields as
arguments.

#### ResourceQuery

| Field | Type |
|---|---|
| `search` | `string?` |
| `favorites_only` | `bool` |
| `owned_by_me` | `bool` |

#### FolderQuery

| Field | Type |
|---|---|
| `search` | `string?` |

#### UserQuery

| Field | Type |
|---|---|
| `search` | `string?` |
| `group_id` | `string?` |
| `admin_only` | `bool` |

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

### Where the constructors and functions live

| Language | Constructors | Functions |
|---|---|---|
| Python | `passbolt.Client.login(...)`, `passbolt.Client.login_with_config(...)` | `passbolt.fetch_server_key(...)` |
| Ruby | `Passbolt::Client.login(...)` | `Passbolt.fetch_server_key(...)` |
| Kotlin | `PassboltClient.login(...)`, `PassboltClient.loginWithConfig(...)` | functions of the package `com.passbolt.sdk`: `fetchServerKey(...)` |
| Swift | `PassboltClient.login(serverUrl:privateKeyArmored:passphrase:)` | global functions: `fetchServerKey(serverUrl:)` |
| Java | `PassboltClient.login(...)`, `PassboltClient.loginWithConfig(...)` | static methods of `PassboltFfi`: `PassboltFfi.fetchServerKey(url, false)` |
| C# | `PassboltClient.Login(...)`, `PassboltClient.LoginWithConfig(...)` | static methods of `PassboltFfi`: `PassboltFfi.FetchServerKey(url)` |
| Go | `passbolt.PassboltClientLogin(...)`, `passbolt.PassboltClientLoginWithConfig(...)` | `passbolt.FetchServerKey(url, false)` |

### What each binding adds or changes

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
- **Kotlin, Swift, C#.** The arguments and record fields with a default can be left out, by name:
  `listResourceViews(search = "github")`, `NewResource(name: "GitHub")`,
  `new ResourceChanges(password: "new")`. The numbers are unsigned where Rust's are (`UInt`,
  `ULong` in Kotlin).
- **Java.** No default arguments: a method takes all its arguments, `null` for an optional value,
  `false` for a flag, `List.of()` for no ID. The records you write have builders that start from
  their defaults: `NewResourceBuilder`, `ResourceChangesBuilder`, `LoginOptionsBuilder`,
  `TotpDataBuilder`, `PasswordGeneratorSettingsBuilder`, `PassphraseGeneratorSettingsBuilder`.
  See [Java](java.md).
- **Go.** The initialisms are capitals: `ID`, `URL`, `URI`, `JSON`, `API`, `TLS`, `HTTP`
  (`GetResourcesByIDs`, `BaseURL()`, `MetadataJSON`). The methods with optional arguments take
  an option struct, whose zero value is the default: see the table below. The other methods take
  every argument, `nil` for an optional one (`CreateFolder(name, nil)`). `PermissionRead`,
  `PermissionUpdate`, `PermissionOwner` and `PermissionRevoke` name the permission types.
  `Close` logs out and releases the client; `Call` and `Run` stop waiting on a
  `context.Context`. See [Go](go.md).

### Go option structs

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

:::note
`user_id` and `base_url` are not awaited. The functions (`fetch_server_key`, the generator, the
OpenPGP helpers) block in every language.
:::

#### Run two calls at once

```python
import asyncio

import passbolt


async def main(private_key: str, passphrase: str) -> None:
    async with await passbolt.AsyncClient.login(
        "https://passbolt.example.com", private_key, passphrase
    ) as client:
        views, folders = await asyncio.gather(
            client.list_resource_views("github"), client.list_folders()
        )
```

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

#### Handle a missing resource

```python
try:
    client.get_resource_view("<RESOURCE_UUID>")
except passbolt.NotFoundError:
    print("No such resource")
except passbolt.ApiError as error:
    print("The server answered", error.status, error.reason)
```

## JavaScript

The npm package, built from `crates/passbolt-wasm`, has the same operations on a
`PassboltSession` whose methods return promises. Its names are camelCase, the methods with
optional arguments take an options object (`listResourceViews({ search, withSecrets })`,
`shareResource(id, { userIds, permissionType })`), the objects keep the field names of the
Passbolt API, and its errors have a `code`. Its methods, options, types and error codes are on
the [JavaScript](javascript.md) page.

## Related

- [Python](python.md), [Java](java.md), [Android](android.md), [.NET](dotnet.md), [Go](go.md),
  [Ruby](ruby.md), [Swift](swift.md): install and use each binding.
- [JavaScript](javascript.md): the npm package and its `PassboltSession`.
- [Rust](rust.md): the Rust crate.
- [Upgrading](upgrading.md): the breaking changes since 0.1.1.
