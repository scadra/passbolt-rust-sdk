---
title: Rust
sidebar_position: 2
---

# Rust

Use the `passbolt-sdk` crate to log in to Passbolt and read, write and share secrets from async Rust.

## Installation

The crate is published on crates.io as `switch-case-passbolt-sdk` and imported as `passbolt_sdk`.
It needs Rust 1.88 or later.

```toml title="Cargo.toml"
[dependencies]
passbolt-sdk = { package = "switch-case-passbolt-sdk", version = "0.1", features = ["native", "totp"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
secrecy = "0.10"
```

| Feature | Default | Description |
|---|---|---|
| `native` | Yes | The reqwest HTTP client, `NativeHttpClient`. |
| `totp` | No | TOTP codes for MFA. |
| `full` | No | `native` and `totp`. |

:::note
Without `native`, implement the `HttpClient` trait over your own transport, as `passbolt-wasm`
does over `fetch`.
:::

## Initialize

Build an `SdkConfig` and an HTTP client, then call `PassboltSdk::login`. `logout` ends the
session on the server.

```rust
use passbolt_sdk::{NativeHttpClient, NativeHttpConfig, OpenPgp, PassboltSdk, SdkConfig};
use secrecy::SecretString;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SdkConfig {
        server_url: "https://passbolt.example.com".into(),
        private_key_armored: std::fs::read_to_string("private.asc")?,
        passphrase: SecretString::from(std::env::var("PASSBOLT_PASSPHRASE")?),
        mfa_mode: "none".into(),
        mfa_totp_token: String::new(),
        mfa_totp_offset: 0,
        mfa_retrys: 3,
        tls_skip_verify: false,
        tls_client_cert: String::new(),
        tls_client_private_key: String::new(),
        proxy: String::new(),
        // The armored key and fingerprint saved when pinning; empty for none.
        server_public_key: String::new(),
        metadata_key_fingerprint: String::new(),
        server_verify_enc_token: String::new(),
        server_verify_token: String::new(),
        openpgp: OpenPgp::default(),
    };
    let http = NativeHttpClient::new(&NativeHttpConfig {
        tls_skip_verify: false,
        client_cert_pem: None,
        client_key_pem: None,
        proxy_url: None,
        resolve: Vec::new(),
        timeout: Some(std::time::Duration::from_secs(60)),
    })?;
    let client = PassboltSdk::login(http, &config, None, 3).await?;

    // Use the client here.

    client.logout().await?;
    Ok(())
}
```

`SdkConfig` zeroizes the key and the passphrase when dropped.

## Login options

`PassboltSdk::login(http, &config, mfa_provider, max_attempts)` takes:

| Parameter | Type | Description |
|---|---|---|
| `http` | `impl HttpClient` | The transport: `NativeHttpClient`, or your own. |
| `config` | `&SdkConfig` | Server, key, passphrase, MFA, TLS and pinned keys. |
| `mfa_provider` | `Option<Box<dyn MfaProvider>>` | An `MfaProvider`, whose `get_totp_code` returns the code to send. |
| `max_attempts` | `u32` | The number of MFA attempts. |

The fields of `SdkConfig` beyond the credentials:

| Field | Description |
|---|---|
| `mfa_mode` | `"interactive-totp"`, `"non-interactive-totp"` or `"none"`. |
| `mfa_totp_token`, `mfa_totp_offset`, `mfa_retrys` | The TOTP secret, its time offset and the number of retries. |
| `tls_skip_verify`, `tls_client_cert`, `tls_client_private_key`, `proxy` | TLS and proxy settings. |
| `server_public_key`, `metadata_key_fingerprint` | The keys pinned with `auth::fetch_server_key`; empty for none. |
| `openpgp` | The OpenPGP engine that reads keys and writes messages. |

`NativeHttpConfig` sets the transport: `tls_skip_verify`, `client_cert_pem` and `client_key_pem`
for mTLS, `proxy_url`, `resolve` (host names pinned to an address, like `curl --resolve`), and
`timeout` for the whole request (`None` waits forever).

## Read resources

`resource::list::list_resources` returns the resource views, with the names of v5 resources
decrypted. Pass `Some(workers)` as the last argument to decrypt the secrets too.

### Search your resources

```rust
use passbolt_sdk::resource::list::list_resources;
use passbolt_sdk::ResourceQuery;

let query = ResourceQuery {
    search: Some("github".into()),
    ..Default::default()
};
for view in list_resources(&client, query, &[], None).await? {
    println!("{}  {}  {}", view.id, view.name, view.username);
}
```

## Create and share resources

Use the functions of the `resource` modules:

- `resource::create::create_resource(&client, &NewResource)`
- `resource::update::update_resource(&client, id, &ResourceChanges)`
- `resource::share` to share a resource.

## Generate a password

The `generator` module generates passwords, passphrases and PIN codes as the extension does. It
also holds `PasswordPolicies` (from `client.get_password_policies()`), `secret_entropy` and
`Strength`.

## Handle errors

Every call returns `PassboltError`. Its variants are `Transport`, `Auth`, `Crypto`, `Api` (an
`ApiError` with the HTTP `status`), `Json`, `NotFound`, `Config`, `InvalidArgument` and `Other`.
The enum is `#[non_exhaustive]`: end a `match` with a wildcard.

## Modules

| Module | Description |
|---|---|
| `resource::{list, get, create, update, share}` | Views, `create_resource(&client, &NewResource)`, `update_resource(&client, id, &ResourceChanges)`, sharing. |
| `folder::{create, list, share, tree}` | Folders and the folder tree. |
| `user`, `group` | Listing, creation, update. |
| `transfer` | What blocks deleting a user or a group, and the transfer of ownership that unblocks it. |
| `metadata` | v5 metadata keys and settings, `migrate-metadata`. |
| `exchange` | CSV import and export in the formats of other password managers, KDBX import. |
| `crypto` | OpenPGP: parse keys, encrypt, decrypt, fingerprints. |
| `generator` | Passwords, passphrases and PIN codes as the extension generates them, `PasswordPolicies` (`client.get_password_policies()`), `secret_entropy`, `Strength`. |
| `auth` | GPGAuth, `fetch_server_key`. |
| `PassboltSdk` methods | The API calls themselves: `get_resource`, `delete_resource`, `get_folders`, `get_users`, `add_favorite`, `get_tags`… |

Build the reference of every type and function:

```bash
cargo doc -p passbolt-sdk --open
```

## Related

- [Overview](README.md): the concepts shared by every language.
- [API reference](api.md): the API of the bindings, built on this crate.
- [JavaScript](javascript.md): the same crate compiled to WebAssembly.
