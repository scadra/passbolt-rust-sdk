---
title: Rust
sidebar_position: 2
---

# Rust

```toml
[dependencies]
passbolt-sdk = { package = "switch-case-passbolt-sdk", version = "0.1", features = ["native", "totp"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
secrecy = "0.10"
```

The crate is imported as `passbolt_sdk`. Features: `native` (default) brings the reqwest HTTP
client, `totp` the TOTP codes for MFA. Without `native`, implement the `HttpClient` trait over
your own transport, as `passbolt-wasm` does over `fetch`.

## Log in and list

```rust
use passbolt_sdk::resource::list::list_resources;
use passbolt_sdk::{NativeHttpClient, NativeHttpConfig, PassboltSdk, ResourceQuery, SdkConfig};
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

    let query = ResourceQuery {
        search: Some("github".into()),
        ..Default::default()
    };
    // Names decrypted for v5 resources; `Some(workers)` also decrypts the secrets.
    for view in list_resources(&client, query, &[], None).await? {
        println!("{}  {}  {}", view.id, view.name, view.username);
    }

    client.logout().await;
    Ok(())
}
```

`SdkConfig` zeroizes the key and the passphrase when dropped. `login` takes an optional
`MfaProvider` (a `get_totp_code` returning the code to send) and the number of MFA attempts.

## Modules

| Module | What |
|---|---|
| `resource::{list, get, create, update, share}` | views, `create_resource(&client, &NewResource)`, `update_resource(&client, id, &ResourceChanges)`, sharing |
| `folder::{create, list, share, tree}` | folders and the folder tree |
| `user`, `group` | creation, update; deletion with `transfer` |
| `metadata` | v5 metadata keys and settings, `migrate-metadata` |
| `exchange` | CSV import and export in the formats of other password managers, KDBX import |
| `crypto` | OpenPGP: parse keys, encrypt, decrypt, fingerprints |
| `auth` | GPGAuth, `fetch_server_key` |
| `PassboltSdk` methods | the API calls themselves: `get_resource`, `delete_resource`, `get_folders`, `get_users`, `add_favorite`, `get_tags`… |

Errors are `PassboltError`: `Auth`, `Crypto`, `Api` (with the HTTP status), `Transport`…

`cargo doc -p passbolt-sdk --open` builds the reference of every type and function.
