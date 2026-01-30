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

use std::collections::HashMap;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};

use serde_json::Value;

use crate::auth::{self, AuthTokens};
use crate::config::SdkConfig;
use crate::crypto::{self, PrivateKey};
use crate::error::{ApiError, AuthError, CryptoError, PassboltError};
use crate::http::{HttpClient, HttpResponse};
use crate::metadata::{self, MetadataKeys, ResourceSessionKey, SessionKeys, SessionKeysBundle};
use crate::mfa::MfaProvider;
use crate::transfer::{DeleteBlockers, Transfer};
#[allow(clippy::wildcard_imports)] // too many types to enumerate explicitly
use crate::types::*;

/// The server disables an account once its failed TOTP verifications since login exceed
/// `passbolt.security.mfa.maxAttempts` (4 by default): a session never sends more than 3 wrong
/// codes, whatever the number of attempts asked.
const MAX_MFA_FAILURES: u32 = 3;

/// Saves of the session keys bundle that conflict with another session's (409).
const SESSION_KEYS_SAVE_ATTEMPTS: u32 = 3;

/// Main Passbolt SDK client, generic over the HTTP backend.
pub struct PassboltSdk<H: HttpClient> {
    http: H,
    pub base_url: String,
    csrf_token: RwLock<String>,
    pub(crate) private_key: PrivateKey,
    pub(crate) passphrase: SecretString,
    pub user_id: String,
    /// Shared v5 metadata keys, fetched and decrypted at most once per session.
    metadata_keys: OnceLock<Arc<MetadataKeys>>,
    /// Fingerprint of the trusted shared metadata key; `None` trusts the active one.
    trusted_metadata_key: Option<String>,
    /// The user's session keys of resource metadata, read once per session, then kept in step
    /// with what this session saves.
    session_keys: Mutex<Option<Arc<SessionKeys>>>,
    resource_types: OnceLock<Arc<Vec<ResourceType>>>,
    metadata_settings: OnceLock<Arc<MetadataSettings>>,
    /// Answers the MFA challenge the server sends on any request after login.
    mfa_provider: Option<Box<dyn MfaProvider>>,
    mfa_attempts: u32,
    /// TOTP codes refused during this session, against [`MAX_MFA_FAILURES`].
    mfa_failures: AtomicU32,
}

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
    Put,
    Delete,
}

/// `MfaRequiredCheckMiddleware` redirects to `/mfa/verify/error.json`, which answers 403.
fn is_mfa_challenge(response: &HttpResponse) -> bool {
    response.status == 403
        && serde_json::from_slice::<Value>(&response.body).is_ok_and(|body| {
            body.pointer("/header/url")
                .and_then(Value::as_str)
                .is_some_and(|url| url.ends_with("/mfa/verify/error.json"))
        })
}

/// The secret as its type has it: the password itself for `password-string` types, JSON
/// otherwise; guessed from the JSON when the type is unknown.
fn parse_typed_secret(
    text: String,
    secret_is_string: Option<bool>,
) -> Result<SecretData, PassboltError> {
    match secret_is_string {
        Some(true) => Ok(SecretData {
            password: Some(text.clone()),
            raw: Some(text),
            ..Default::default()
        }),
        Some(false) => serde_json::from_str(&text).map_err(|error| {
            PassboltError::Other(format!(
                "The secret is not the JSON its type expects: {error}"
            ))
        }),
        None => parse_secret(text.into_bytes()),
    }
}

/// A JSON object secret, or the plain password of a `password-string` type.
fn parse_secret(plaintext: Vec<u8>) -> Result<SecretData, PassboltError> {
    let text = String::from_utf8(plaintext)
        .map_err(|error| PassboltError::Other(format!("Secret is not valid UTF-8: {error}")))?;
    Ok(
        serde_json::from_str::<SecretData>(&text).unwrap_or_else(|_| SecretData {
            password: Some(text.clone()),
            raw: Some(text),
            ..Default::default()
        }),
    )
}

/// The number of items at `pointer` in `value`.
fn count(value: &Value, pointer: &str) -> u32 {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map_or(0, |items| u32::try_from(items.len()).unwrap_or(u32::MAX))
}

/// The MFA providers a challenge offers (`mfa_providers`); empty when it does not say.
fn mfa_providers(challenge: &HttpResponse) -> Vec<String> {
    serde_json::from_slice::<Value>(&challenge.body)
        .ok()
        .and_then(|body| body.pointer("/body/mfa_providers").cloned())
        .and_then(|providers| serde_json::from_value(providers).ok())
        .unwrap_or_default()
}

/// A wrong code: the server answers it with the validation error of the `totp` field.
fn is_refused_code(response: &HttpResponse) -> bool {
    response.status == 400
        && serde_json::from_slice::<Value>(&response.body)
            .is_ok_and(|body| body.pointer("/body/totp").is_some())
}

fn server_message(response: &HttpResponse) -> String {
    serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|body| body.pointer("/header/message")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("HTTP {}", response.status))
}

/// `id` unchanged if it is a hyphenated UUID, the only form safe to put in a URL path.
fn uuid_segment(id: &str) -> Result<&str, PassboltError> {
    if id.len() == 36 && uuid::Uuid::try_parse(id).is_ok() {
        Ok(id)
    } else {
        Err(PassboltError::InvalidArgument(format!(
            "{id:?} is not a UUID"
        )))
    }
}

/// Refuse a server URL that would send the session in clear text.
fn check_server_url(server_url: &str) -> Result<(), PassboltError> {
    let url = url::Url::parse(server_url)
        .map_err(|error| PassboltError::Config(format!("invalid server_address: {error}")))?;
    match url.scheme() {
        "https" => Ok(()),
        // A local server (docker, end-to-end tests) is often plain HTTP;
        // its traffic never leaves the machine.
        "http" if is_loopback(&url) => Ok(()),
        scheme => Err(PassboltError::Config(format!(
            "server_address must use https, not {scheme}"
        ))),
    }
}

fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

impl<H: HttpClient> PassboltSdk<H> {
    /// Create a new SDK client with a pre-built HTTP backend and authenticate.
    pub async fn login(
        http: H,
        sdk_config: &SdkConfig,
        mfa_provider: Option<Box<dyn MfaProvider>>,
        max_attempts: u32,
    ) -> Result<Self, PassboltError> {
        if sdk_config.server_url.is_empty() {
            return Err(PassboltError::Config(
                "server_address is not configured".into(),
            ));
        }
        check_server_url(&sdk_config.server_url)?;

        let private_key = crypto::parse_private_key(&sdk_config.private_key_armored)?;
        let passphrase = sdk_config.passphrase.clone();
        let base_url = sdk_config.server_url.trim_end_matches('/').to_string();

        auth::check_server_identity(
            &http,
            &base_url,
            &private_key.fingerprint,
            &sdk_config.server_public_key,
            &sdk_config.server_verify_token,
            &sdk_config.server_verify_enc_token,
        )
        .await?;

        let mut tokens: AuthTokens =
            auth::login(&http, &base_url, &private_key, passphrase.expose_secret()).await?;

        let mut client = Self {
            http,
            base_url,
            csrf_token: RwLock::new(std::mem::take(&mut tokens.csrf_token)),
            private_key,
            passphrase,
            user_id: std::mem::take(&mut tokens.user_id),
            metadata_keys: OnceLock::new(),
            trusted_metadata_key: Some(sdk_config.metadata_key_fingerprint.clone())
                .filter(|fingerprint| !fingerprint.is_empty()),
            session_keys: Mutex::default(),
            resource_types: OnceLock::new(),
            metadata_settings: OnceLock::new(),
            mfa_provider,
            mfa_attempts: max_attempts.clamp(1, MAX_MFA_FAILURES),
            mfa_failures: AtomicU32::new(0),
        };

        // Login is exempt from CSRF: the token cookie comes with this first GET.
        client.user_id = client.fetch_current_user().await?;
        if client.csrf_token().is_empty() {
            return Err(
                AuthError::LoginFailed("the server did not provide a CSRF token".into()).into(),
            );
        }
        Ok(client)
    }

    /// Current user id, from `GET /users/me.json` (post-login verify).
    async fn fetch_current_user(&self) -> Result<String, PassboltError> {
        let url = format!("{}/users/me.json?contain[gpgkey]=1", self.base_url);
        let response = self.http_get(&url).await?;
        let current_user: User = self.parse_response(&response).map_err(|error| {
            PassboltError::from(AuthError::LoginFailed(format!(
                "Failed to fetch current user info: {error}"
            )))
        })?;

        // Cross-check: encrypt a probe with the server's copy of our public key,
        // then decrypt it with our private key.
        let armored_key = current_user
            .gpg_key
            .as_ref()
            .and_then(|gpg_key| gpg_key.armored_key.as_deref())
            .ok_or(AuthError::KeyCrossCheckFailed)?;
        let probe = b"passbolt-key-check";
        let decrypted_probe = crypto::parse_public_key(armored_key)
            .and_then(|public_key| crypto::encrypt_message(probe, &[&public_key]))
            .and_then(|encrypted_probe| {
                crypto::decrypt_message(
                    &encrypted_probe,
                    &self.private_key.key,
                    self.passphrase.expose_secret(),
                )
            })
            .map_err(|_| AuthError::KeyCrossCheckFailed)?;
        if decrypted_probe != probe {
            return Err(AuthError::KeyCrossCheckFailed.into());
        }

        Ok(current_user.id)
    }

    /// Terminate the server-side session.
    pub async fn logout(&self) {
        let url = format!("{}/auth/logout.json", self.base_url);
        let csrf_token = self.csrf_token();
        let _ = self
            .http
            .post(&url, &[("X-CSRF-Token", csrf_token.as_str())], &[])
            .await;
    }

    /// Check if the current session is still authenticated.
    ///
    /// Returns `true` if the session is valid, `false` if expired/unauthenticated.
    /// Callers can use this for keep-alive or session refresh logic.
    ///
    /// As the browser extension reads `/auth/is-authenticated.json`: the MFA challenge is an
    /// error, never answered here (a status check must not use MFA attempts), and so are a 404
    /// and an answer that is not JSON.
    pub async fn check_auth_status(&self) -> Result<bool, PassboltError> {
        let url = format!("{}/auth/is-authenticated.json", self.base_url);
        let response = self.send_once(Method::Get, &url, None).await?;
        if is_mfa_challenge(&response) {
            return Err(AuthError::MfaRequired.into());
        }
        if response.status == 404 || serde_json::from_slice::<Value>(&response.body).is_err() {
            return Err(ApiError {
                status: response.status,
                message: format!(
                    "unexpected answer to the session check: {}",
                    server_message(&response)
                ),
                validation_errors: None,
            }
            .into());
        }
        Ok(response.status < 400)
    }

    /// Keep the session alive, as the browser extension does every few minutes
    /// (`keepSessionAliveService`): a long-lived client stays logged in between operations.
    pub async fn keep_alive(&self) -> Result<(), PassboltError> {
        let _: Value = self.get("/users/me.json").await?;
        Ok(())
    }

    // ── Internal HTTP helpers ─────────────────────────────────────────────────

    /// Token to send as `X-CSRF-Token`: the `csrfToken` cookie, whichever request set it.
    pub fn csrf_token(&self) -> String {
        self.http
            .cookie(&self.base_url, "csrfToken")
            .unwrap_or_else(|| self.csrf_token.read().unwrap().clone())
    }

    fn remember_csrf_cookie(&self, response: &HttpResponse) {
        if let Some(token) = auth::csrf_cookie(response) {
            *self.csrf_token.write().unwrap() = token;
        }
    }

    async fn http_get(&self, url: &str) -> Result<HttpResponse, PassboltError> {
        self.send(Method::Get, url, None).await
    }

    /// Send a request. When the server asks for MFA (on the first request after login,
    /// or once the MFA cookie expires), answer it and replay the request once.
    async fn send(
        &self,
        method: Method,
        url: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, PassboltError> {
        let response = self.send_once(method, url, body).await?;
        if !is_mfa_challenge(&response) {
            return Ok(response);
        }
        self.verify_mfa(&response).await?;
        let response = self.send_once(method, url, body).await?;
        if is_mfa_challenge(&response) {
            return Err(AuthError::MfaFailed {
                attempts: self.mfa_attempts,
                message: "MFA was requested again right after a successful verification".into(),
            }
            .into());
        }
        Ok(response)
    }

    async fn send_once(
        &self,
        method: Method,
        url: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, PassboltError> {
        let csrf_token = self.csrf_token();
        let headers = [("X-CSRF-Token", csrf_token.as_str())];
        let response = match (method, body) {
            (Method::Get, _) => self.http.get(url, &[]).await?,
            (Method::Post, body) => {
                self.http
                    .post(url, &headers, body.unwrap_or_default())
                    .await?
            }
            (Method::Put, body) => {
                self.http
                    .put(url, &headers, body.unwrap_or_default())
                    .await?
            }
            (Method::Delete, None) => self.http.delete(url, &headers).await?,
            (Method::Delete, Some(body)) => self.http.delete_with_body(url, &headers, body).await?,
        };
        self.remember_csrf_cookie(&response);
        Ok(response)
    }

    /// Answer the TOTP `challenge`; the server sets the `passbolt_mfa` cookie on success.
    ///
    /// A refused code is tried again, up to the attempts asked and never more than
    /// [`MAX_MFA_FAILURES`] refused codes in the session. Any other refusal ends the attempts:
    /// the server logs the user out (and disables them) when it gets too many.
    async fn verify_mfa(&self, challenge: &HttpResponse) -> Result<(), PassboltError> {
        let providers = mfa_providers(challenge);
        if !providers.is_empty() && !providers.iter().any(|provider| provider == "totp") {
            return Err(AuthError::MfaUnsupported { providers }.into());
        }
        let provider = self.mfa_provider.as_deref().ok_or(AuthError::MfaRequired)?;
        let url = format!("{}/mfa/verify/totp.json", self.base_url);
        let mut attempts = 0;
        let mut last_error = String::new();
        while attempts < self.mfa_attempts
            && self.mfa_failures.load(Ordering::SeqCst) < MAX_MFA_FAILURES
        {
            attempts += 1;
            let body = serde_json::to_vec(
                &serde_json::json!({ "totp": provider.get_totp_code()?, "remember": false }),
            )?;
            let response = self.send_once(Method::Post, &url, Some(&body)).await?;
            if response.status < 400 {
                return Ok(());
            }
            if !is_refused_code(&response) {
                return Err(AuthError::MfaLockedOut(server_message(&response)).into());
            }
            self.mfa_failures.fetch_add(1, Ordering::SeqCst);
            last_error = server_message(&response);
        }
        if attempts == 0 {
            last_error = format!("{MAX_MFA_FAILURES} codes were already refused in this session");
        }
        Err(AuthError::MfaFailed {
            attempts,
            message: last_error,
        }
        .into())
    }

    pub(crate) async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let response = self.http_get(&url).await?;
        self.parse_response(&response)
    }

    async fn get_with_query<T, K, V>(
        &self,
        path: &str,
        params: &[(K, V)],
    ) -> Result<T, PassboltError>
    where
        T: DeserializeOwned,
        K: AsRef<str> + Sync,
        V: AsRef<str> + Sync,
    {
        // Build URL with query string
        let mut url = format!("{}{path}", self.base_url);
        if !params.is_empty() {
            let separator = if url.contains('?') { '&' } else { '?' };
            url.push(separator);
            let query_pairs: Vec<String> = params
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        percent_encoding::utf8_percent_encode(
                            key.as_ref(),
                            percent_encoding::NON_ALPHANUMERIC,
                        ),
                        percent_encoding::utf8_percent_encode(
                            value.as_ref(),
                            percent_encoding::NON_ALPHANUMERIC,
                        ),
                    )
                })
                .collect();
            url.push_str(&query_pairs.join("&"));
        }

        let response = self.http_get(&url).await?;
        self.parse_response(&response)
    }

    pub(crate) async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<T, PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let json_body = serde_json::to_vec(body)?;
        let response = self.send(Method::Post, &url, Some(&json_body)).await?;
        self.parse_response(&response)
    }

    async fn put_request<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<T, PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let json_body = serde_json::to_vec(body)?;
        let response = self.send(Method::Put, &url, Some(&json_body)).await?;
        self.parse_response(&response)
    }

    async fn delete_request(&self, path: &str) -> Result<(), PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let response = self.send(Method::Delete, &url, None).await?;

        if response.status >= 400 {
            let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
            let message = body
                .pointer("/header/message")
                .and_then(|value| value.as_str())
                .unwrap_or("Unknown error");
            return Err(ApiError {
                status: response.status,
                message: format!("DELETE {path} failed: {message}"),
                validation_errors: None,
            }
            .into());
        }
        Ok(())
    }

    #[allow(clippy::unused_self)] // keeps API consistent; may use self for logging later
    fn parse_response<T: DeserializeOwned>(
        &self,
        response: &HttpResponse,
    ) -> Result<T, PassboltError> {
        let body: Value = serde_json::from_slice(&response.body)?;

        if response.status >= 400 {
            let message = body
                .pointer("/header/message")
                .and_then(|value| value.as_str())
                .unwrap_or("Unknown error");
            let validation_errors = body.get("body").cloned();
            return Err(ApiError {
                status: response.status,
                message: message.to_string(),
                validation_errors,
            }
            .into());
        }

        let data = body.get("body").cloned().unwrap_or(body);
        serde_json::from_value(data).map_err(PassboltError::from)
    }

    /// Fetch a paginated list endpoint.
    ///
    /// - If `pagination.page` is `Some(p)`, fetch only that page.
    /// - If `pagination.page` is `None`, auto-paginate all pages (max 100 safety limit).
    async fn get_paginated<T: DeserializeOwned>(
        &self,
        path: &str,
        base_params: &[(&str, String)],
        pagination: &PaginationParams,
    ) -> Result<Vec<T>, PassboltError> {
        let mut all_params: Vec<(&str, String)> = base_params.to_vec();

        if let Some(limit) = pagination.limit {
            all_params.push(("api-version", "v2".into()));
            all_params.push(("limit", limit.to_string()));
        }

        // Single-page mode
        if let Some(page) = pagination.page {
            all_params.push(("page", page.to_string()));
            return self.get_with_query(path, &all_params).await;
        }

        // Auto-paginate mode (safety limit)
        let max_pages: u32 = 100;
        let mut results: Vec<T> = Vec::new();

        for page in 1..=max_pages {
            let mut page_params = all_params.clone();
            page_params.push(("page", page.to_string()));

            let url = self.build_query_url(path, &page_params);
            let response = self.http_get(&url).await?;
            let body: Value = serde_json::from_slice(&response.body)?;

            if response.status >= 400 {
                let message = body
                    .pointer("/header/message")
                    .and_then(|value| value.as_str())
                    .unwrap_or("Unknown error");
                return Err(ApiError {
                    status: response.status,
                    message: message.to_string(),
                    validation_errors: None,
                }
                .into());
            }

            let data = body.get("body").cloned().unwrap_or_else(|| body.clone());
            let page_items: Vec<T> = serde_json::from_value(data)?;
            let page_count = page_items.len();
            results.extend(page_items);

            // Check pagination info from response header
            let pagination_info = body
                .pointer("/header/pagination")
                .and_then(|value| serde_json::from_value::<PaginationInfo>(value.clone()).ok());

            if let Some(info) = pagination_info {
                let limit = info.limit.unwrap_or(20);
                if page_count < limit as usize || results.len() >= info.count as usize {
                    break;
                }
            } else {
                // No pagination header — single page response
                break;
            }
        }

        Ok(results)
    }

    fn build_query_url<K: AsRef<str>, V: AsRef<str>>(
        &self,
        path: &str,
        params: &[(K, V)],
    ) -> String {
        let mut url = format!("{}{path}", self.base_url);
        if !params.is_empty() {
            let separator = if url.contains('?') { '&' } else { '?' };
            url.push(separator);
            let query_pairs: Vec<String> = params
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        percent_encoding::utf8_percent_encode(
                            key.as_ref(),
                            percent_encoding::NON_ALPHANUMERIC,
                        ),
                        percent_encoding::utf8_percent_encode(
                            value.as_ref(),
                            percent_encoding::NON_ALPHANUMERIC,
                        ),
                    )
                })
                .collect();
            url.push_str(&query_pairs.join("&"));
        }
        url
    }

    // ── v5 Metadata key ────────────────────────────────────────────────────────

    /// The shared metadata keys the user holds a share of, cached for the session.
    pub async fn metadata_keys(&self) -> Result<Arc<MetadataKeys>, PassboltError> {
        if let Some(keys) = self.metadata_keys.get() {
            return Ok(Arc::clone(keys));
        }
        let keys: Vec<MetadataKey> = self
            .get("/metadata/keys.json?contain[metadata_private_keys]=1&filter[deleted]=0")
            .await?;
        let decrypted_keys = Arc::new(MetadataKeys::decrypt(
            &keys,
            &self.user_id,
            &self.private_key.key,
            self.passphrase.expose_secret(),
        )?);
        // A concurrent caller may have set it first: both decrypted the same keys.
        Ok(Arc::clone(
            self.metadata_keys.get_or_init(|| decrypted_keys),
        ))
    }

    /// Encrypt `metadata` for the active shared key, if it is the trusted one, as the browser
    /// extension checks before writing shared metadata.
    pub(crate) async fn encrypt_shared_metadata(
        &self,
        metadata: &ResourceMetadata,
    ) -> Result<metadata::EncryptedMetadata, PassboltError> {
        let metadata_keys = self.metadata_keys().await?;
        if let (Some(pinned), Some(active)) = (
            &self.trusted_metadata_key,
            metadata_keys.active_fingerprint(),
        ) {
            if !pinned.eq_ignore_ascii_case(&active) {
                return Err(CryptoError::UntrustedMetadataKey {
                    pinned: pinned.clone(),
                    active,
                }
                .into());
            }
        }
        metadata_keys.encrypt(metadata, &self.user_signer())
    }

    /// The user's session keys bundles, still encrypted.
    pub async fn session_keys_bundles(&self) -> Result<Vec<SessionKeysBundle>, PassboltError> {
        self.get("/metadata/session-keys.json").await
    }

    /// The user's session keys of resource metadata, read once per session. Empty when they
    /// cannot be read: they only make decryption faster.
    pub async fn session_keys(&self) -> Arc<SessionKeys> {
        if let Some(session_keys) = self.cached_session_keys() {
            return session_keys;
        }
        let session_keys = Arc::new(self.read_session_keys().await);
        Arc::clone(
            self.session_keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_or_insert(session_keys),
        )
    }

    fn cached_session_keys(&self) -> Option<Arc<SessionKeys>> {
        self.session_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn read_session_keys(&self) -> SessionKeys {
        let bundles = self.session_keys_bundles().await.unwrap_or_default();
        SessionKeys::decrypt(
            &bundles,
            &self.private_key.key,
            self.passphrase.expose_secret(),
        )
    }

    /// Add `new` session keys to the user's latest bundle, created if there is none, then
    /// delete the older bundles, as the browser extension does. A bundle changed meanwhile
    /// by another session (409) is read again, up to [`SESSION_KEYS_SAVE_ATTEMPTS`] times.
    pub async fn save_session_keys(&self, new: &[ResourceSessionKey]) -> Result<(), PassboltError> {
        if new.is_empty() {
            return Ok(());
        }
        let mut current = self.session_keys().await;
        let mut attempt = 1;
        let saved = loop {
            match self.write_session_keys(&current.with(new)).await {
                Err(PassboltError::Api(ApiError { status: 409, .. }))
                    if attempt < SESSION_KEYS_SAVE_ATTEMPTS =>
                {
                    attempt += 1;
                    current = Arc::new(self.read_session_keys().await);
                }
                result => break result?,
            }
        };
        *self
            .session_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(saved));
        Ok(())
    }

    /// Store `session_keys` in their latest bundle and delete the older ones; returns them as
    /// saved.
    async fn write_session_keys(
        &self,
        session_keys: &SessionKeys,
    ) -> Result<SessionKeys, PassboltError> {
        let me = self.get_me().await?;
        let (public_key, _) = crate::resource::document::public_key_of(&me)?;
        let data = crypto::sign_and_encrypt(
            &session_keys.bundle_data()?,
            &[self.user_signer()],
            &[&public_key],
        )?;
        let saved: SessionKeysBundle = match session_keys.bundle() {
            Some((id, modified)) => {
                let body = serde_json::json!({ "data": data, "modified": modified });
                self.put_request(
                    &format!("/metadata/session-keys/{}.json", uuid_segment(id)?),
                    &body,
                )
                .await?
            }
            None => {
                self.post(
                    "/metadata/session-keys.json",
                    &serde_json::json!({ "data": data }),
                )
                .await?
            }
        };
        for older_id in session_keys.older_bundle_ids() {
            // A bundle left behind is only read again and replaced next time.
            let _ = self
                .delete_request(&format!(
                    "/metadata/session-keys/{}.json",
                    uuid_segment(older_id)?
                ))
                .await;
        }
        Ok(session_keys
            .clone()
            .saved_in(saved.id, saved.modified.unwrap_or_default()))
    }

    /// Decrypt the `metadata` of a v5 resource, with its session key when known; also gives
    /// the session key of the metadata when it was not known.
    pub(crate) async fn decrypt_resource_metadata_keeping_session_key(
        &self,
        resource: &Resource,
    ) -> Result<Option<(ResourceMetadata, Option<crypto::SessionKey>)>, PassboltError> {
        if !resource.is_v5() {
            return Ok(None);
        }
        let session_keys = self.session_keys().await;
        let decrypt = |shared_keys: &MetadataKeys| {
            metadata::decrypt_resource_metadata_with_session_keys(
                resource,
                &self.private_key.key,
                self.passphrase.expose_secret(),
                shared_keys,
                &session_keys,
            )
        };
        let personal = resource.metadata_key_type.as_deref() == Some("user_key");
        // The shared keys are fetched only if the session key is missing or stale.
        if personal || session_keys.get(&resource.id).is_some() {
            let decrypted = decrypt(&MetadataKeys::default());
            if personal || decrypted.is_ok() {
                return decrypted;
            }
        }
        let shared_keys = self.metadata_keys().await?;
        decrypt(&shared_keys)
    }

    /// Decrypt the `metadata` of a v5 resource; `None` for a v4 resource.
    pub async fn decrypt_resource_metadata(
        &self,
        resource: &Resource,
    ) -> Result<Option<ResourceMetadata>, PassboltError> {
        let decrypted = self
            .decrypt_resource_metadata_keeping_session_key(resource)
            .await?;
        Ok(decrypted.map(|(metadata, _)| metadata))
    }

    // ── Batch decrypt (native only — requires tokio JoinSet) ────────────────

    /// Decrypt secrets for a batch of resources in parallel.
    #[cfg(feature = "native")]
    pub async fn decrypt_secrets_batch(
        &self,
        resources: &[Resource],
        workers: usize,
    ) -> Result<HashMap<String, SecretData>, PassboltError> {
        let mut texts = self.decrypt_secret_texts_batch(resources, workers).await?;
        let mut secrets = HashMap::with_capacity(resources.len());
        for resource in resources {
            let secret = match texts.remove(&resource.id) {
                Some(text) => parse_typed_secret(text?, self.secret_is_string(resource).await?)?,
                None => SecretData::default(),
            };
            secrets.insert(resource.id.clone(), secret);
        }
        Ok(secrets)
    }

    /// The decrypted secrets of `resources` by resource id, as written, or why one could not be
    /// decrypted; resources without a secret for the user are left out. Decrypted in parallel
    /// on `workers` threads (0: one per CPU).
    // Without `native`, decryption is sequential: nothing to await, nothing to share.
    #[cfg_attr(
        not(feature = "native"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            clippy::needless_collect
        )
    )]
    pub async fn decrypt_secret_texts_batch(
        &self,
        resources: &[Resource],
        workers: usize,
    ) -> Result<HashMap<String, Result<String, PassboltError>>, PassboltError> {
        let encrypted_secrets: Vec<(String, String)> = resources
            .iter()
            .filter_map(|resource| {
                let encrypted = resource.secrets.first()?.data.clone()?;
                (!encrypted.is_empty()).then(|| (resource.id.clone(), encrypted))
            })
            .collect();
        let key = Arc::new(self.private_key.key.clone());
        let passphrase = Arc::new(self.passphrase.clone());
        let decrypt = move |id: String, encrypted: String| {
            let text = crypto::decrypt_message(&encrypted, &key, passphrase.expose_secret())
                .map_err(|error| {
                    CryptoError::Decrypt(format!("resource {id} secret: {error}")).into()
                })
                .and_then(|plaintext| {
                    String::from_utf8(plaintext).map_err(|error| {
                        PassboltError::Other(format!(
                            "Secret of resource {id} is not valid UTF-8: {error}"
                        ))
                    })
                });
            (id, text)
        };

        #[cfg(feature = "native")]
        {
            use tokio::task::JoinSet;

            let concurrency = if workers == 0 {
                std::thread::available_parallelism().map_or(4, std::num::NonZero::get)
            } else {
                workers
            };
            let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
            let decrypt = Arc::new(decrypt);
            let mut tasks = JoinSet::new();
            for (id, encrypted) in encrypted_secrets {
                let permit = Arc::clone(&semaphore)
                    .acquire_owned()
                    .await
                    .map_err(|error| PassboltError::Other(format!("Semaphore error: {error}")))?;
                let decrypt = Arc::clone(&decrypt);
                tasks.spawn_blocking(move || {
                    let _permit = permit;
                    decrypt(id, encrypted)
                });
            }
            let mut texts = HashMap::new();
            while let Some(result) = tasks.join_next().await {
                let (id, text) = result.map_err(|error| {
                    PassboltError::Other(format!("Decryption task failed: {error}"))
                })?;
                texts.insert(id, text);
            }
            Ok(texts)
        }
        #[cfg(not(feature = "native"))]
        {
            let _ = workers;
            Ok(encrypted_secrets
                .into_iter()
                .map(|(id, encrypted)| decrypt(id, encrypted))
                .collect())
        }
    }

    /// Decrypt the metadata of the v5 resources among `resources`, by resource id.
    pub async fn decrypt_metadata_batch(
        &self,
        resources: &[Resource],
    ) -> Result<HashMap<String, ResourceMetadata>, PassboltError> {
        let mut metadatas = HashMap::new();
        for resource in resources {
            if let Some(metadata) = self.decrypt_resource_metadata(resource).await? {
                metadatas.insert(resource.id.clone(), metadata);
            }
        }
        Ok(metadatas)
    }

    // ── Crypto accessors ────────────────────────────────────────────────────

    /// Get a reference-counted clone of the PGP private key for parallel tasks.
    pub fn pgp_key_arc(&self) -> Arc<pgp::SignedSecretKey> {
        Arc::new(self.private_key.key.clone())
    }

    /// Get a reference-counted clone of the passphrase for parallel tasks.
    pub fn passphrase_arc(&self) -> Arc<SecretString> {
        Arc::new(self.passphrase.clone())
    }

    // ── Resources ──────────────────────────────────────────────────────────────

    pub async fn get_resources(
        &self,
        options: ResourceQuery,
    ) -> Result<Vec<Resource>, PassboltError> {
        let mut params: Vec<(&str, String)> = vec![
            ("contain[permission]", "1".into()),
            ("contain[secret]", "1".into()),
            ("contain[favorite]", "1".into()),
        ];

        // The server filters on one group: `filter[is-shared-with-group]` is not a list.
        match <[String; 1]>::try_from(options.group_ids) {
            Ok([group_id]) => params.push(("filter[is-shared-with-group]", group_id)),
            Err(group_ids) if group_ids.is_empty() => {}
            Err(_) => {
                return Err(PassboltError::InvalidArgument(
                    "Resources can be filtered on one group only".into(),
                ))
            }
        }
        for folder_id in options.folder_ids {
            params.push(("filter[has-parent][]", folder_id));
        }

        if options.favorites_only {
            params.push(("filter[is-favorite]", "1".into()));
        }
        if options.owned_by_me {
            params.push(("filter[is-owned-by-me]", "1".into()));
        }
        if let Some(search) = options.search {
            params.push(("filter[search]", search));
        }

        self.get_paginated("/resources.json", &params, &options.pagination)
            .await
    }

    pub async fn get_resource(&self, id: &str) -> Result<Resource, PassboltError> {
        let id = uuid_segment(id)?;
        self.get(&format!(
            "/resources/{id}.json?contain[permission]=1&contain[secret]=1"
        ))
        .await
    }

    pub async fn create_resource(
        &self,
        payload: &CreateResourcePayload,
    ) -> Result<Resource, PassboltError> {
        let body = serde_json::to_value(payload)?;
        self.post("/resources.json", &body).await
    }

    pub async fn update_resource(
        &self,
        id: &str,
        payload: &UpdateResourcePayload,
    ) -> Result<Resource, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        self.put_request(&format!("/resources/{id}.json"), &body)
            .await
    }

    pub async fn delete_resource(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/resources/{id}.json")).await
    }

    pub async fn get_resource_permissions(
        &self,
        id: &str,
    ) -> Result<Vec<Permission>, PassboltError> {
        let id = uuid_segment(id)?;
        self.get(&format!("/permissions/resource/{id}.json")).await
    }

    /// Fetch and decrypt a resource secret.
    pub async fn decrypt_resource_secret(
        &self,
        resource: &Resource,
    ) -> Result<SecretData, PassboltError> {
        let Some(text) = self.decrypt_resource_secret_text(resource).await? else {
            return Ok(SecretData::default());
        };
        let secret_is_string = self.secret_is_string(resource).await?;
        parse_typed_secret(text, secret_is_string)
    }

    /// The decrypted secret as written: the password of `password-string` types, JSON otherwise.
    ///
    /// `None` when the resource has no secret for the user.
    pub async fn decrypt_resource_secret_text(
        &self,
        resource: &Resource,
    ) -> Result<Option<String>, PassboltError> {
        let secret_data = if let Some(secret) = resource.secrets.first() {
            secret.data.clone().unwrap_or_default()
        } else {
            let secrets: Vec<Secret> = self
                .get(&format!(
                    "/secrets/resource/{}.json",
                    uuid_segment(&resource.id)?
                ))
                .await?;
            secrets
                .first()
                .and_then(|secret| secret.data.clone())
                .unwrap_or_default()
        };

        if secret_data.is_empty() {
            return Ok(None);
        }

        let plaintext = crypto::decrypt_message(
            &secret_data,
            &self.private_key.key,
            self.passphrase.expose_secret(),
        )
        .map_err(|error| CryptoError::Decrypt(format!("resource secret: {error}")))?;
        String::from_utf8(plaintext)
            .map(Some)
            .map_err(|error| PassboltError::Other(format!("Secret is not valid UTF-8: {error}")))
    }

    /// Whether the secret of `resource` is the password itself, by its type
    /// (`password-string`); `None` type, or one the server does not list: guessed from the JSON.
    async fn secret_is_string(&self, resource: &Resource) -> Result<Option<bool>, PassboltError> {
        let Some(type_id) = resource.resource_type_id.as_deref() else {
            return Ok(None);
        };
        Ok(self
            .resource_types()
            .await?
            .iter()
            .find(|resource_type| resource_type.id == type_id)
            .map(ResourceType::secret_is_string))
    }

    /// The user's key, to sign what the user encrypts.
    pub(crate) fn user_signer(&self) -> crypto::Signer<'_> {
        crypto::Signer {
            key: &self.private_key.key,
            passphrase: self.passphrase.expose_secret(),
        }
    }

    /// Encrypt a secret for the given user IDs, signed by the user.
    pub async fn encrypt_secret_for_users(
        &self,
        secret_json: &str,
        user_ids: &[String],
    ) -> Result<Vec<SecretPayload>, PassboltError> {
        let mut payloads = Vec::new();

        for user_id in user_ids {
            let user: User = self
                .get(&format!(
                    "/users/{}.json?contain[gpgkey]=1",
                    uuid_segment(user_id)?
                ))
                .await?;
            let armored_key = user
                .gpg_key
                .as_ref()
                .and_then(|gpg_key| gpg_key.armored_key.as_deref())
                .ok_or_else(|| PassboltError::NotFound(format!("User {user_id} has no GPG key")))?;

            let public_key = crypto::parse_public_key(armored_key)?;
            let encrypted =
                crypto::sign_and_encrypt(secret_json, &[self.user_signer()], &[&public_key])?;

            payloads.push(SecretPayload {
                user_id: user_id.clone(),
                data: encrypted,
            });
        }

        Ok(payloads)
    }

    // ── Folders ───────────────────────────────────────────────────────────────

    pub async fn get_folders(&self, options: FolderQuery) -> Result<Vec<Folder>, PassboltError> {
        let mut params: Vec<(&str, String)> = vec![
            ("contain[permission]", "1".into()),
            ("contain[permissions]", "1".into()),
        ];

        if let Some(search) = options.search {
            params.push(("filter[search]", search));
        }
        for parent_folder_id in options.parent_folder_ids {
            params.push(("filter[has-parent][]", parent_folder_id));
        }

        let mut folders: Vec<Folder> = self
            .get_paginated("/folders.json", &params, &options.pagination)
            .await?;
        // The folders index has no group filter: keep the folders the group has a permission on.
        if let Some(group_id) = options.group_id {
            folders.retain(|folder| {
                folder.permissions.iter().any(|permission| {
                    permission.aro.as_deref() == Some("Group")
                        && permission.aro_foreign_key.as_deref() == Some(group_id.as_str())
                })
            });
        }
        Ok(folders)
    }

    /// The folder with its permissions and the user's own one.
    pub async fn get_folder(&self, id: &str) -> Result<Folder, PassboltError> {
        let id = uuid_segment(id)?;
        self.get(&format!(
            "/folders/{id}.json?contain[permission]=1&contain[permissions]=1"
        ))
        .await
    }

    pub async fn create_folder(
        &self,
        payload: &CreateFolderPayload,
    ) -> Result<Folder, PassboltError> {
        let body = serde_json::to_value(payload)?;
        self.post("/folders.json", &body).await
    }

    pub async fn update_folder(
        &self,
        id: &str,
        payload: &UpdateFolderPayload,
    ) -> Result<Folder, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        self.put_request(&format!("/folders/{id}.json"), &body)
            .await
    }

    /// Delete a folder; its content moves to the root.
    pub async fn delete_folder(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/folders/{id}.json")).await
    }

    /// Delete a folder with its sub-folders and the resources the user may delete in them.
    pub async fn delete_folder_with_content(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/folders/{id}.json?cascade=1"))
            .await
    }

    pub async fn get_folder_permissions(&self, id: &str) -> Result<Vec<Permission>, PassboltError> {
        let id = uuid_segment(id)?;
        let folder: Folder = self
            .get(&format!("/folders/{id}.json?contain[permissions]=1"))
            .await?;
        Ok(folder.permissions)
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    pub async fn get_users(&self, options: UserQuery) -> Result<Vec<User>, PassboltError> {
        let mut params: Vec<(&str, String)> = vec![
            ("contain[role]", "1".into()),
            ("contain[gpgkey]", "1".into()),
            ("contain[groups_users]", "1".into()),
        ];

        if let Some(search) = options.search {
            params.push(("filter[search]", search));
        }
        if let Some(group_id) = options.group_id {
            params.push(("filter[has-groups]", group_id));
        }
        if let Some(resource_id) = options.resource_id {
            params.push(("filter[has-access]", resource_id));
        }
        if options.admin_only {
            params.push(("filter[is-admin]", "1".into()));
        }

        self.get_paginated("/users.json", &params, &options.pagination)
            .await
    }

    pub async fn get_user(&self, id: &str) -> Result<User, PassboltError> {
        let id = if id == "me" { id } else { uuid_segment(id)? };
        self.get(&format!(
            "/users/{id}.json?contain[role]=1&contain[gpgkey]=1"
        ))
        .await
    }

    pub async fn create_user(&self, payload: &CreateUserPayload) -> Result<User, PassboltError> {
        let body = serde_json::to_value(payload)?;
        self.post("/users.json", &body).await
    }

    pub async fn update_user(
        &self,
        id: &str,
        payload: &UpdateUserPayload,
    ) -> Result<User, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        self.put_request(&format!("/users/{id}.json"), &body).await
    }

    pub async fn delete_user(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/users/{id}.json")).await
    }

    pub async fn get_me(&self) -> Result<User, PassboltError> {
        self.get("/users/me.json?contain[role]=1&contain[gpgkey]=1")
            .await
    }

    // ── Groups ────────────────────────────────────────────────────────────────

    pub async fn get_groups(&self, options: GroupQuery) -> Result<Vec<Group>, PassboltError> {
        let mut params: Vec<(&str, String)> = vec![("contain[groups_users]", "1".into())];

        if let Some(user_id) = options.user_id {
            params.push(("filter[has-users]", user_id));
        }
        if let Some(manager_id) = options.manager_id {
            params.push(("filter[has-managers]", manager_id));
        }

        self.get_paginated("/groups.json", &params, &options.pagination)
            .await
    }

    pub async fn get_group(&self, id: &str) -> Result<Group, PassboltError> {
        let id = uuid_segment(id)?;
        self.get(&format!(
            "/groups/{id}.json?contain[groups_users]=1&contain[groups_users.user.profile]=1"
        ))
        .await
    }

    pub async fn create_group(&self, payload: &CreateGroupPayload) -> Result<Group, PassboltError> {
        let body = serde_json::to_value(payload)?;
        self.post("/groups.json", &body).await
    }

    /// `PUT /groups/{id}/dry-run.json`: the secrets new members need, and the user's own
    /// secrets to encrypt them from.
    pub async fn update_group_dry_run(
        &self,
        id: &str,
        payload: &UpdateGroupPayload,
    ) -> Result<Value, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        self.put_request(&format!("/groups/{id}/dry-run.json"), &body)
            .await
    }

    /// Decrypt a message encrypted for the user.
    pub(crate) fn decrypt_text(&self, armored: &str) -> Result<String, PassboltError> {
        let plaintext = crypto::decrypt_message(
            armored,
            &self.private_key.key,
            self.passphrase.expose_secret(),
        )?;
        String::from_utf8(plaintext)
            .map_err(|error| PassboltError::Other(format!("Secret is not valid UTF-8: {error}")))
    }

    pub async fn update_group(
        &self,
        id: &str,
        payload: &UpdateGroupPayload,
    ) -> Result<Group, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        self.put_request(&format!("/groups/{id}.json"), &body).await
    }

    pub async fn delete_group(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/groups/{id}.json")).await
    }

    // ── Favorites ─────────────────────────────────────────────────────────────

    pub async fn add_favorite(&self, resource_id: &str) -> Result<Favorite, PassboltError> {
        let resource_id = uuid_segment(resource_id)?;
        let body = serde_json::json!({});
        self.post(&format!("/favorites/resource/{resource_id}.json"), &body)
            .await
    }

    pub async fn remove_favorite(&self, favorite_id: &str) -> Result<(), PassboltError> {
        let favorite_id = uuid_segment(favorite_id)?;
        self.delete_request(&format!("/favorites/{favorite_id}.json"))
            .await
    }

    // ── Sharing ───────────────────────────────────────────────────────────────

    pub async fn share_resource(
        &self,
        id: &str,
        payload: &SharePayload,
    ) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        let _: Value = self
            .put_request(&format!("/share/resource/{id}.json"), &body)
            .await?;
        Ok(())
    }

    /// `POST /share/simulate/resource/{id}.json`: the users who would gain access.
    pub async fn simulate_share_resource(
        &self,
        id: &str,
        permissions: &[ShareChange],
    ) -> Result<Vec<String>, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::json!({ "permissions": permissions });
        let simulation: Value = self
            .post(&format!("/share/simulate/resource/{id}.json"), &body)
            .await?;
        Ok(simulation
            .pointer("/changes/added")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|added| added.pointer("/User/id")?.as_str().map(String::from))
            .collect())
    }

    pub async fn share_folder(
        &self,
        id: &str,
        payload: &SharePayload,
    ) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        let _: Value = self
            .put_request(&format!("/share/folder/{id}.json"), &body)
            .await?;
        Ok(())
    }

    // ── Roles ─────────────────────────────────────────────────────────────────

    pub async fn get_role_id_by_name(&self, role_name: &str) -> Result<String, PassboltError> {
        let roles: Vec<serde_json::Value> = self.get("/roles.json").await?;
        roles
            .iter()
            .find(|role| role["name"].as_str() == Some(role_name))
            .and_then(|role| role["id"].as_str())
            .map(str::to_owned)
            .ok_or_else(|| PassboltError::NotFound(format!("Role not found: {role_name}")))
    }

    // ── Resource types ────────────────────────────────────────────────────────

    /// The resource types, cached for the session.
    pub async fn resource_types(&self) -> Result<Arc<Vec<ResourceType>>, PassboltError> {
        if let Some(types) = self.resource_types.get() {
            return Ok(Arc::clone(types));
        }
        let types: Vec<ResourceType> = self.get("/resource-types.json").await?;
        Ok(Arc::clone(
            self.resource_types.get_or_init(|| Arc::new(types)),
        ))
    }

    /// The resource type named `slug`; an error if the server does not have it.
    pub async fn resource_type_by_slug(&self, slug: &str) -> Result<ResourceType, PassboltError> {
        self.resource_types()
            .await?
            .iter()
            .find(|resource_type| resource_type.slug == slug)
            .cloned()
            .ok_or_else(|| PassboltError::InvalidArgument(format!("Unknown resource type: {slug}")))
    }

    pub async fn get_resource_type_id_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<String>, PassboltError> {
        Ok(self
            .resource_types()
            .await?
            .iter()
            .find(|resource_type| resource_type.slug == slug)
            .map(|resource_type| resource_type.id.clone()))
    }

    // ── Move ──────────────────────────────────────────────────────────────────

    pub async fn move_resource(
        &self,
        id: &str,
        folder_parent_id: Option<&str>,
    ) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        let payload = MovePayload {
            folder_parent_id: folder_parent_id.map(String::from),
        };
        let body = serde_json::to_value(&payload)?;
        let _: Value = self
            .put_request(&format!("/move/resource/{id}.json"), &body)
            .await?;
        Ok(())
    }

    pub async fn move_folder(
        &self,
        id: &str,
        folder_parent_id: Option<&str>,
    ) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        let payload = MovePayload {
            folder_parent_id: folder_parent_id.map(String::from),
        };
        let body = serde_json::to_value(&payload)?;
        let _: Value = self
            .put_request(&format!("/move/folder/{id}.json"), &body)
            .await?;
        Ok(())
    }

    // ── Bulk Delete ──────────────────────────────────────────────────────────

    /// Delete multiple resources at once.
    /// Delete resources one by one, as the browser extension does: the API has no bulk delete.
    /// Stops at the first failure; the resources before it are deleted.
    pub async fn delete_resources(&self, ids: &[String]) -> Result<(), PassboltError> {
        for id in ids {
            self.delete_resource(id).await?;
        }
        Ok(())
    }

    // ── Find Resources by IDs ────────────────────────────────────────────────

    /// Fetch multiple resources by their IDs in a single request.
    pub async fn get_resources_by_ids(
        &self,
        ids: &[String],
    ) -> Result<Vec<Resource>, PassboltError> {
        let mut params: Vec<(&str, String)> = vec![
            ("contain[permission]", "1".into()),
            ("contain[secret]", "1".into()),
        ];
        for id in ids {
            params.push(("filter[has-id][]", id.clone()));
        }
        let pagination = PaginationParams::default();
        self.get_paginated("/resources.json", &params, &pagination)
            .await
    }

    // ── Search AROs ──────────────────────────────────────────────────────────

    /// Search for users and groups (AROs) matching a search term.
    pub async fn search_aros(&self, search: &str) -> Result<Vec<Aro>, PassboltError> {
        self.get_with_query("/share/search-aros.json", &[("filter[search]", search)])
            .await
    }

    // ── Tags ─────────────────────────────────────────────────────────────────

    /// List all tags.
    pub async fn get_tags(&self) -> Result<Vec<Tag>, PassboltError> {
        self.get("/tags.json").await
    }

    /// Add a tag to a resource, keeping its other tags. Creates the tag if it doesn't exist.
    pub async fn add_tag_to_resource(
        &self,
        resource_id: &str,
        slug: &str,
    ) -> Result<Vec<Tag>, PassboltError> {
        let resource_id = uuid_segment(resource_id)?;
        let resource: Resource = self
            .get(&format!("/resources/{resource_id}.json?contain[tag]=1"))
            .await?;
        let mut slugs: Vec<String> = resource.tags.into_iter().map(|tag| tag.slug).collect();
        if !slugs.iter().any(|existing| existing == slug) {
            slugs.push(slug.to_string());
        }
        self.update_resource_tags(resource_id, &slugs).await
    }

    /// Replace all tags on a resource: `POST /tags/{resource_id}.json`, as the browser extension.
    pub async fn update_resource_tags(
        &self,
        resource_id: &str,
        slugs: &[String],
    ) -> Result<Vec<Tag>, PassboltError> {
        let resource_id = uuid_segment(resource_id)?;
        let body = serde_json::json!({ "tags": slugs });
        self.post(&format!("/tags/{resource_id}.json"), &body).await
    }

    /// Update a tag's slug.
    pub async fn update_tag(&self, id: &str, slug: &str) -> Result<Tag, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::json!({ "slug": slug });
        self.put_request(&format!("/tags/{id}.json"), &body).await
    }

    /// Delete a tag.
    pub async fn delete_tag(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/tags/{id}.json")).await
    }

    // ── Comments ─────────────────────────────────────────────────────────────

    /// List comments for a resource.
    pub async fn get_comments(&self, resource_id: &str) -> Result<Vec<Comment>, PassboltError> {
        let resource_id = uuid_segment(resource_id)?;
        self.get(&format!(
            "/comments/resource/{resource_id}.json?contain[creator]=1"
        ))
        .await
    }

    /// Create a comment on a resource.
    pub async fn create_comment(
        &self,
        resource_id: &str,
        content: &str,
        parent_id: Option<&str>,
    ) -> Result<Comment, PassboltError> {
        let resource_id = uuid_segment(resource_id)?;
        let mut body = serde_json::json!({ "content": content });
        if let Some(parent_id) = parent_id {
            body["parent_id"] = serde_json::json!(parent_id);
        }
        self.post(&format!("/comments/resource/{resource_id}.json"), &body)
            .await
    }

    /// Delete a comment.
    pub async fn delete_comment(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/comments/{id}.json")).await
    }

    // ── Password Expiry Settings ─────────────────────────────────────────────

    /// Get the password expiry settings.
    pub async fn get_password_expiry_settings(
        &self,
    ) -> Result<PasswordExpirySettings, PassboltError> {
        self.get("/password-expiry/settings.json").await
    }

    /// Create or update password expiry settings.
    pub async fn save_password_expiry_settings(
        &self,
        settings: &PasswordExpirySettings,
    ) -> Result<PasswordExpirySettings, PassboltError> {
        let body = serde_json::to_value(settings)?;
        self.post("/password-expiry/settings.json", &body).await
    }

    /// Delete password expiry settings.
    pub async fn delete_password_expiry_settings(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/password-expiry/settings/{id}.json"))
            .await
    }

    // ── HIBP Password Breach Check ───────────────────────────────────────────

    /// Check if a password has been exposed in data breaches (HIBP k-anonymity).
    ///
    /// Returns the number of times the password was found (0 = not breached).
    pub async fn check_password_pwned(&self, password: &str) -> Result<u64, PassboltError> {
        crate::pwned::check_pwned(&self.http, password).await
    }

    // ── Delete Dry-Run ───────────────────────────────────────────────────────

    /// Preview the impact of deleting a user (admin).
    ///
    /// Returns counts of resources/folders where the user is sole owner,
    /// and groups where they are sole manager.
    pub async fn delete_user_dry_run(&self, id: &str) -> Result<UserDeleteDryRun, PassboltError> {
        let id = uuid_segment(id)?;
        let blockers = self
            .delete_dry_run(&format!("/users/{id}/dry-run.json"))
            .await?;
        Ok(UserDeleteDryRun {
            resources_sole_owner_count: count(&blockers, "/errors/resources/sole_owner"),
            folders_sole_owner_count: count(&blockers, "/errors/folders/sole_owner"),
            groups_sole_manager_count: count(&blockers, "/errors/groups/sole_manager"),
        })
    }

    /// Preview the impact of deleting a group.
    ///
    /// Returns counts of resources/folders where the group is sole accessor.
    pub async fn delete_group_dry_run(&self, id: &str) -> Result<GroupDeleteDryRun, PassboltError> {
        let id = uuid_segment(id)?;
        let blockers = self
            .delete_dry_run(&format!("/groups/{id}/dry-run.json"))
            .await?;
        Ok(GroupDeleteDryRun {
            resources_sole_group_count: count(&blockers, "/errors/resources/sole_owner"),
            folders_sole_group_count: count(&blockers, "/errors/folders/sole_owner"),
        })
    }

    /// What blocks deleting the user: what they alone own or manage.
    pub async fn user_delete_blockers(&self, id: &str) -> Result<DeleteBlockers, PassboltError> {
        let id = uuid_segment(id)?;
        let body = self
            .delete_dry_run(&format!("/users/{id}/dry-run.json"))
            .await?;
        DeleteBlockers::from_body(&body)
    }

    /// What blocks deleting the group: what it alone owns.
    pub async fn group_delete_blockers(&self, id: &str) -> Result<DeleteBlockers, PassboltError> {
        let id = uuid_segment(id)?;
        let body = self
            .delete_dry_run(&format!("/groups/{id}/dry-run.json"))
            .await?;
        DeleteBlockers::from_body(&body)
    }

    /// Delete the user, giving what they alone owned or managed to the `transfer` successors.
    pub async fn delete_user_with_transfer(
        &self,
        id: &str,
        transfer: &Transfer,
    ) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_with_body(&format!("/users/{id}.json"), transfer)
            .await
    }

    /// Delete the group, giving what it alone owned to the `transfer` successors.
    pub async fn delete_group_with_transfer(
        &self,
        id: &str,
        transfer: &Transfer,
    ) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_with_body(&format!("/groups/{id}.json"), transfer)
            .await
    }

    async fn delete_with_body(&self, path: &str, transfer: &Transfer) -> Result<(), PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let body = serde_json::to_vec(&serde_json::json!({ "transfer": transfer }))?;
        let response = self.send(Method::Delete, &url, Some(&body)).await?;
        if response.status >= 400 {
            return Err(ApiError {
                status: response.status,
                message: format!("DELETE {path} failed: {}", server_message(&response)),
                validation_errors: None,
            }
            .into());
        }
        Ok(())
    }

    /// `DELETE …/dry-run.json`: what blocks the deletion, the 400 `body` (`errors`,
    /// `groups_to_delete`); `null` if nothing.
    async fn delete_dry_run(&self, path: &str) -> Result<Value, PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let response = self.send(Method::Delete, &url, None).await?;
        let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        match response.status {
            status if status < 400 => Ok(Value::Null),
            400 if body.pointer("/body/errors").is_some() => {
                Ok(body.pointer("/body").cloned().unwrap_or(Value::Null))
            }
            status => Err(ApiError {
                status,
                message: server_message(&response),
                validation_errors: None,
            }
            .into()),
        }
    }

    // ── Metadata Settings ────────────────────────────────────────────────────

    /// The metadata types and keys settings, cached for the session.
    ///
    /// Without the Metadata plugin (404), the server defaults apply: v4 only.
    pub async fn metadata_settings(&self) -> Result<Arc<MetadataSettings>, PassboltError> {
        if let Some(settings) = self.metadata_settings.get() {
            return Ok(Arc::clone(settings));
        }
        let settings = match self.get_metadata_types_settings().await {
            Ok(types) => MetadataSettings {
                types,
                keys: self.get_metadata_keys_settings().await?,
            },
            Err(PassboltError::Api(ApiError { status: 404, .. })) => MetadataSettings::default(),
            Err(error) => return Err(error),
        };
        Ok(Arc::clone(
            self.metadata_settings.get_or_init(|| Arc::new(settings)),
        ))
    }

    /// Get metadata types settings (which versions are allowed).
    pub async fn get_metadata_types_settings(
        &self,
    ) -> Result<MetadataTypesSettings, PassboltError> {
        self.get("/metadata/types/settings.json").await
    }

    /// Save metadata types settings (admin).
    pub async fn save_metadata_types_settings(
        &self,
        settings: &MetadataTypesSettings,
    ) -> Result<MetadataTypesSettings, PassboltError> {
        let body = serde_json::to_value(settings)?;
        self.post("/metadata/types/settings.json", &body).await
    }

    /// Get metadata keys settings.
    pub async fn get_metadata_keys_settings(&self) -> Result<MetadataKeysSettings, PassboltError> {
        self.get("/metadata/keys/settings.json").await
    }

    /// Save metadata keys settings (admin).
    pub async fn save_metadata_keys_settings(
        &self,
        settings: &MetadataKeysSettings,
    ) -> Result<MetadataKeysSettings, PassboltError> {
        let body = serde_json::to_value(settings)?;
        self.post("/metadata/keys/settings.json", &body).await
    }

    /// Share metadata private key(s) with users.
    ///
    /// Each entry contains the metadata key ID, user ID, and the private key
    /// encrypted for that user's public key.
    pub async fn share_metadata_private_keys(
        &self,
        entries: &[MetadataPrivateKeyPayload],
    ) -> Result<(), PassboltError> {
        let body = serde_json::to_value(entries)?;
        let _: Value = self.post("/metadata/keys/private.json", &body).await?;
        Ok(())
    }
}

// ── Query option structs ──────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ResourceQuery {
    pub favorites_only: bool,
    pub owned_by_me: bool,
    pub group_ids: Vec<String>,
    pub folder_ids: Vec<String>,
    pub search: Option<String>,
    pub pagination: PaginationParams,
}

#[derive(Debug, Default)]
pub struct FolderQuery {
    pub search: Option<String>,
    /// Folders the group has a permission on.
    pub group_id: Option<String>,
    /// Folders directly in any of these folders.
    pub parent_folder_ids: Vec<String>,
    pub pagination: PaginationParams,
}

#[derive(Debug, Default)]
pub struct UserQuery {
    pub search: Option<String>,
    pub group_id: Option<String>,
    pub resource_id: Option<String>,
    pub admin_only: bool,
    pub pagination: PaginationParams,
}

#[derive(Debug, Default)]
pub struct GroupQuery {
    pub user_id: Option<String>,
    pub manager_id: Option<String>,
    pub pagination: PaginationParams,
}
