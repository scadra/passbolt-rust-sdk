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

use percent_encoding::percent_decode_str;
use serde_json::Value;
use zeroize::Zeroize;

use crate::crypto::{
    decrypt_message, encrypt_message, parse_public_key, public_key_fingerprint, PrivateKey,
};
use crate::error::{AuthError, PassboltError};
use crate::http::HttpClient;

/// Result of a successful login — CSRF token and user ID.
pub struct AuthTokens {
    pub csrf_token: String,
    pub user_id: String,
}

impl Drop for AuthTokens {
    fn drop(&mut self) {
        self.csrf_token.zeroize();
        self.user_id.zeroize();
    }
}

/// MFA configuration (CLI-oriented).
///
/// SDK consumers that don't use the config file can pass `MfaProvider` directly.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct MfaConfig {
    pub mode: String,
    pub totp_token: secrecy::SecretString,
    pub totp_offset: i64,
    pub retrys: u32,
}

/// Perform the full Passbolt GPG challenge-response login (cookie-based).
pub async fn login<H: HttpClient>(
    http: &H,
    base_url: &str,
    private_key: &PrivateKey,
    passphrase: &str,
) -> Result<AuthTokens, PassboltError> {
    let url = format!("{base_url}/auth/login.json");

    // Step 1: send fingerprint, receive encrypted challenge in header
    let init_body = serde_json::json!({
        "gpg_auth": { "keyid": private_key.fingerprint }
    });
    let json_bytes = serde_json::to_vec(&init_body)?;

    let response = http.post(&url, &[], &json_bytes).await?;

    let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);

    if response.status >= 400 {
        let message = body
            .pointer("/header/message")
            .and_then(|value| value.as_str())
            .unwrap_or("Unknown error");
        return Err(AuthError::LoginFailed(format!(
            "Login initiation failed ({}): {message}",
            response.status
        ))
        .into());
    }

    // Extract challenge from response header
    let challenge_encoded = response
        .header("X-GPGAuth-User-Auth-Token")
        .ok_or_else(|| {
            AuthError::LoginFailed("Server did not return X-GPGAuth-User-Auth-Token header".into())
        })?
        .to_string();

    let encrypted_challenge = decode_auth_token_header(&challenge_encoded)?;

    // Step 2: decrypt the challenge
    let decrypted =
        decrypt_message(&encrypted_challenge, &private_key.key, passphrase).map_err(|error| {
            AuthError::LoginFailed(format!("Failed to decrypt server challenge: {error}"))
        })?;
    let token = String::from_utf8(decrypted)
        .map_err(|error| {
            AuthError::LoginFailed(format!("Decrypted challenge is not valid UTF-8: {error}"))
        })?
        .trim()
        .to_owned();
    check_auth_token_format(&token)?;

    // Step 3: send decrypted token to complete auth
    let verify_body = serde_json::json!({
        "gpg_auth": {
            "keyid": private_key.fingerprint,
            "user_token_result": token
        }
    });
    let verify_bytes = serde_json::to_vec(&verify_body)?;

    let verify_response = http.post(&url, &[], &verify_bytes).await?;

    if verify_response.status >= 400 {
        let error_body: Value =
            serde_json::from_slice(&verify_response.body).unwrap_or(Value::Null);
        let message = error_body
            .pointer("/header/message")
            .and_then(|value| value.as_str())
            .unwrap_or("Unknown error");
        return Err(AuthError::LoginFailed(format!(
            "Login verification failed ({}): {message}",
            verify_response.status
        ))
        .into());
    }

    extract_auth_tokens(&verify_response)
}

/// Refuse to send back anything but a `GPGAuth` nonce, as the server checks it
/// (`GpgAuthenticator::_checkNonce`): the key must not decrypt arbitrary messages for the server.
fn check_auth_token_format(token: &str) -> Result<(), AuthError> {
    let is_valid = matches!(
        token.split('|').collect::<Vec<_>>().as_slice(),
        ["gpgauthv1.3.0", "36", nonce, "gpgauthv1.3.0"]
            if nonce.len() == 36 && uuid::Uuid::try_parse(nonce).is_ok()
    );
    if is_valid {
        Ok(())
    } else {
        Err(AuthError::LoginFailed(
            "the server challenge is not a GPGAuth token".into(),
        ))
    }
}

/// Inverse of PHP `quotemeta(urlencode($armored))`, how the server sends the challenge.
fn decode_auth_token_header(encoded: &str) -> Result<String, AuthError> {
    let unquoted = encoded.replace('\\', "").replace('+', " ");
    percent_decode_str(&unquoted)
        .decode_utf8()
        .map(Into::into)
        .map_err(|error| {
            AuthError::LoginFailed(format!("Invalid X-GPGAuth-User-Auth-Token header: {error}"))
        })
}

/// The `csrfToken` cookie, which the server only sets on a GET without it.
pub(crate) fn csrf_cookie(response: &crate::http::HttpResponse) -> Option<String> {
    response
        .headers_by_name("set-cookie-name")
        .iter()
        .find_map(|cookie| cookie.strip_prefix("csrfToken="))
        .map(str::to_owned)
}

/// Extract CSRF token and `user_id` from a successful login/MFA response.
fn extract_auth_tokens(response: &crate::http::HttpResponse) -> Result<AuthTokens, PassboltError> {
    let csrf_from_header = response.header("X-CSRF-Token").map(str::to_owned);

    let csrf_from_cookie = csrf_cookie(response);

    let body: Value = serde_json::from_slice(&response.body)?;

    let csrf_from_body = body
        .pointer("/body/csrfToken")
        .and_then(|value| value.as_str())
        .map(str::to_owned);

    let csrf_token = csrf_from_header
        .or(csrf_from_cookie)
        .or(csrf_from_body)
        .unwrap_or_default();

    let user_id = body
        .pointer("/body/user/id")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_owned();

    Ok(AuthTokens {
        csrf_token,
        user_id,
    })
}

const VERIFY_TOKEN_VERSION: &str = "gpgauthv1.3.0";

/// The server public key and its fingerprint, as `GET /auth/verify.json` serves them.
///
/// Anyone can serve a copy: pin it once, then prove the server holds the private key
/// with [`verify_server`] at every login.
pub async fn fetch_server_key<H: HttpClient>(
    http: &H,
    base_url: &str,
) -> Result<(String, String), PassboltError> {
    let response = http
        .get(&format!("{base_url}/auth/verify.json"), &[])
        .await?;
    let body: Value = serde_json::from_slice(&response.body)?;
    let field = |name: &str| {
        body.pointer(&format!("/body/{name}"))
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| AuthError::LoginFailed(format!("the server sent no {name}")))
    };
    let (claimed_fingerprint, armored_key) = (field("fingerprint")?, field("keydata")?);
    let fingerprint = public_key_fingerprint(&armored_key).map_err(|error| {
        AuthError::LoginFailed(format!("the server key is unreadable: {error}"))
    })?;
    if !claimed_fingerprint.eq_ignore_ascii_case(&fingerprint) {
        return Err(AuthError::ServerIdentityMismatch(format!(
            "the server announces the fingerprint {claimed_fingerprint} for a key of fingerprint \
             {fingerprint}"
        ))
        .into());
    }
    Ok((fingerprint, armored_key))
}

/// A fresh `GPGAuth` nonce, in the format the server agrees to decrypt.
#[must_use]
pub fn new_verify_token() -> String {
    format!(
        "{VERIFY_TOKEN_VERSION}|36|{}|{VERIFY_TOKEN_VERSION}",
        uuid::Uuid::new_v4()
    )
}

/// Ask the server to decrypt `encrypted_token` (`GPGAuth` stage 0): only the holder of the
/// server private key can answer `expected_token` in `X-GPGAuth-Verify-Response`.
///
/// `user_fingerprint` must be a key the server knows: it identifies the user first.
pub async fn verify_server<H: HttpClient>(
    http: &H,
    base_url: &str,
    user_fingerprint: &str,
    encrypted_token: &str,
    expected_token: &str,
) -> Result<(), PassboltError> {
    let body = serde_json::json!({
        "gpg_auth": { "keyid": user_fingerprint, "server_verify_token": encrypted_token }
    });
    let response = http
        .post(
            &format!("{base_url}/auth/verify.json"),
            &[],
            &serde_json::to_vec(&body)?,
        )
        .await?;
    // The server answers "authentication failed": stage 0 does not log in.
    if response.header("X-GPGAuth-Verify-Response") == Some(expected_token) {
        return Ok(());
    }
    Err(AuthError::ServerIdentityMismatch(
        "the server could not prove it holds its private key".into(),
    )
    .into())
}

/// Prove the server holds the key pinned by `passbolt verify`, before sending anything.
///
/// With `server_public_key`, a fresh token is encrypted for it, as the browser extension does.
/// Without it, the stored `encrypted_token` is sent again, as go-passbolt-cli does.
pub async fn check_server_identity<H: HttpClient>(
    http: &H,
    base_url: &str,
    user_fingerprint: &str,
    server_public_key: &str,
    token: &str,
    encrypted_token: &str,
) -> Result<(), PassboltError> {
    if !server_public_key.is_empty() {
        let server_key = parse_public_key(server_public_key)?;
        let token = new_verify_token();
        let encrypted_token = encrypt_message(token.as_bytes(), &[&server_key])?;
        return verify_server(http, base_url, user_fingerprint, &encrypted_token, &token).await;
    }
    if token.is_empty() && encrypted_token.is_empty() {
        return Ok(());
    }
    if token.is_empty() || !encrypted_token.starts_with("-----BEGIN PGP MESSAGE-----") {
        return Err(AuthError::ServerIdentityMismatch(
            "the stored server verification is incomplete: run `passbolt verify` again".into(),
        )
        .into());
    }
    verify_server(http, base_url, user_fingerprint, encrypted_token, token).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::quotemeta_space("BEGIN\\+PGP\\+MESSAGE", "BEGIN PGP MESSAGE")]
    #[case::quotemeta_dot("Version%3A\\+1\\.0", "Version: 1.0")]
    #[case::base64_plus("ab%2Bcd%2F%3D", "ab+cd/=")]
    #[case::literal_backslash("a%5Cb", "a\\b")]
    #[case::newline("line1%0Aline2", "line1\nline2")]
    fn test_decode_auth_token_header(#[case] header: &str, #[case] expected: &str) {
        assert_eq!(decode_auth_token_header(header).unwrap(), expected);
    }

    #[rstest]
    #[case::other_version("gpgauthv1.2.0|36|de305d54-75b4-431b-adb2-eb6b9e546014|gpgauthv1.2.0")]
    #[case::mismatched_versions(
        "gpgauthv1.3.0|36|de305d54-75b4-431b-adb2-eb6b9e546014|gpgauthv1.2.0"
    )]
    #[case::wrong_length("gpgauthv1.3.0|32|de305d54-75b4-431b-adb2-eb6b9e546014|gpgauthv1.3.0")]
    #[case::not_a_uuid("gpgauthv1.3.0|36|de305d54-75b4-431b-adb2-eb6b9e54601z|gpgauthv1.3.0")]
    #[case::simple_uuid("gpgauthv1.3.0|36|de305d5475b4431badb2eb6b9e546014|gpgauthv1.3.0")]
    #[case::extra_field("gpgauthv1.3.0|36|de305d54-75b4-431b-adb2-eb6b9e546014|gpgauthv1.3.0|x")]
    #[case::plaintext("any plaintext")]
    fn test_check_auth_token_format_rejects(#[case] token: &str) {
        assert!(check_auth_token_format(token).is_err());
    }

    #[test]
    fn test_check_auth_token_format_accepts_a_nonce() {
        assert!(check_auth_token_format(
            "gpgauthv1.3.0|36|de305d54-75b4-431b-adb2-eb6b9e546014|gpgauthv1.3.0"
        )
        .is_ok());
    }

    #[test]
    fn test_decode_auth_token_header_invalid_utf8() {
        assert!(decode_auth_token_header("%FF").is_err());
    }
}
