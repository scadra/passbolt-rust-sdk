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

use std::cell::RefCell;
use std::sync::Mutex;

use js_sys::{Array, Uint8Array};
use passbolt_sdk::error::TransportError;
use passbolt_sdk::http::{HttpClient, HttpResponse};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCredentials, RequestInit, RequestMode, Response};

#[wasm_bindgen]
extern "C" {
    /// The global `fetch`, available in windows and in workers (MV3 service worker)
    /// alike, unlike `web_sys::window()`.
    #[wasm_bindgen(js_name = fetch)]
    fn global_fetch(request: &Request) -> js_sys::Promise;
}

const DEFAULT_HEADERS: [(&str, &str); 2] = [
    ("Content-Type", "application/json"),
    ("Accept", "application/json"),
];

/// JSON defaults followed by the caller's headers; a caller header replaces a
/// default of the same name (case-insensitive), as `Headers.set` does.
fn build_request_headers<'header>(
    headers: &[(&'header str, &'header str)],
) -> Vec<(&'header str, &'header str)> {
    let mut merged: Vec<(&str, &str)> = Vec::with_capacity(DEFAULT_HEADERS.len() + headers.len());
    for &(name, value) in DEFAULT_HEADERS.iter().chain(headers) {
        if let Some(existing) = merged
            .iter_mut()
            .find(|(existing_name, _)| existing_name.eq_ignore_ascii_case(name))
        {
            *existing = (name, value);
        } else {
            merged.push((name, value));
        }
    }
    merged
}

const CSRF_COOKIE: &str = "csrfToken";

thread_local! {
    /// JS function giving the `csrfToken` cookie, sync or as a promise: `fetch` cannot read
    /// `Set-Cookie`. WASM runs on one thread, and a JS function is not `Send`.
    static CSRF_TOKEN_PROVIDER: RefCell<Option<js_sys::Function>> = const { RefCell::new(None) };
}

/// Read the CSRF token with `provider` (e.g. `browser.cookies.get` in an extension), instead of
/// `document.cookie`, which only pages served by Passbolt can read.
pub fn set_csrf_token_provider(provider: Option<js_sys::Function>) {
    CSRF_TOKEN_PROVIDER.with(|stored| *stored.borrow_mut() = provider);
}

/// HTTP client using `fetch()` with cookie credentials.
///
/// The CSRF cookie is read again after each response, as the browser extension does.
/// Browsers keep the cookies and hide `Set-Cookie`; Node, Deno and Bun show it and keep
/// nothing, so the client keeps those cookies itself: one client talks to one server.
pub struct WasmHttpClient {
    csrf_token: Mutex<Option<String>>,
    cookies: Mutex<Vec<(String, String)>>,
}

impl WasmHttpClient {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            csrf_token: Mutex::new(None),
            cookies: Mutex::new(Vec::new()),
        }
    }

    async fn refresh_csrf_token(&self) {
        let provider = CSRF_TOKEN_PROVIDER.with(|stored| stored.borrow().clone());
        let token = match provider {
            Some(provider) => provided_token(&provider).await,
            None => document_cookie().and_then(|cookies| cookie_value(&cookies, CSRF_COOKIE)),
        };
        if let (Some(token), Ok(mut stored)) = (token, self.csrf_token.lock()) {
            *stored = Some(token);
        }
    }

    fn kept_cookie(&self, name: &str) -> Option<String> {
        let cookies = self.cookies.lock().ok()?;
        cookies
            .iter()
            .find(|(kept_name, _)| kept_name == name)
            .map(|(_, value)| value.clone())
    }

    fn keep_cookies(&self, response_headers: &Headers) {
        let Ok(mut cookies) = self.cookies.lock() else {
            return;
        };
        for set_cookie in set_cookie_headers(response_headers) {
            keep_cookie(&mut cookies, &set_cookie);
        }
    }

    async fn fetch(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, TransportError> {
        let request_init = RequestInit::new();
        request_init.set_method(method);
        request_init.set_credentials(RequestCredentials::Include);
        request_init.set_mode(RequestMode::Cors);

        let request_headers = Headers::new().map_err(|error| js_err("Headers::new", &error))?;
        for (name, value) in build_request_headers(headers) {
            request_headers
                .set(name, value)
                .map_err(|error| js_err(&format!("set header {name}"), &error))?;
        }
        request_init.set_headers(&request_headers);

        // Set body if present
        if let Some(bytes) = body {
            let body_array = Uint8Array::from(bytes);
            request_init.set_body(&body_array);
        }

        let request = Request::new_with_str_and_init(url, &request_init)
            .map_err(|error| js_err("Request::new", &error))?;

        let response_value = JsFuture::from(global_fetch(&request))
            .await
            .map_err(|error| js_err(&format!("{method} {url}"), &error))?;

        let response: Response = response_value
            .dyn_into()
            .map_err(|_| TransportError::Http("Response is not a Response object".into()))?;

        let status = response.status();

        // Extract response headers
        let response_headers = response.headers();
        self.keep_cookies(&response_headers);
        let mut header_vec: Vec<(String, String)> = Vec::new();

        // Iterate through headers using js_sys
        let entries = js_sys::try_iter(&response_headers).ok().flatten();
        if let Some(entry_iterator) = entries {
            for entry in entry_iterator.flatten() {
                let pair: Array = entry.into();
                let key = pair.get(0).as_string().unwrap_or_default();
                let value = pair.get(1).as_string().unwrap_or_default();
                header_vec.push((key, value));
            }
        }

        // Read body as bytes
        let body_promise = response
            .array_buffer()
            .map_err(|error| js_err("arrayBuffer()", &error))?;
        let body_value = JsFuture::from(body_promise)
            .await
            .map_err(|error| js_err("read body", &error))?;
        let body_bytes = Uint8Array::new(&body_value).to_vec();
        self.refresh_csrf_token().await;

        Ok(HttpResponse {
            status,
            headers: header_vec,
            body: body_bytes,
        })
    }
}

/// The token the provider returns, directly or through a promise.
async fn provided_token(provider: &js_sys::Function) -> Option<String> {
    let returned = provider.call0(&JsValue::NULL).ok()?;
    let value = match returned.dyn_into::<js_sys::Promise>() {
        Ok(promise) => JsFuture::from(promise).await.ok()?,
        Err(value) => value,
    };
    value.as_string().filter(|token| !token.is_empty())
}

/// `document.cookie`, absent in a worker.
fn document_cookie() -> Option<String> {
    let document = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("document")).ok()?;
    js_sys::Reflect::get(&document, &JsValue::from_str("cookie"))
        .ok()?
        .as_string()
}

/// The `Set-Cookie` headers, one per cookie: `getSetCookie()` gives none in a browser.
fn set_cookie_headers(headers: &Headers) -> Vec<String> {
    let Ok(get_set_cookie) = js_sys::Reflect::get(headers, &JsValue::from_str("getSetCookie"))
    else {
        return Vec::new();
    };
    let Ok(get_set_cookie) = get_set_cookie.dyn_into::<js_sys::Function>() else {
        return Vec::new();
    };
    get_set_cookie
        .call0(headers)
        .ok()
        .and_then(|values| values.dyn_into::<Array>().ok())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Keep the cookie of a `Set-Cookie` header, replacing the one of the same name; an empty
/// value or `Max-Age=0`, as the server logs out, removes it.
fn keep_cookie(cookies: &mut Vec<(String, String)>, set_cookie: &str) {
    let mut attributes = set_cookie.split(';').map(str::trim);
    let Some((name, value)) = attributes.next().and_then(|pair| pair.split_once('=')) else {
        return;
    };
    let expired = attributes.any(|attribute| attribute.eq_ignore_ascii_case("max-age=0"));
    cookies.retain(|(kept_name, _)| kept_name != name);
    if !value.is_empty() && !expired {
        cookies.push((name.to_string(), value.to_string()));
    }
}

/// The value of cookie `name` in a `document.cookie` string.
fn cookie_value(cookies: &str, name: &str) -> Option<String> {
    cookies.split("; ").find_map(|cookie| {
        let (cookie_name, value) = cookie.split_once('=')?;
        (cookie_name == name && !value.is_empty()).then(|| value.to_string())
    })
}

impl HttpClient for WasmHttpClient {
    fn cookie(&self, _url: &str, name: &str) -> Option<String> {
        if name != CSRF_COOKIE {
            return self.kept_cookie(name);
        }
        self.csrf_token.lock().ok()?.clone()
    }

    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        self.fetch("GET", url, headers, None).await
    }

    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        self.fetch("POST", url, headers, Some(body)).await
    }

    async fn put(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        self.fetch("PUT", url, headers, Some(body)).await
    }

    async fn delete(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        self.fetch("DELETE", url, headers, None).await
    }

    async fn delete_with_body(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        self.fetch("DELETE", url, headers, Some(body)).await
    }
}

fn js_err(context: &str, err: &JsValue) -> TransportError {
    let message = err
        .as_string()
        .or_else(|| js_sys::JSON::stringify(err).ok().map(String::from))
        .unwrap_or_else(|| format!("{err:?}"));
    TransportError::Network(format!("{context}: {message}"))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::only_cookie("csrfToken=abc", Some("abc"))]
    #[case::among_others("passbolt_session=s; csrfToken=abc; theme=dark", Some("abc"))]
    #[case::prefix_is_not_the_name("csrfTokenOld=old; csrfToken=new", Some("new"))]
    #[case::absent("passbolt_session=s", None)]
    #[case::empty_value("csrfToken=", None)]
    fn test_cookie_value(#[case] cookies: &str, #[case] expected: Option<&str>) {
        assert_eq!(cookie_value(cookies, CSRF_COOKIE).as_deref(), expected);
    }

    fn kept(set_cookies: &[&str]) -> Vec<(String, String)> {
        let mut cookies = Vec::new();
        for set_cookie in set_cookies {
            keep_cookie(&mut cookies, set_cookie);
        }
        cookies
    }

    #[rstest]
    #[case::name_and_value(&["passbolt_session=s1; path=/; HttpOnly"], &[("passbolt_session", "s1")])]
    #[case::several(&["passbolt_session=s1", "csrfToken=t1"], &[("passbolt_session", "s1"), ("csrfToken", "t1")])]
    #[case::replaced_by_name(&["csrfToken=t1", "csrfToken=t2"], &[("csrfToken", "t2")])]
    #[case::emptied(&["passbolt_session=s1", "passbolt_session=; path=/"], &[])]
    #[case::expired(&["passbolt_session=s1", "passbolt_session=s1; Max-Age=0"], &[])]
    #[case::value_with_equals(&["token=a=b"], &[("token", "a=b")])]
    #[case::without_value(&["broken"], &[])]
    fn test_keep_cookie(#[case] set_cookies: &[&str], #[case] expected: &[(&str, &str)]) {
        let expected: Vec<(String, String)> = expected
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();

        assert_eq!(kept(set_cookies), expected);
    }

    #[test]
    fn test_a_new_client_has_no_csrf_token() {
        assert_eq!(
            WasmHttpClient::new().cookie("https://passbolt.test", CSRF_COOKIE),
            None
        );
    }

    #[test]
    fn test_build_request_headers_without_caller_headers_is_json_defaults() {
        let headers = build_request_headers(&[]);

        assert_eq!(headers, DEFAULT_HEADERS.to_vec());
    }

    #[test]
    fn test_build_request_headers_appends_caller_headers() {
        let headers = build_request_headers(&[("X-CSRF-Token", "token")]);

        assert_eq!(
            headers,
            vec![
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
                ("X-CSRF-Token", "token"),
            ]
        );
    }

    #[rstest]
    #[case::same_case("Content-Type")]
    #[case::other_case("content-type")]
    fn test_build_request_headers_caller_replaces_default(#[case] name: &str) {
        let headers = build_request_headers(&[(name, "text/plain")]);

        assert_eq!(
            headers,
            vec![(name, "text/plain"), ("Accept", "application/json")]
        );
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    const JSON_DATA_URL: &str = "data:application/json,%7B%7D";

    /// The CSRF token the client holds after a response, read with `provider`.
    async fn token_after_a_response(provider: Option<js_sys::Function>) -> Option<String> {
        set_csrf_token_provider(provider);
        let client = WasmHttpClient::new();
        client.get(JSON_DATA_URL, &[]).await.unwrap();
        set_csrf_token_provider(None);
        client.cookie(JSON_DATA_URL, CSRF_COOKIE)
    }

    #[wasm_bindgen_test]
    async fn test_the_csrf_token_comes_from_the_provider() {
        let provider = js_sys::Function::new_no_args("return 'from-provider';");

        assert_eq!(
            token_after_a_response(Some(provider)).await.as_deref(),
            Some("from-provider")
        );
    }

    #[wasm_bindgen_test]
    async fn test_the_provider_may_return_a_promise() {
        let provider = js_sys::Function::new_no_args("return Promise.resolve('from-promise');");

        assert_eq!(
            token_after_a_response(Some(provider)).await.as_deref(),
            Some("from-promise")
        );
    }

    #[wasm_bindgen_test]
    async fn test_without_provider_nor_document_there_is_no_token() {
        assert_eq!(token_after_a_response(None).await, None);
    }

    #[wasm_bindgen_test]
    async fn test_a_provider_without_token_keeps_none() {
        let provider = js_sys::Function::new_no_args("return null;");

        assert_eq!(token_after_a_response(Some(provider)).await, None);
    }

    #[wasm_bindgen_test]
    async fn test_get_fetches_without_a_window() {
        let client = WasmHttpClient::new();

        let response = client
            .get("data:application/json,%7B%22ok%22%3Atrue%7D", &[])
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, br#"{"ok":true}"#);
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "application/json"));
    }
}
