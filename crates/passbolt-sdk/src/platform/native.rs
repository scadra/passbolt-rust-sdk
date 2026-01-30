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

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::cookie::{CookieStore, Jar};

use reqwest::{
    header::{self, HeaderMap, HeaderValue},
    redirect::Policy,
    Client, ClientBuilder,
};

use crate::error::{PassboltError, TransportError};
use crate::http::{HttpClient, HttpResponse};

/// HTTP client configuration for building a `NativeHttpClient`.
pub struct NativeHttpConfig {
    pub tls_skip_verify: bool,
    pub client_cert_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
    pub proxy_url: Option<String>,
    /// Host names pinned to an address, like `curl --resolve`.
    pub resolve: Vec<(String, SocketAddr)>,
    /// Whole-request timeout (connect, send and read); `None` waits forever.
    pub timeout: Option<std::time::Duration>,
}

/// Native HTTP client backed by `reqwest`.
pub struct NativeHttpClient {
    inner: Client,
    cookies: Arc<Jar>,
}

/// Sent with every request, as `passbolt-rust/<version>`: the server shows it, in the account
/// recovery emails for instance.
pub const USER_AGENT: &str = concat!("passbolt-rust/", env!("CARGO_PKG_VERSION"));

impl NativeHttpClient {
    /// Build a new native HTTP client from the given configuration.
    pub fn new(config: &NativeHttpConfig) -> Result<Self, PassboltError> {
        let cookies = Arc::new(Jar::default());
        let mut builder = ClientBuilder::new()
            .user_agent(USER_AGENT)
            .use_rustls_tls()
            .cookie_provider(Arc::clone(&cookies))
            .redirect(same_origin_redirects())
            .danger_accept_invalid_certs(config.tls_skip_verify);

        // mTLS — client certificate
        if let (Some(cert_pem), Some(key_pem)) = (
            config.client_cert_pem.as_ref(),
            config.client_key_pem.as_ref(),
        ) {
            let mut combined = Vec::from(cert_pem.as_slice());
            combined.extend_from_slice(key_pem);
            let identity = reqwest::tls::Identity::from_pem(&combined).map_err(|error| {
                TransportError::Http(format!("Failed to parse client TLS identity: {error}"))
            })?;
            builder = builder.identity(identity);
        }

        // HTTP proxy
        if let Some(url) = config.proxy_url.as_deref() {
            if !url.is_empty() {
                let proxy = reqwest::Proxy::all(url).map_err(|error| {
                    TransportError::Http(format!("Failed to configure HTTP proxy: {error}"))
                })?;
                builder = builder.proxy(proxy);
            }
        }

        if let Some(timeout) = config.timeout {
            builder = builder.timeout(timeout);
        }
        for (host, address) in &config.resolve {
            builder = builder.resolve(host, *address);
        }

        // Default headers
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        let inner = builder.default_headers(headers).build().map_err(|error| {
            TransportError::Http(format!("Failed to build HTTP client: {error}"))
        })?;

        Ok(Self { inner, cookies })
    }
}

/// Follow redirects within the origin of the request only: reqwest would
/// otherwise send the `X-CSRF-Token` header and the body to any other server.
fn same_origin_redirects() -> Policy {
    const MAX_REDIRECTS: usize = 10;
    Policy::custom(|attempt| {
        let is_same_origin = attempt
            .previous()
            .first()
            .is_some_and(|original| original.origin() == attempt.url().origin());
        if !is_same_origin {
            let message = format!("refused redirect to another origin: {}", attempt.url());
            attempt.error(message)
        } else if attempt.previous().len() > MAX_REDIRECTS {
            attempt.error("too many redirects")
        } else {
            attempt.follow()
        }
    })
}

/// Convert a `reqwest::Response` into our `HttpResponse`.
async fn into_http_response(response: reqwest::Response) -> Result<HttpResponse, TransportError> {
    let status = response.status().as_u16();

    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    // Extract Set-Cookie headers for token parsing
    let mut all_headers = headers;

    // Also capture cookies from the cookie jar (if any were set)
    for cookie in response.cookies() {
        all_headers.push((
            "set-cookie-name".to_string(),
            format!("{}={}", cookie.name(), cookie.value()),
        ));
    }

    let body = response
        .bytes()
        .await
        .map_err(|error| TransportError::Network(format!("Failed to read response body: {error}")))?
        .to_vec();

    Ok(HttpResponse {
        status,
        headers: all_headers,
        body,
    })
}

impl HttpClient for NativeHttpClient {
    fn cookie(&self, url: &str, name: &str) -> Option<String> {
        let url = reqwest::Url::parse(url).ok()?;
        let cookies = self.cookies.cookies(&url)?;
        cookies
            .to_str()
            .ok()?
            .split("; ")
            .find_map(|cookie| cookie.strip_prefix(name)?.strip_prefix('='))
            .map(str::to_owned)
    }

    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self.inner.get(url);
        for &(name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .send()
            .await
            .map_err(|error| TransportError::Network(format!("GET {url}: {error}")))?;
        into_http_response(response).await
    }

    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self.inner.post(url);
        for &(name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .body(body.to_vec())
            .send()
            .await
            .map_err(|error| TransportError::Network(format!("POST {url}: {error}")))?;
        into_http_response(response).await
    }

    async fn put(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self.inner.put(url);
        for &(name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .body(body.to_vec())
            .send()
            .await
            .map_err(|error| TransportError::Network(format!("PUT {url}: {error}")))?;
        into_http_response(response).await
    }

    async fn delete(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self.inner.delete(url);
        for &(name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .send()
            .await
            .map_err(|error| TransportError::Network(format!("DELETE {url}: {error}")))?;
        into_http_response(response).await
    }

    async fn delete_with_body(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self.inner.delete(url);
        for &(name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .body(body.to_vec())
            .send()
            .await
            .map_err(|error| TransportError::Network(format!("DELETE {url}: {error}")))?;
        into_http_response(response).await
    }
}
