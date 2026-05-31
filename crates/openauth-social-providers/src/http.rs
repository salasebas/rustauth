//! Shared SSRF-guarded HTTP client for social provider userinfo/profile calls.
//!
//! Provider profile fetches must apply the same outbound safeguards as the
//! token/JWKS/introspection calls in [`openauth_oauth`]: a connection timeout,
//! a stable user agent, and SSRF protection that blocks private or otherwise
//! non-public addresses. This module centralizes that policy so providers route
//! their userinfo requests through [`ProviderHttpClient`] (or the shared
//! [`shared_client`]) instead of a raw [`reqwest::Client`].

use std::sync::OnceLock;

use openauth_oauth::oauth2::{url_host_is_blocked_ip, OAuthError, OAuthHttpClient};
use reqwest::{Client, RequestBuilder};

/// Returns a clone of the shared SSRF-guarded [`reqwest::Client`] (connection
/// timeout, stable user agent, and private-IP DNS blocking) used for provider
/// profile fetches. Cloning is cheap because `reqwest::Client` shares its
/// connection pool internally.
///
/// The guarded client is built once via [`OAuthHttpClient::default_client`].
/// Building only fails on an unrecoverable TLS backend initialization error —
/// the same condition under which the fallback `Client::new()` itself panics —
/// so this never silently yields an unguarded client in practice.
pub fn shared_client() -> Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            OAuthHttpClient::default_client()
                .map(|client| client.reqwest_client().clone())
                .unwrap_or_else(|_| Client::new())
        })
        .clone()
}

/// HTTP client for social provider userinfo/profile requests.
///
/// The production default ([`ProviderHttpClient::shared`]) routes requests
/// through the SSRF-guarded shared client and rejects URLs whose host is a
/// literal private/internal IP before connecting — the gap `reqwest`'s DNS
/// guard cannot see. Tests opt into [`ProviderHttpClient::permissive`] to reach
/// loopback fixtures.
#[derive(Debug, Clone)]
pub struct ProviderHttpClient {
    client: Client,
    allow_private_ips: bool,
}

impl Default for ProviderHttpClient {
    fn default() -> Self {
        Self::shared()
    }
}

impl ProviderHttpClient {
    /// SSRF-guarded client used in production: blocks private/internal hosts.
    pub fn shared() -> Self {
        Self {
            client: shared_client(),
            allow_private_ips: false,
        }
    }

    /// Permissive client that allows private and loopback addresses. Intended
    /// for tests that exercise userinfo handling against local HTTP fixtures.
    pub fn permissive() -> Self {
        Self {
            client: Client::new(),
            allow_private_ips: true,
        }
    }

    /// Wraps an explicit [`reqwest::Client`]. Set `allow_private_ips` to `true`
    /// only for deployments that intentionally reach internal addresses.
    pub fn new(client: Client, allow_private_ips: bool) -> Self {
        Self {
            client,
            allow_private_ips,
        }
    }

    /// Builds a GET request for `url`, rejecting literal private/internal IP
    /// hosts unless this client opts into private IPs.
    pub fn get(&self, url: &str) -> Result<RequestBuilder, OAuthError> {
        if !self.allow_private_ips && url_host_is_blocked_ip(url) {
            return Err(OAuthError::InvalidConfiguration(
                "refusing to fetch user info from a private or internal IP address".to_owned(),
            ));
        }
        Ok(self.client.get(url))
    }
}
