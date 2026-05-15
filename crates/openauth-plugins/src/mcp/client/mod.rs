//! Small framework-neutral helpers for MCP resource servers.

use http::{header, HeaderValue, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct McpAuthClientOptions {
    pub auth_url: String,
    pub resource: Option<String>,
    pub allowed_origin: Option<String>,
    pub discovery_cache_ttl: Duration,
    pub http_client: reqwest::Client,
}

impl Default for McpAuthClientOptions {
    fn default() -> Self {
        Self {
            auth_url: String::new(),
            resource: None,
            allowed_origin: None,
            discovery_cache_ttl: Duration::from_secs(60),
            http_client: reqwest::Client::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct McpAuthClient {
    auth_url: String,
    resource: Option<String>,
    allowed_origin: Option<String>,
    discovery_cache_ttl: Duration,
    http_client: reqwest::Client,
    discovery_cache: Arc<Mutex<Option<CachedMetadata>>>,
}

#[derive(Debug, Clone)]
struct CachedMetadata {
    value: Value,
    cached_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct McpSession {
    pub record: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum McpClientError {
    #[error("http response build failed: {0}")]
    Http(#[from] http::Error),
    #[error("token verification failed: {0}")]
    Verify(#[from] reqwest::Error),
}

#[derive(Debug, Serialize)]
struct JsonRpcUnauthorized<'a> {
    jsonrpc: &'static str,
    error: JsonRpcError<'a>,
    id: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError<'a> {
    code: i64,
    message: &'a str,
    #[serde(rename = "www-authenticate")]
    www_authenticate: &'a str,
}

impl McpAuthClient {
    pub fn new(options: McpAuthClientOptions) -> Self {
        Self {
            auth_url: options.auth_url.trim_end_matches('/').to_owned(),
            resource: options.resource,
            allowed_origin: options.allowed_origin,
            discovery_cache_ttl: options.discovery_cache_ttl,
            http_client: options.http_client,
            discovery_cache: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn verify_token(&self, token: &str) -> Result<Option<McpSession>, reqwest::Error> {
        let response = self
            .http_client
            .get(format!("{}/mcp/get-session", self.auth_url))
            .bearer_auth(token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Ok(None);
        }
        let value = response.json::<Value>().await?;
        if value.is_null() || value.get("userId").is_none() {
            return Ok(None);
        }
        Ok(Some(McpSession { record: value }))
    }

    pub async fn discovery_metadata(&self) -> Result<Value, reqwest::Error> {
        if let Some(cached) = self
            .discovery_cache
            .lock()
            .ok()
            .and_then(|cache| cache.clone())
        {
            if cached.cached_at.elapsed() < self.discovery_cache_ttl {
                return Ok(cached.value);
            }
        }
        let value = self
            .http_client
            .get(format!(
                "{}/.well-known/oauth-authorization-server",
                self.auth_url
            ))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        if let Ok(mut cache) = self.discovery_cache.lock() {
            *cache = Some(CachedMetadata {
                value: value.clone(),
                cached_at: Instant::now(),
            });
        }
        Ok(value)
    }

    pub fn protected_resource_metadata(&self, server_url: &str) -> Value {
        json!({
            "resource": self.resource.clone().unwrap_or_else(|| origin_from_url(server_url)),
            "authorization_servers": [self.auth_url.clone()],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
        })
    }

    pub fn www_authenticate(&self) -> String {
        let base = self.resource.as_deref().unwrap_or(&self.auth_url);
        format!("Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource\"")
    }

    pub fn unauthorized_response(&self) -> Result<Response<Vec<u8>>, http::Error> {
        let authenticate = self.www_authenticate();
        let body = serde_json::to_vec(&JsonRpcUnauthorized {
            jsonrpc: "2.0",
            error: JsonRpcError {
                code: -32000,
                message: "Unauthorized: Authentication required",
                www_authenticate: &authenticate,
            },
            id: None,
        })
        .unwrap_or_default();
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::WWW_AUTHENTICATE, authenticate)
            .header("Access-Control-Expose-Headers", "WWW-Authenticate")
            .body(body)
    }

    pub fn cors_preflight_response(&self) -> Result<Response<Vec<u8>>, http::Error> {
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, self.allowed_origin())
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS")
            .header(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Content-Type, Authorization",
            )
            .header(header::ACCESS_CONTROL_MAX_AGE, "86400")
            .body(Vec::new())
    }

    pub fn bearer_token<B>(&self, request: &Request<B>) -> Option<String> {
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::to_owned)
    }

    pub async fn authorize_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<Option<McpSession>, reqwest::Error> {
        let Some(token) = self.bearer_token(request) else {
            return Ok(None);
        };
        self.verify_token(&token).await
    }

    pub async fn handle_request<F, Fut>(
        &self,
        request: Request<Vec<u8>>,
        handler: F,
    ) -> Result<Response<Vec<u8>>, McpClientError>
    where
        F: FnOnce(Request<Vec<u8>>, McpSession) -> Fut,
        Fut: Future<Output = Result<Response<Vec<u8>>, http::Error>>,
    {
        if request.method() == http::Method::OPTIONS {
            return Ok(self.cors_preflight_response()?);
        }
        let Some(token) = self.bearer_token(&request) else {
            return Ok(self.unauthorized_response()?);
        };
        let Some(session) = self.verify_token(&token).await? else {
            return Ok(self.unauthorized_response()?);
        };
        Ok(handler(request, session).await?)
    }

    fn allowed_origin(&self) -> HeaderValue {
        if let Some(origin) = &self.allowed_origin {
            return HeaderValue::from_str(origin).unwrap_or_else(|_| HeaderValue::from_static("*"));
        }
        url::Url::parse(&self.auth_url)
            .ok()
            .and_then(|url| {
                let scheme = url.scheme();
                let host = url.host_str()?;
                let port = url
                    .port()
                    .map(|port| format!(":{port}"))
                    .unwrap_or_default();
                HeaderValue::from_str(&format!("{scheme}://{host}{port}")).ok()
            })
            .unwrap_or_else(|| HeaderValue::from_static("*"))
    }
}

fn origin_from_url(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|url| {
            let scheme = url.scheme();
            let host = url.host_str()?;
            let port = url
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default();
            Some(format!("{scheme}://{host}{port}"))
        })
        .unwrap_or_else(|| url.trim_end_matches('/').to_owned())
}
