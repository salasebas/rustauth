#![allow(dead_code)]

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderValue, Method, Request};
use openauth::db::DbValue;
use openauth::{
    ApiResponse, AsyncAuthEndpoint, AuthContext, AuthEndpointOptions, MemoryAdapter, OpenAuthError,
};
use openauth::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, OpenAuth, OpenAuthOptions, ProviderOptions,
    SocialAuthorizationCodeRequest, SocialAuthorizationUrlRequest, SocialIdTokenRequest,
    SocialOAuthProvider, SocialProviderFuture,
};
use serde_json::Value;
use url::Url;

pub const SECRET: &str = "test-secret-123456789012345678901234";
pub const BODY_LIMIT: usize = 10 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseExtensionMarker(pub &'static str);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestExtensionMarker(pub &'static str);

fn with_test_defaults(options: OpenAuthOptions) -> OpenAuthOptions {
    openauth_core::test_utils::with_integration_test_defaults(options)
}

pub fn auth_with_options(options: OpenAuthOptions) -> Result<OpenAuth, openauth::OpenAuthError> {
    OpenAuth::builder()
        .options(with_test_defaults(options))
        .secret(SECRET)
        .build()
}

pub fn auth_with_adapter(
    adapter: MemoryAdapter,
    options: OpenAuthOptions,
) -> Result<OpenAuth, openauth::OpenAuthError> {
    OpenAuth::builder()
        .options(with_test_defaults(options))
        .secret(SECRET)
        .adapter(adapter)
        .build()
}

pub fn auth_with_async_endpoint(
    endpoint: AsyncAuthEndpoint,
) -> Result<OpenAuth, openauth::OpenAuthError> {
    OpenAuth::builder()
        .secret(SECRET)
        .async_endpoint(endpoint)
        .build()
}

pub fn custom_endpoint(path: &'static str) -> AsyncAuthEndpoint {
    openauth::create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new(),
        |_context: &AuthContext, _request| {
            Box::pin(async {
                let mut response = ApiResponse::new(b"CUSTOM".to_vec());
                *response.status_mut() = axum::http::StatusCode::OK;
                Ok(response)
            })
        },
    )
}

pub fn request_extension_endpoint(path: &'static str) -> AsyncAuthEndpoint {
    openauth::create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new(),
        |_context: &AuthContext, request| {
            Box::pin(async move {
                let marker = request
                    .extensions()
                    .get::<RequestExtensionMarker>()
                    .map(|marker| marker.0)
                    .unwrap_or("missing");
                let mut response = ApiResponse::new(format!("request={marker}").into_bytes());
                *response.status_mut() = axum::http::StatusCode::OK;
                Ok(response)
            })
        },
    )
}

pub fn response_contract_endpoint(path: &'static str) -> AsyncAuthEndpoint {
    openauth::create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new(),
        |_context: &AuthContext, request| {
            Box::pin(async move {
                let query = request.uri().query().unwrap_or("");
                let mut response = ApiResponse::new(format!("query={query}").into_bytes());
                *response.status_mut() = axum::http::StatusCode::CREATED;
                *response.version_mut() = axum::http::Version::HTTP_2;
                response.headers_mut().append(
                    header::SET_COOKIE,
                    HeaderValue::from_static("a=1; Path=/; HttpOnly"),
                );
                response.headers_mut().append(
                    header::SET_COOKIE,
                    HeaderValue::from_static("b=2; Path=/; HttpOnly"),
                );
                response
                    .headers_mut()
                    .append("x-openauth-test", HeaderValue::from_static("one"));
                response
                    .headers_mut()
                    .append("x-openauth-test", HeaderValue::from_static("two"));
                response
                    .extensions_mut()
                    .insert(ResponseExtensionMarker("response-contract"));
                Ok(response)
            })
        },
    )
}

pub fn empty_response_endpoint(path: &'static str) -> AsyncAuthEndpoint {
    openauth::create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new(),
        |_context: &AuthContext, _request| {
            Box::pin(async {
                let mut response = ApiResponse::new(Vec::new());
                *response.status_mut() = axum::http::StatusCode::NO_CONTENT;
                Ok(response)
            })
        },
    )
}

pub fn failing_endpoint(path: &'static str) -> AsyncAuthEndpoint {
    openauth::create_auth_endpoint(
        path,
        Method::GET,
        AuthEndpointOptions::new(),
        |_context: &AuthContext, _request| {
            Box::pin(async { Err(OpenAuthError::Api("simulated internal failure".to_owned())) })
        },
    )
}

pub fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Body>, axum::http::Error> {
    request(method, path, body, cookie)?.with_header(header::CONTENT_TYPE, "application/json")
}

pub fn request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Body>, axum::http::Error> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::from(body.to_owned()))
}

pub trait RequestHeaderExt {
    fn with_header(
        self,
        name: header::HeaderName,
        value: &'static str,
    ) -> Result<Request<Body>, axum::http::Error>;
}

impl RequestHeaderExt for Request<Body> {
    fn with_header(
        self,
        name: header::HeaderName,
        value: &'static str,
    ) -> Result<Request<Body>, axum::http::Error> {
        let (mut parts, body) = self.into_parts();
        parts.headers.insert(name, HeaderValue::from_static(value));
        Ok(Request::from_parts(parts, body))
    }
}

pub async fn body_json(
    response: axum::response::Response,
) -> Result<Value, Box<dyn std::error::Error>> {
    let bytes = to_bytes(response.into_body(), BODY_LIMIT).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn body_text(
    response: axum::response::Response,
) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = to_bytes(response.into_body(), BODY_LIMIT).await?;
    Ok(String::from_utf8(bytes.to_vec())?)
}

pub fn cookie_header(response: &axum::response::Response) -> Option<String> {
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next().map(str::to_owned))
        .collect::<Vec<_>>();
    (!cookies.is_empty()).then(|| cookies.join("; "))
}

pub async fn reset_token(adapter: &MemoryAdapter) -> Result<String, Box<dyn std::error::Error>> {
    let records = adapter.records("verification").await;
    let record = records.first().ok_or("missing verification")?;
    let identifier = match record.get("identifier") {
        Some(DbValue::String(identifier)) => identifier,
        _ => return Err("missing verification identifier".into()),
    };
    let token = identifier
        .strip_prefix("reset-password:")
        .ok_or("unexpected verification identifier")?;
    Ok(token.to_owned())
}

pub fn query_value(url: &str, key: &str) -> Option<String> {
    Url::parse(url)
        .ok()?
        .query_pairs()
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

#[derive(Debug)]
pub struct FakeProvider {
    id: String,
    options: ProviderOptions,
}

impl FakeProvider {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            options: ProviderOptions::default(),
        }
    }
}

impl SocialOAuthProvider for FakeProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.id
    }

    fn provider_options(&self) -> ProviderOptions {
        self.options.clone()
    }

    fn create_authorization_url(
        &self,
        request: SocialAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = Url::parse("https://provider.example/authorize")?;
        url.query_pairs_mut()
            .append_pair("state", &request.state)
            .append_pair("redirect_uri", &request.redirect_uri);
        Ok(url)
    }

    fn validate_authorization_code<'a>(
        &'a self,
        _request: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'a, OAuth2Tokens> {
        Box::pin(async {
            Ok(OAuth2Tokens {
                token_type: Some("Bearer".to_owned()),
                access_token: Some("access-token".to_owned()),
                refresh_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scopes: Vec::new(),
                id_token: None,
                raw: Value::Null,
            })
        })
    }

    fn verify_id_token<'a>(
        &'a self,
        _request: SocialIdTokenRequest,
    ) -> SocialProviderFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn get_user_info<'a>(
        &'a self,
        _tokens: OAuth2Tokens,
        _provider_user: Option<Value>,
    ) -> SocialProviderFuture<'a, Option<OAuth2UserInfo>> {
        Box::pin(async {
            Ok(Some(OAuth2UserInfo {
                id: "provider-user-1".to_owned(),
                name: Some("Ada".to_owned()),
                email: Some("ada@example.com".to_owned()),
                image: None,
                email_verified: true,
            }))
        })
    }

    fn refresh_access_token<'a>(
        &'a self,
        refresh_token: String,
    ) -> SocialProviderFuture<'a, OAuth2Tokens> {
        Box::pin(async move {
            if refresh_token != "stored-refresh-token" {
                return Err(OAuthError::InvalidResponse("bad refresh token".to_owned()));
            }
            Ok(OAuth2Tokens {
                token_type: Some("Bearer".to_owned()),
                access_token: Some("new-access-token".to_owned()),
                refresh_token: Some("new-refresh-token".to_owned()),
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scopes: vec!["read:user".to_owned()],
                id_token: Some("new-id-token".to_owned()),
                raw: Value::Null,
            })
        })
    }
}
