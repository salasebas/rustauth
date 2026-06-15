#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use actix_web::http::{header, Method};
use actix_web::test::TestRequest;
use http::{HeaderValue, StatusCode as HttpStatusCode, Version};
use rustauth::api::{
    create_auth_endpoint, ApiResponse, AsyncAuthEndpoint, AuthEndpointOptions, RequestBaseUrl,
};
use rustauth::db::{DbValue, MemoryAdapter};
use rustauth::error::RustAuthError;
use rustauth::oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};
use rustauth::options::RustAuthOptions;
use rustauth::RustAuth;
use serde_json::Value;
use url::Url;

pub const SECRET: &str = "test-secret-123456789012345678901234";
pub const BODY_LIMIT: usize = 10 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseExtensionMarker(pub &'static str);

fn with_test_defaults(options: RustAuthOptions) -> RustAuthOptions {
    rustauth_core::test_utils::with_integration_test_defaults(options)
}

pub async fn auth_with_options(
    options: RustAuthOptions,
) -> Result<RustAuth, rustauth::error::RustAuthError> {
    RustAuth::builder()
        .options(with_test_defaults(options))
        .secret(SECRET)
        .build()
        .await
}

pub async fn auth_with_adapter(
    adapter: MemoryAdapter,
    options: RustAuthOptions,
) -> Result<RustAuth, rustauth::error::RustAuthError> {
    RustAuth::builder()
        .options(with_test_defaults(options))
        .secret(SECRET)
        .adapter(adapter)
        .build()
        .await
}

pub async fn auth_with_async_endpoint(
    endpoint: AsyncAuthEndpoint,
) -> Result<RustAuth, rustauth::error::RustAuthError> {
    RustAuth::builder()
        .secret(SECRET)
        .async_endpoint(endpoint)
        .build()
        .await
}

pub fn custom_endpoint(path: &'static str) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        http::Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| async move {
            let mut response = ApiResponse::new(b"CUSTOM".to_vec());
            *response.status_mut() = HttpStatusCode::OK;
            Ok(response)
        },
    )
}

pub fn request_extension_endpoint(path: &'static str) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        http::Method::GET,
        AuthEndpointOptions::new(),
        |_context, request| async move {
            let marker = request
                .extensions()
                .get::<RequestBaseUrl>()
                .map(|base| base.0.as_str())
                .unwrap_or("missing");
            let mut response = ApiResponse::new(format!("request={marker}").into_bytes());
            *response.status_mut() = HttpStatusCode::OK;
            Ok(response)
        },
    )
}

pub fn response_contract_endpoint(path: &'static str) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        http::Method::GET,
        AuthEndpointOptions::new(),
        |_context, request| async move {
            let query = request.uri().query().unwrap_or("");
            let mut response = ApiResponse::new(format!("query={query}").into_bytes());
            *response.status_mut() = HttpStatusCode::CREATED;
            *response.version_mut() = Version::HTTP_2;
            response.headers_mut().append(
                http::header::SET_COOKIE,
                HeaderValue::from_static("a=1; Path=/; HttpOnly"),
            );
            response.headers_mut().append(
                http::header::SET_COOKIE,
                HeaderValue::from_static("b=2; Path=/; HttpOnly"),
            );
            response
                .headers_mut()
                .append("x-rustauth-test", HeaderValue::from_static("one"));
            response
                .headers_mut()
                .append("x-rustauth-test", HeaderValue::from_static("two"));
            response
                .extensions_mut()
                .insert(ResponseExtensionMarker("response-contract"));
            Ok(response)
        },
    )
}

pub fn empty_response_endpoint(path: &'static str) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        http::Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| async move {
            let mut response = ApiResponse::new(Vec::new());
            *response.status_mut() = HttpStatusCode::NO_CONTENT;
            Ok(response)
        },
    )
}

pub fn failing_endpoint(path: &'static str) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        path,
        http::Method::GET,
        AuthEndpointOptions::new(),
        |_context, _request| async move {
            Err(RustAuthError::Api("simulated internal failure".to_owned()))
        },
    )
}

pub fn test_request(method: Method, path: &str, body: &str, cookie: Option<&str>) -> TestRequest {
    let mut builder = TestRequest::default().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.insert_header((header::COOKIE, cookie));
    }
    if !body.is_empty() {
        builder = builder.set_payload(body.to_owned());
    }
    builder
}

pub fn json_test_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> TestRequest {
    test_request(method, path, body, cookie)
        .insert_header((header::CONTENT_TYPE, "application/json"))
}

pub trait TestRequestHeaderExt {
    fn with_header(self, name: header::HeaderName, value: &'static str) -> Self;
}

impl TestRequestHeaderExt for TestRequest {
    fn with_header(self, name: header::HeaderName, value: &'static str) -> Self {
        self.insert_header((name, value))
    }
}

#[macro_export]
macro_rules! mounted_app {
    ($auth:expr, $options:expr $(,)?) => {{
        #[allow(clippy::expect_used)]
        {
            use rustauth_actix_web::RustAuthActixWebExt as _;
            let scope = $auth
                .mount_at_base_path($options)
                .expect("valid RustAuth Actix mount");
            actix_web::test::init_service(actix_web::App::new().service(scope)).await
        }
    }};
}

#[macro_export]
macro_rules! handle_app {
    ($auth:expr, $options:expr $(,)?) => {{
        let state = actix_web::web::Data::new(($auth, $options));
        actix_web::test::init_service(
            actix_web::App::new()
                .app_data(state.clone())
                .default_service(actix_web::web::route().to(
                    |req: actix_web::HttpRequest,
                     payload: actix_web::web::Payload,
                     state: actix_web::web::Data<(
                        std::sync::Arc<rustauth::RustAuth>,
                        rustauth_actix_web::RustAuthActixWebOptions,
                    )>| async move {
                        let (auth, options) = state.get_ref();
                        rustauth_actix_web::handle(auth.as_ref(), *options, req, payload).await
                    },
                )),
        )
        .await
    }};
}

pub async fn body_json(
    response: actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(actix_web::test::read_body_json(response).await)
}

pub async fn body_text(
    response: actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = actix_web::test::read_body(response).await;
    Ok(String::from_utf8(bytes.to_vec())?)
}

pub fn cookie_header(
    response: &actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) -> Option<String> {
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next().map(str::to_owned))
        .collect::<Vec<_>>();
    (!cookies.is_empty()).then(|| cookies.join("; "))
}

pub async fn wait_for_mutex_option<T: Clone>(
    value: &std::sync::Mutex<Option<T>>,
) -> Result<T, Box<dyn std::error::Error>> {
    for _ in 0..200 {
        if let Some(value) = value.lock().ok().and_then(|guard| guard.clone()) {
            return Ok(value);
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    Err("missing captured outbound value".into())
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

pub fn actix_method(method: &http::Method) -> Result<Method, Box<dyn std::error::Error>> {
    Ok(Method::from_bytes(method.as_str().as_bytes()).map_err(|_| "invalid HTTP method")?)
}

pub fn test_request_with_peer_addr(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
    client_ip: &str,
) -> Result<TestRequest, Box<dyn std::error::Error>> {
    let ip = IpAddr::V4(client_ip.parse::<Ipv4Addr>()?);
    Ok(test_request(method, path, body, cookie).peer_addr(SocketAddr::new(ip, 12345)))
}

pub fn test_request_with_peer_addr_and_forwarded_for(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
    client_ip: &str,
    forwarded_for: &'static str,
) -> Result<TestRequest, Box<dyn std::error::Error>> {
    Ok(
        test_request_with_peer_addr(method, path, body, cookie, client_ip)?.insert_header((
            header::HeaderName::from_static("x-forwarded-for"),
            forwarded_for,
        )),
    )
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
