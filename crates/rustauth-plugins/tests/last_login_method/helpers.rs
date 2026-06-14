use std::sync::Arc;

use http::{header, HeaderValue, Method, Request, Response};
use rustauth_core::api::{core_auth_async_endpoints, AuthRouter};
use rustauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use rustauth_core::db::{DbAdapter, DbRecord, DbValue, FindOne, MemoryAdapter, Where};
use rustauth_core::options::RustAuthOptions;
use rustauth_core::test_utils::with_integration_test_defaults;
use rustauth_oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};
use rustauth_plugins::last_login_method::{last_login_method, LastLoginMethodOptions};
use url::Url;

pub fn request(path: &str) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:3000{path}"))
        .body(Vec::new())
}

pub fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

pub fn router_with_plugin(
    adapter: Arc<MemoryAdapter>,
    options: LastLoginMethodOptions,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    router_with_plugin_options(adapter, options, RustAuthOptions::default())
}

pub fn router_with_plugin_options(
    adapter: Arc<MemoryAdapter>,
    options: LastLoginMethodOptions,
    rustauth_options: RustAuthOptions,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    let base_adapter: Arc<dyn DbAdapter> = adapter;
    let mut rustauth_options = rustauth_options;
    rustauth_options
        .plugins
        .push(last_login_method(options.store_in_database(true)));
    rustauth_options.secret = Some(secret().to_owned());
    rustauth_options.advanced.disable_csrf_check = true;
    rustauth_options.advanced.disable_origin_check = true;
    let rustauth_options = with_integration_test_defaults(rustauth_options);
    let context = create_auth_context_with_adapter(rustauth_options, Arc::clone(&base_adapter))?;
    Ok(AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(),
    )?)
}

pub async fn find_user_by_email(
    adapter: &MemoryAdapter,
    email: &str,
) -> Result<Option<DbRecord>, rustauth_core::error::RustAuthError> {
    adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("email", DbValue::String(email.to_owned()))),
        )
        .await
}

pub fn signed_session_cookie(token: &str) -> Result<String, rustauth_core::error::RustAuthError> {
    let context = create_auth_context(RustAuthOptions {
        secret: Some(secret().to_owned()),
        ..RustAuthOptions::default()
    })?;
    let cookies = rustauth_core::cookies::set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        rustauth_core::cookies::SessionCookieOptions::default(),
    )?;
    Ok(cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; "))
}

pub fn response_with_set_cookie(
    cookie: &str,
) -> Result<Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut response = Response::builder().status(200).body(Vec::new())?;
    response
        .headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_str(cookie)?);
    Ok(response)
}

pub async fn run_last_login_after_hook(
    plugin: &rustauth_core::plugin::AuthPlugin,
    context: &rustauth_core::context::AuthContext,
    request: &Request<Vec<u8>>,
    response: Response<Vec<u8>>,
) -> Result<Response<Vec<u8>>, Box<dyn std::error::Error>> {
    let hook = plugin
        .hooks
        .async_after
        .first()
        .ok_or("missing async after hook")?;
    let rustauth_core::plugin::PluginAfterHookAction::Continue(response) =
        (hook.handler)(context, request, response).await?;
    Ok(response)
}

pub fn set_cookie_values(response: &Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

pub fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

#[derive(Debug)]
pub struct FakeProvider {
    id: String,
}

impl FakeProvider {
    pub fn new(id: &str) -> Self {
        Self { id: id.to_owned() }
    }
}

impl SocialOAuthProvider for FakeProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        "Fake Provider"
    }

    fn provider_options(&self) -> ProviderOptions {
        ProviderOptions {
            client_id: Some("client-id".into()),
            client_secret: Some(
                rustauth_oauth::oauth2::ClientSecret::new("client-secret").expect("client secret"),
            ),
            ..ProviderOptions::default()
        }
    }

    fn create_authorization_url(
        &self,
        input: SocialAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        Url::parse(&format!(
            "https://provider.example.com/oauth?state={}&redirect_uri={}",
            input.state, input.redirect_uri
        ))
        .map_err(OAuthError::InvalidUrl)
    }

    fn validate_authorization_code(
        &self,
        input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async move {
            if input.code == "ok" {
                Ok(OAuth2Tokens {
                    access_token: Some("access-token".to_owned()),
                    refresh_token: Some("refresh-token".to_owned()),
                    scopes: vec!["profile".to_owned()],
                    ..OAuth2Tokens::default()
                })
            } else {
                Err(OAuthError::InvalidResponse(
                    "invalid authorization code".to_owned(),
                ))
            }
        })
    }

    fn get_user_info(
        &self,
        _tokens: OAuth2Tokens,
        _provider_user: Option<serde_json::Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        let id = format!("{}_ada", self.id);
        Box::pin(async move {
            Ok(Some(OAuth2UserInfo {
                id,
                name: Some("Ada Lovelace".to_owned()),
                email: Some("ada.oauth@example.com".to_owned()),
                image: None,
                email_verified: true,
            }))
        })
    }

    fn verify_id_token(&self, input: SocialIdTokenRequest) -> SocialProviderFuture<'_, bool> {
        Box::pin(async move { Ok(input.token == "valid-id-token") })
    }
}
