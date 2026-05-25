pub use std::collections::{BTreeMap, BTreeSet};
pub use std::sync::Arc;

pub use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
pub use base64::Engine;
pub use hmac::{Hmac, Mac};
pub use http::{header, Method, Request, StatusCode};
pub use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
pub use openauth_core::context::create_auth_context_with_adapter;
pub use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
pub use openauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, FindMany, MemoryAdapter, Session, Update, Where,
};
pub use openauth_core::error::OpenAuthError;
pub use openauth_core::options::{AdvancedOptions, OpenAuthOptions, RateLimitRule};
pub use openauth_oauth_provider::mcp::{
    authorization_server_metadata as mcp_authorization_server_metadata,
    protected_resource_metadata as mcp_protected_resource_metadata, validate_bearer_token,
    www_authenticate_for_resources,
};
pub use openauth_oauth_provider::{
    delete_consent, find_consent, has_granted_scopes, oauth_provider, upsert_consent,
    ClientPrivilegeAction, ClientPrivilegesResolver, ClientReferenceResolver,
    ClientSecretHashResolver, ConsentGrantInput, CustomAccessTokenClaimsResolver,
    CustomIdTokenClaimsResolver, CustomTokenResponseFieldsResolver, CustomUserInfoClaimsResolver,
    GrantType, OAuthProviderConfigError, OAuthProviderOptions, OAuthProviderRateLimit,
    OAuthProviderRateLimits, OAuthTokenPrefixes, PromptRedirectResolver,
    RefreshTokenFormatDecodeOutput, RefreshTokenFormatter, RequestUriResolver, SecretStorage,
    StringGeneratorResolver, TokenHashResolver,
};
pub use serde_json::{json, Value};
pub use sha2::{Digest, Sha256};
pub use time::{Duration, OffsetDateTime};

pub const BASE_URL: &str = "http://localhost:3000";
pub const SECRET: &str = "test-secret-123456789012345678901234";
pub type HmacSha256 = Hmac<Sha256>;

pub async fn register_client(
    router: &AuthRouter,
    body: &str,
    cookie: Option<&str>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let path = if cookie.is_some() && body.contains("\"skip_consent\"") {
        "/api/auth/admin/oauth2/create-client"
    } else {
        "/api/auth/oauth2/register"
    };
    let response = router
        .handle_async(request(Method::POST, path, body, cookie)?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response)
}

pub async fn create_admin_client(
    router: &AuthRouter,
    body: &str,
    cookie: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let response = router
        .handle_async(request(
            Method::POST,
            "/api/auth/admin/oauth2/create-client",
            body,
            Some(cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response)
}

pub async fn exchange_authorization_code(
    router: &AuthRouter,
    cookie: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    exchange_authorization_code_with_scope(
        router,
        cookie,
        client_id,
        client_secret,
        "openid offline_access",
    )
    .await
}

pub async fn exchange_authorization_code_with_scope(
    router: &AuthRouter,
    cookie: &str,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope={}&code_challenge={challenge}&code_challenge_method=S256",
        query_encode(scope)
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&code_verifier={verifier}"
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response)
}

pub async fn exchange_authorization_code_with_resource(
    router: &AuthRouter,
    cookie: &str,
    client_id: &str,
    client_secret: &str,
    resource: Option<&str>,
) -> Result<Value, Box<dyn std::error::Error>> {
    if resource.is_none() {
        return exchange_authorization_code(router, cookie, client_id, client_secret).await;
    }

    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&scope=openid%20offline_access&code_challenge={challenge}&code_challenge_method=S256"
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri=https%3A%2F%2Frp.example%2Fcallback&resource={}&code_verifier={verifier}",
        query_encode(resource.unwrap_or_default())
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response)
}

pub async fn exchange_authorization_code_with_redirect(
    router: &AuthRouter,
    cookie: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let verifier = "correct-horse-battery-staple";
    let challenge = pkce_challenge(verifier);
    let authorize_path = format!(
        "/api/auth/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid%20offline_access&code_challenge={challenge}&code_challenge_method=S256",
        query_encode(redirect_uri)
    );
    let response = router
        .handle_async(request(Method::GET, &authorize_path, "", Some(cookie))?)
        .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let code = authorization_code_from_location(&response)?;
    let body = format!(
        "grant_type=authorization_code&client_id={client_id}&client_secret={client_secret}&code={code}&redirect_uri={}&code_verifier={verifier}",
        query_encode(redirect_uri)
    );
    let response = router
        .handle_async(form_request(Method::POST, "/api/auth/oauth2/token", &body)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response)
}

pub fn authorization_code_from_location(
    response: &http::Response<Vec<u8>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let redirect = redirect_url(response)?;
    redirect
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then_some(value.into_owned()))
        .ok_or_else(|| "missing code".into())
}

pub fn redirect_url(
    response: &http::Response<Vec<u8>>,
) -> Result<url::Url, Box<dyn std::error::Error>> {
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing location")?;
    Ok(url::Url::parse(BASE_URL)?.join(location)?)
}

pub fn redirect_query_value(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find_map(|(key, value)| (key == name).then_some(value.into_owned()))
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn decode_jwt_payload(token: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or("token does not contain a jwt payload")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
}

pub fn query_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

pub fn signed_oauth_query(exp: i64) -> Result<String, OpenAuthError> {
    let unsigned = format!("exp={exp}");
    let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes())
        .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
    mac.update(unsigned.as_bytes());
    let signature = STANDARD.encode(mac.finalize().into_bytes());
    Ok(format!("{unsigned}&sig={}", query_encode(&signature)))
}

pub fn default_provider(
) -> Result<openauth_oauth_provider::OAuthProviderPlugin, OAuthProviderConfigError> {
    oauth_provider(default_options())
}

pub fn default_options() -> OAuthProviderOptions {
    OAuthProviderOptions {
        login_page: "/login".into(),
        consent_page: "/consent".into(),
        ..OAuthProviderOptions::default()
    }
}

pub fn options_with_provider(
    plugin: openauth_oauth_provider::OAuthProviderPlugin,
) -> OpenAuthOptions {
    OpenAuthOptions {
        base_url: Some(BASE_URL.to_owned()),
        secret: Some(SECRET.to_owned()),
        plugins: vec![plugin.into_auth_plugin()],
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    }
}

pub fn router(
    plugin: openauth_oauth_provider::OAuthProviderPlugin,
    adapter: Arc<MemoryAdapter>,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(options_with_provider(plugin), adapter.clone())?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

pub fn adapter() -> Arc<MemoryAdapter> {
    Arc::new(MemoryAdapter::new())
}

pub fn request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{BASE_URL}{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

pub fn form_request(
    method: Method,
    path: &str,
    body: &str,
) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("{BASE_URL}{path}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
}

pub fn bearer_request(
    method: Method,
    path: &str,
    token: &str,
) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(format!("{BASE_URL}{path}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Vec::new())
}

pub fn json_body(response: http::Response<Vec<u8>>) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(response.body())?)
}

pub async fn seed_user_session(adapter: &MemoryAdapter) -> Result<(), OpenAuthError> {
    seed_user_session_with(
        adapter,
        UserSeed {
            user_id: "user_1",
            session_id: "session_1",
            token: "token_1",
            name: "Ada Lovelace",
            email: "ada@example.com",
        },
    )
    .await
}

pub struct UserSeed<'a> {
    pub user_id: &'a str,
    pub session_id: &'a str,
    pub token: &'a str,
    pub name: &'a str,
    pub email: &'a str,
}

pub async fn seed_user_session_with(
    adapter: &MemoryAdapter,
    seed: UserSeed<'_>,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(create_query("user", user_record(now, &seed)))
        .await?;
    adapter
        .create(create_query("session", session_record(now, &seed)))
        .await?;
    Ok(())
}

pub fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(SECRET.to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter(),
    )?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        SessionCookieOptions::default(),
    )?;
    Ok(cookies
        .iter()
        .map(|cookie: &Cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; "))
}

pub fn create_query(model: &str, record: DbRecord) -> Create {
    record
        .into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
}

pub fn user_record(now: OffsetDateTime, seed: &UserSeed<'_>) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(seed.user_id.to_owned()));
    record.insert("name".to_owned(), DbValue::String(seed.name.to_owned()));
    record.insert("email".to_owned(), DbValue::String(seed.email.to_owned()));
    record.insert("email_verified".to_owned(), DbValue::Boolean(true));
    record.insert("image".to_owned(), DbValue::Null);
    record.insert("created_at".to_owned(), DbValue::Timestamp(now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(now));
    record
}

pub fn session_record(now: OffsetDateTime, seed: &UserSeed<'_>) -> DbRecord {
    let mut record = DbRecord::new();
    let session = Session {
        id: seed.session_id.to_owned(),
        user_id: seed.user_id.to_owned(),
        expires_at: now + Duration::hours(1),
        token: seed.token.to_owned(),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
    };
    record.insert("id".to_owned(), DbValue::String(session.id));
    record.insert("user_id".to_owned(), DbValue::String(session.user_id));
    record.insert(
        "expires_at".to_owned(),
        DbValue::Timestamp(session.expires_at),
    );
    record.insert("token".to_owned(), DbValue::String(session.token));
    record.insert("ip_address".to_owned(), DbValue::Null);
    record.insert("user_agent".to_owned(), DbValue::Null);
    record.insert(
        "created_at".to_owned(),
        DbValue::Timestamp(session.created_at),
    );
    record.insert(
        "updated_at".to_owned(),
        DbValue::Timestamp(session.updated_at),
    );
    record
}
