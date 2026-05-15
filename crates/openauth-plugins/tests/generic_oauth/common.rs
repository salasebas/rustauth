pub(super) use http::{header, Method, Request, Response, StatusCode};
pub(super) use openauth_core::api::AuthRouter;
pub(super) use openauth_core::context::{create_auth_context_with_adapter, AuthContext};
pub(super) use openauth_core::cookies::{
    get_session_cookie, set_session_cookie, verify_cookie_value, Cookie, SessionCookieOptions,
};
pub(super) use openauth_core::db::{DbAdapter, MemoryAdapter};
pub(super) use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
pub(super) use openauth_core::plugin::AuthPlugin;
pub(super) use openauth_core::session::{CreateSessionInput, DbSessionStore};
pub(super) use openauth_core::user::{CreateOAuthAccountInput, CreateUserInput, DbUserStore};
pub(super) use openauth_oauth::oauth2::{
    ClientAuthentication, OAuth2Tokens, OAuth2UserInfo, OAuthError, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialOAuthProvider,
};
pub(super) use openauth_plugins::generic_oauth::{
    auth0, generic_oauth, gumroad, hubspot, keycloak, line, microsoft_entra_id, okta, patreon,
    slack, Auth0Options, BaseOAuthProviderOptions, GenericOAuthConfig, GenericOAuthFlow,
    GenericOAuthOptions, GenericOAuthParamsContext, GenericOAuthTokenRequest, GumroadOptions,
    HubSpotOptions, KeycloakOptions, LineOptions, MicrosoftEntraIdOptions, OktaOptions,
    PatreonOptions, SlackOptions, UPSTREAM_PLUGIN_ID,
};
pub(super) use serde_json::Value;
pub(super) use std::collections::BTreeMap;
pub(super) use std::io::{Read, Write};
pub(super) use std::net::TcpListener;
pub(super) use std::sync::atomic::{AtomicUsize, Ordering};
pub(super) use std::sync::{Arc, Mutex};
pub(super) use std::thread;
pub(super) use time::{Duration, OffsetDateTime};

pub(super) fn example_config() -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        "example",
        "client-1",
        Some("secret-1"),
        "https://idp.example.com/oauth/authorize",
        "https://idp.example.com/oauth/token",
    );
    config.user_info_url = Some("https://idp.example.com/oauth/userinfo".to_owned());
    config.scopes = vec!["openid".to_owned(), "email".to_owned()];
    config.pkce = true;
    config.prompt = Some("consent".to_owned());
    config
        .authorization_url_params
        .insert("audience".to_owned(), "api".to_owned());
    config
}

pub(super) fn provider(
    config: GenericOAuthConfig,
) -> openauth_plugins::generic_oauth::GenericOAuthProvider {
    openauth_plugins::generic_oauth::GenericOAuthProvider::new(config)
}

pub(super) fn helper_base(client_id: &str, client_secret: &str) -> BaseOAuthProviderOptions {
    BaseOAuthProviderOptions {
        client_id: client_id.to_owned(),
        client_secret: Some(client_secret.to_owned()),
        ..BaseOAuthProviderOptions::default()
    }
}

pub(super) fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

pub(super) fn discovery_server(hits: Arc<AtomicUsize>) -> String {
    discovery_server_with_token(
        hits,
        "https://idp.example.com/oauth/token",
        "https://idp.example.com/oauth/userinfo",
    )
}

pub(super) fn discovery_server_with_token(
    hits: Arc<AtomicUsize>,
    token_endpoint: &str,
    userinfo_endpoint: &str,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let token_endpoint = token_endpoint.to_owned();
    let userinfo_endpoint = userinfo_endpoint.to_owned();
    thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let mut stream = stream.unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer);
            hits.fetch_add(1, Ordering::SeqCst);
            let body = format!(
                r#"{{"authorization_endpoint":"https://idp.example.com/oauth/authorize","token_endpoint":"{token_endpoint}","userinfo_endpoint":"{userinfo_endpoint}","issuer":"https://idp.example.com"}}"#
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    format!("http://{address}/.well-known/openid-configuration")
}

pub(super) fn capture_post_server(captured_body: Arc<Mutex<String>>, body: &str) -> String {
    capture_server("token", captured_body, body)
}

pub(super) fn capture_get_server(captured_request: Arc<Mutex<String>>, body: &str) -> String {
    capture_server("userinfo", captured_request, body)
}

fn capture_server(path: &str, captured_request: Arc<Mutex<String>>, body: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let body = body.to_owned();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let size = stream.read(&mut buffer).unwrap_or(0);
        let request = String::from_utf8_lossy(&buffer[..size]);
        *captured_request.lock().unwrap() = request.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    format!("http://{address}/{path}")
}

pub(super) fn oauth_flow_config(user_id: &str) -> GenericOAuthConfig {
    let mut config = example_config();
    let user_id = user_id.to_owned();
    config.get_token = Some(Arc::new(|_request| {
        Box::pin(async {
            Ok(OAuth2Tokens {
                access_token: Some("access-token".to_owned()),
                refresh_token: Some("refresh-token".to_owned()),
                scopes: vec!["openid".to_owned(), "email".to_owned()],
                ..OAuth2Tokens::default()
            })
        })
    }));
    config.get_user_info = Some(Arc::new(move |_tokens| {
        let user_id = user_id.clone();
        Box::pin(async move {
            Ok(Some(OAuth2UserInfo {
                id: user_id,
                name: Some("Ada Lovelace".to_owned()),
                email: Some("ada@example.com".to_owned()),
                image: Some("https://img.example.com/ada.png".to_owned()),
                email_verified: true,
            }))
        })
    }));
    config
}

pub(super) fn oauth_plugin(config: GenericOAuthConfig) -> AuthPlugin {
    generic_oauth(GenericOAuthOptions {
        config: vec![config],
    })
}

pub(super) fn context_with_plugin(adapter: Arc<dyn DbAdapter>, plugin: AuthPlugin) -> AuthContext {
    create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            secret: Some(secret().to_owned()),
            plugins: vec![plugin],
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        adapter,
    )
    .unwrap()
}

pub(super) async fn sign_in_url(
    router: &AuthRouter,
    provider_id: &str,
    callback_url: &str,
    new_user_url: Option<&str>,
    request_sign_up: bool,
) -> Result<url::Url, Box<dyn std::error::Error>> {
    let new_user = new_user_url
        .map(|url| format!(r#","newUserCallbackURL":"{url}""#))
        .unwrap_or_default();
    let request_sign_up = if request_sign_up {
        r#","requestSignUp":true"#
    } else {
        ""
    };
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/sign-in/oauth2")
                .header(header::CONTENT_TYPE, "application/json")
                .body(
                    format!(
                        r#"{{"providerId":"{provider_id}","callbackURL":"{callback_url}","disableRedirect":true{new_user}{request_sign_up}}}"#
                    )
                    .into_bytes(),
                )?,
        )
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    Ok(url::Url::parse(body["url"].as_str().ok_or("missing url")?)?)
}

pub(super) async fn sign_in_state(
    router: &AuthRouter,
    provider_id: &str,
    callback_url: &str,
    new_user_url: Option<&str>,
    request_sign_up: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = sign_in_url(
        router,
        provider_id,
        callback_url,
        new_user_url,
        request_sign_up,
    )
    .await?;
    query_value(&url, "state").ok_or_else(|| "missing state".into())
}

pub(super) async fn link_state(
    router: &AuthRouter,
    provider_id: &str,
    cookie: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri("https://app.example.com/api/auth/oauth2/link")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(
                    format!(r#"{{"providerId":"{provider_id}","callbackURL":"/settings"}}"#)
                        .into_bytes(),
                )?,
        )
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    let url = url::Url::parse(body["url"].as_str().ok_or_else(|| {
        format!(
            "missing url in {} response: {}",
            response.status(),
            String::from_utf8_lossy(response.body())
        )
    })?)?;
    query_value(&url, "state").ok_or_else(|| "missing state".into())
}

pub(super) async fn oauth_callback(
    router: &AuthRouter,
    provider_id: &str,
    code: &str,
    state: &str,
) -> Result<Response<Vec<u8>>, openauth_core::error::OpenAuthError> {
    router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "https://app.example.com/api/auth/oauth2/callback/{provider_id}?code={code}&state={state}"
                ))
                .body(Vec::new())
                .unwrap(),
        )
        .await
}

pub(super) fn location(response: &Response<Vec<u8>>) -> Option<&str> {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
}

pub(super) fn session_token_from_response(
    context: &AuthContext,
    response: &Response<Vec<u8>>,
) -> String {
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap();
    let signed = get_session_cookie(cookie, None, None).unwrap();
    verify_cookie_value(&signed, &context.secret)
        .unwrap()
        .unwrap()
}

pub(super) async fn seed_user(adapter: &dyn DbAdapter, id: &str, email: &str) {
    DbUserStore::new(adapter)
        .create_user(CreateUserInput::new("Ada Lovelace", email).id(id))
        .await
        .unwrap();
}

pub(super) async fn session_cookie_for(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user_id: &str,
) -> String {
    let session = DbSessionStore::new(adapter)
        .create_session(CreateSessionInput::new(
            user_id,
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await
        .unwrap();
    cookie_header(
        &set_session_cookie(
            &context.auth_cookies,
            &context.secret,
            &session.token,
            SessionCookieOptions::default(),
        )
        .unwrap(),
    )
}

pub(super) fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

pub(super) fn jwt_with_claims(claims: &str) -> String {
    fn encode(input: &str) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let bytes = input.as_bytes();
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            output.push(TABLE[(b0 >> 2) as usize] as char);
            output.push(TABLE[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                output.push(TABLE[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(TABLE[(b2 & 0b111111) as usize] as char);
            }
        }
        output
    }

    format!("{}.{}.", encode(r#"{"alg":"none"}"#), encode(claims))
}
