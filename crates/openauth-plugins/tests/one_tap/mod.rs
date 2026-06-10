use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter, Body};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{
    AdapterFuture, Create, DbAdapter, DbRecord, DbValue, FindOne, MemoryAdapter, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};
use openauth_core::options::{
    AccountLinkingOptions, AccountOptions, AdvancedOptions, OpenAuthOptions,
};
use openauth_plugins::additional_fields::{
    additional_fields_with, AdditionalField, AdditionalFieldsOptions,
};
use openauth_plugins::one_tap::{one_tap, one_tap_with, OneTapOptions};
use openauth_plugins::one_time_token::{one_time_token_with, OneTimeTokenOptions};
use serde_json::Value;
use time::OffsetDateTime;
use url::Url;

#[test]
fn exposes_one_tap_plugin_builder() {
    let plugin = one_tap();

    assert_eq!(openauth_plugins::one_tap::UPSTREAM_PLUGIN_ID, "one-tap");
    assert_eq!(plugin.id, "one-tap");
    assert!(plugin.endpoints.iter().any(|endpoint| {
        endpoint.path == "/one-tap/callback" && endpoint.method == Method::POST
    }));
}

#[tokio::test]
async fn callback_rejects_missing_id_token() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, OneTapOptions::default())?;

    let response = router
        .handle_async(json_request("/api/auth/one-tap/callback", r#"{}"#)?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

#[tokio::test]
async fn callback_rejects_invalid_id_token() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, OneTapOptions::default())?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"invalid-id-token"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_TOKEN");
    Ok(())
}

#[tokio::test]
async fn callback_creates_user_account_session_and_sets_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter.clone(), OneTapOptions::default())?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"valid-id-token"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(body["token"].is_string());
    assert_eq!(body["user"]["email"], "ada@example.com");
    assert!(set_cookie_values(&response)
        .iter()
        .any(|value| value.starts_with("open-auth.session_token=")));
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("account").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}

#[tokio::test]
async fn callback_accepts_form_encoded_id_token() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, OneTapOptions::default())?;

    let response = router
        .handle_async(form_request(
            "/api/auth/one-tap/callback",
            "idToken=valid-id-token",
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["email"], "ada@example.com");
    Ok(())
}

#[tokio::test]
async fn callback_rejects_token_without_email() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, OneTapOptions::default())?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"no-email-token"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "EMAIL_NOT_AVAILABLE");
    Ok(())
}

#[tokio::test]
async fn callback_rejects_new_user_when_signup_is_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(
        adapter.clone(),
        OneTapOptions {
            disable_signup: true,
            ..OneTapOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"valid-id-token"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body["code"], "SIGNUP_DISABLED");
    assert_eq!(adapter.len("user").await, 0);
    assert_eq!(adapter.len("account").await, 0);
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}

#[tokio::test]
async fn callback_rejects_unlinked_existing_user_when_account_linking_is_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    adapter.insert_user(test_user()).await?;
    let router = router_with_options(
        adapter.clone(),
        OneTapOptions::default(),
        OpenAuthOptions {
            account: AccountOptions {
                account_linking: AccountLinkingOptions {
                    enabled: false,
                    ..AccountLinkingOptions::default()
                },
                ..AccountOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        vec![],
    )?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"valid-id-token"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "ACCOUNT_NOT_LINKED");
    assert_eq!(adapter.len("account").await, 0);
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}

#[tokio::test]
async fn callback_rejects_unverified_existing_user_when_google_is_not_trusted(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    adapter.insert_user(test_user()).await?;
    let router = router(adapter.clone(), OneTapOptions::default())?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"unverified-id-token"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "ACCOUNT_NOT_LINKED");
    assert_eq!(adapter.len("account").await, 0);
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}

#[tokio::test]
async fn callback_links_unverified_existing_user_when_google_is_trusted(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    adapter.insert_user(test_user()).await?;
    let router = router_with_options(
        adapter.clone(),
        OneTapOptions::default(),
        OpenAuthOptions {
            account: AccountOptions {
                account_linking: AccountLinkingOptions::default().trusted_provider("google"),
                ..AccountOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        vec![],
    )?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"unverified-id-token"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(adapter.len("account").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}

#[tokio::test]
async fn callback_links_google_account_for_existing_verified_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    adapter.insert_user(test_user()).await?;
    let router = router(adapter.clone(), OneTapOptions::default())?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"valid-id-token"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("account").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    assert!(contains_record_string(&adapter, "account", "account_id", "google_ada").await?);
    Ok(())
}

#[tokio::test]
async fn callback_signs_in_existing_google_account_without_duplication(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(test_user()).await?;
    adapter
        .insert_account(linked_account_record(
            "account_1",
            "google",
            "google_ada",
            "user_1",
            Some("openid,profile,email"),
            now,
        ))
        .await?;
    let router = router(adapter.clone(), OneTapOptions::default())?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"valid-id-token"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["id"], "user_1");
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("account").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}

#[tokio::test]
async fn callback_sets_one_time_token_header_for_new_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_options(
        adapter,
        OneTapOptions::default(),
        OpenAuthOptions::default(),
        vec![one_time_token_with(
            OneTimeTokenOptions::default()
                .set_ott_header_on_new_session(true)
                .generate_token(|_, _| Ok("one-tap-ott".to_owned())),
        )],
    )?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"valid-id-token"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("set-ott")
            .and_then(|value| value.to_str().ok()),
        Some("one-tap-ott")
    );
    Ok(())
}

#[tokio::test]
async fn callback_returns_configured_additional_user_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_options(
        adapter,
        OneTapOptions::default(),
        OpenAuthOptions::default(),
        vec![additional_fields_with(
            AdditionalFieldsOptions::new().user_field(
                "role",
                AdditionalField::new(openauth_core::db::DbFieldType::String)
                    .default_value(DbValue::String("member".to_owned()))
                    .generated(),
            ),
        )],
    )?;

    let response = router
        .handle_async(json_request(
            "/api/auth/one-tap/callback",
            r#"{"idToken":"valid-id-token"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["role"], "member");
    Ok(())
}

fn router(
    adapter: Arc<MemoryAdapter>,
    options: OneTapOptions,
) -> Result<AuthRouter, OpenAuthError> {
    router_with_options(adapter, options, OpenAuthOptions::default(), vec![])
}

fn router_with_options(
    adapter: Arc<MemoryAdapter>,
    one_tap_options: OneTapOptions,
    options: OpenAuthOptions,
    extra_plugins: Vec<openauth_core::plugin::AuthPlugin>,
) -> Result<AuthRouter, OpenAuthError> {
    let mut plugins = vec![one_tap_with(one_tap_options)];
    plugins.extend(extra_plugins);
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(secret().to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins,
            social_providers: vec![Arc::new(FakeGoogleProvider)],
            ..options
        },
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn json_request(path: &str, body: &str) -> Result<Request<Body>, http::Error> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.as_bytes().to_vec())
}

fn form_request(path: &str, body: &str) -> Result<Request<Body>, http::Error> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
}

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

fn set_cookie_values(response: &http::Response<Body>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

trait AdapterSeed {
    fn insert_user(&self, user: openauth_core::db::User) -> AdapterFuture<'_, ()>;
    fn insert_account(&self, record: DbRecord) -> AdapterFuture<'_, ()>;
}

impl AdapterSeed for MemoryAdapter {
    fn insert_user(&self, user: openauth_core::db::User) -> AdapterFuture<'_, ()> {
        Box::pin(async move {
            self.create(create_query("user", user_record(user))).await?;
            Ok(())
        })
    }

    fn insert_account(&self, record: DbRecord) -> AdapterFuture<'_, ()> {
        Box::pin(async move {
            self.create(create_query("account", record)).await?;
            Ok(())
        })
    }
}

fn test_user() -> openauth_core::db::User {
    let now = OffsetDateTime::now_utc();
    openauth_core::db::User {
        id: "user_1".to_owned(),
        name: "Ada".to_owned(),
        email: "ada@example.com".to_owned(),
        email_verified: true,
        image: None,
        username: None,
        display_username: None,
        created_at: now,
        updated_at: now,
    }
}

fn user_record(user: openauth_core::db::User) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(user.id));
    record.insert("name".to_owned(), DbValue::String(user.name));
    record.insert("email".to_owned(), DbValue::String(user.email));
    record.insert(
        "email_verified".to_owned(),
        DbValue::Boolean(user.email_verified),
    );
    record.insert(
        "image".to_owned(),
        user.image.map(DbValue::String).unwrap_or(DbValue::Null),
    );
    record.insert(
        "username".to_owned(),
        user.username.map(DbValue::String).unwrap_or(DbValue::Null),
    );
    record.insert(
        "display_username".to_owned(),
        user.display_username
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(user.created_at));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(user.updated_at));
    record
}

fn linked_account_record(
    id: &str,
    provider_id: &str,
    account_id: &str,
    user_id: &str,
    scope: Option<&str>,
    now: OffsetDateTime,
) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(id.to_owned()));
    record.insert(
        "provider_id".to_owned(),
        DbValue::String(provider_id.to_owned()),
    );
    record.insert(
        "account_id".to_owned(),
        DbValue::String(account_id.to_owned()),
    );
    record.insert("user_id".to_owned(), DbValue::String(user_id.to_owned()));
    record.insert("access_token".to_owned(), DbValue::Null);
    record.insert("refresh_token".to_owned(), DbValue::Null);
    record.insert("id_token".to_owned(), DbValue::Null);
    record.insert("access_token_expires_at".to_owned(), DbValue::Null);
    record.insert("refresh_token_expires_at".to_owned(), DbValue::Null);
    record.insert(
        "scope".to_owned(),
        scope
            .map(|scope| DbValue::String(scope.to_owned()))
            .unwrap_or(DbValue::Null),
    );
    record.insert("password".to_owned(), DbValue::Null);
    record.insert("created_at".to_owned(), DbValue::Timestamp(now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(now));
    record
}

fn create_query(model: &str, record: DbRecord) -> Create {
    record
        .into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
}

async fn contains_record_string(
    adapter: &MemoryAdapter,
    model: &str,
    field: &str,
    value: &str,
) -> Result<bool, OpenAuthError> {
    Ok(adapter
        .find_one(
            FindOne::new(model).where_clause(Where::new(field, DbValue::String(value.to_owned()))),
        )
        .await?
        .is_some())
}

#[derive(Debug)]
struct FakeGoogleProvider;

impl SocialOAuthProvider for FakeGoogleProvider {
    fn id(&self) -> &str {
        "google"
    }

    fn name(&self) -> &str {
        "Google"
    }

    fn provider_options(&self) -> ProviderOptions {
        ProviderOptions {
            client_id: Some("client-id".into()),
            client_secret: Some(
                openauth_oauth::oauth2::ClientSecret::new("client-secret").expect("client secret"),
            ),
            ..ProviderOptions::default()
        }
    }

    fn create_authorization_url(
        &self,
        _input: SocialAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        Url::parse("https://accounts.google.com/o/oauth2/v2/auth").map_err(OAuthError::InvalidUrl)
    }

    fn validate_authorization_code(
        &self,
        _input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async { Ok(OAuth2Tokens::default()) })
    }

    fn get_user_info(
        &self,
        tokens: OAuth2Tokens,
        _provider_user: Option<Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        Box::pin(async move {
            match tokens.id_token.as_deref() {
                Some("valid-id-token") => Ok(Some(OAuth2UserInfo {
                    id: "google_ada".to_owned(),
                    name: Some("Ada Lovelace".to_owned()),
                    email: Some("ada@example.com".to_owned()),
                    image: Some("https://example.com/ada.png".to_owned()),
                    email_verified: true,
                })),
                Some("unverified-id-token") => Ok(Some(OAuth2UserInfo {
                    id: "google_ada".to_owned(),
                    name: Some("Ada Lovelace".to_owned()),
                    email: Some("ada@example.com".to_owned()),
                    image: Some("https://example.com/ada.png".to_owned()),
                    email_verified: false,
                })),
                Some("no-email-token") => Ok(Some(OAuth2UserInfo {
                    id: "google_no_email".to_owned(),
                    name: Some("No Email".to_owned()),
                    email: None,
                    image: None,
                    email_verified: true,
                })),
                _ => Ok(None),
            }
        })
    }

    fn verify_id_token(&self, input: SocialIdTokenRequest) -> SocialProviderFuture<'_, bool> {
        Box::pin(async move {
            Ok(matches!(
                input.token.as_str(),
                "valid-id-token" | "unverified-id-token" | "no-email-token"
            ))
        })
    }
}
