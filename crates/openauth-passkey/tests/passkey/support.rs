use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{parse_set_cookie_header, sign_cookie_value};
use openauth_core::crypto::password::hash_password;
use openauth_core::db::{
    AdapterCapabilities, AdapterFuture, Count, Create, DbAdapter, DbRecord, DbSchema, DbValue,
    Delete, DeleteMany, FindMany, FindOne, MemoryAdapter, SchemaCreation, TransactionCallback,
    Update, UpdateMany, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, EmailPasswordOptions, OpenAuthOptions, SessionOptions,
};
use openauth_core::test_utils::MemorySecondaryStorage;

fn with_test_defaults(mut options: OpenAuthOptions) -> OpenAuthOptions {
    if !options.production {
        options.development = true;
    }
    if !options.email_password.enabled {
        options.email_password = EmailPasswordOptions::new().enabled(true);
    }
    options
}
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use openauth_passkey::{
    passkey, PasskeyAuthenticationStart, PasskeyOptions, PasskeyRegistrationStart,
    PasskeyRegistrationUser, PasskeyWebAuthnBackend, RegistrationWebAuthnOptions,
    VerifiedAuthentication, VerifiedPasskeyCredential, WebAuthnConfig,
};
use serde_json::{json, Value};
use time::OffsetDateTime;

pub fn allow_credentials_contains_id(allowed: &[Value], credential_id: &str) -> bool {
    allowed.iter().any(|entry| {
        entry["id"].as_str() == Some(credential_id)
            || entry
                .get("cred")
                .and_then(|cred| cred.get("cred_id"))
                .and_then(Value::as_str)
                == Some(credential_id)
    })
}

pub async fn seeded_router(
    options: PasskeyOptions,
) -> Result<(Arc<MemoryAdapter>, AuthRouter, Arc<FakeWebAuthnBackend>), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user(adapter.as_ref()).await?;
    let backend = Arc::new(FakeWebAuthnBackend::default());
    let context = create_auth_context_with_adapter(
        with_test_defaults(OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![passkey(options.backend(backend.clone()))],
            ..OpenAuthOptions::default()
        }),
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router, backend))
}

/// Build a seeded router with caller-supplied `AdvancedOptions` so tests can
/// exercise cookie naming/attribute policy (prefix, cross-subdomain, defaults).
pub async fn seeded_router_with_advanced(
    options: PasskeyOptions,
    advanced: AdvancedOptions,
) -> Result<(Arc<MemoryAdapter>, AuthRouter, Arc<FakeWebAuthnBackend>), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user(adapter.as_ref()).await?;
    let backend = Arc::new(FakeWebAuthnBackend::default());
    let context = create_auth_context_with_adapter(
        with_test_defaults(OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            advanced,
            plugins: vec![passkey(options.backend(backend.clone()))],
            ..OpenAuthOptions::default()
        }),
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router, backend))
}

/// Build a seeded router with caller-supplied top-level auth options.
pub async fn seeded_router_with_auth_options(
    auth_options: OpenAuthOptions,
    passkey_options: PasskeyOptions,
) -> Result<(Arc<MemoryAdapter>, AuthRouter, Arc<FakeWebAuthnBackend>), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user(adapter.as_ref()).await?;
    let backend = Arc::new(FakeWebAuthnBackend::default());
    let context = create_auth_context_with_adapter(
        with_test_defaults(OpenAuthOptions {
            plugins: vec![passkey(passkey_options.backend(backend.clone()))],
            ..auth_options
        }),
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router, backend))
}

pub type InMemorySecondaryStorage = MemorySecondaryStorage;

/// Build a seeded router that resolves sessions/challenges from secondary storage only.
pub async fn seeded_router_with_secondary_storage(
    options: PasskeyOptions,
    storage: Arc<InMemorySecondaryStorage>,
) -> Result<(Arc<MemoryAdapter>, AuthRouter, Arc<FakeWebAuthnBackend>), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user(adapter.as_ref()).await?;
    let backend = Arc::new(FakeWebAuthnBackend::default());
    let context = create_auth_context_with_adapter(
        with_test_defaults(OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            secondary_storage: Some(storage),
            session: SessionOptions::new().store_session_in_database(false),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![passkey(options.backend(backend.clone()))],
            ..OpenAuthOptions::default()
        }),
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router, backend))
}

pub async fn router_with_adapter<A>(
    adapter: Arc<A>,
    options: PasskeyOptions,
) -> Result<(AuthRouter, Arc<FakeWebAuthnBackend>), Box<dyn std::error::Error>>
where
    A: DbAdapter + 'static,
{
    let backend = Arc::new(FakeWebAuthnBackend::default());
    let context = create_auth_context_with_adapter(
        with_test_defaults(OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![passkey(options.backend(backend.clone()))],
            ..OpenAuthOptions::default()
        }),
        adapter.clone(),
    )?;
    let router =
        AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))?;
    Ok((router, backend))
}

#[derive(Debug, Clone)]
pub struct RaceDuplicateAdapter {
    inner: MemoryAdapter,
    credential_id: String,
    injected: Arc<AtomicBool>,
}

impl RaceDuplicateAdapter {
    pub fn new(credential_id: impl Into<String>) -> Self {
        Self {
            inner: MemoryAdapter::new(),
            credential_id: credential_id.into(),
            injected: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn inner(&self) -> &MemoryAdapter {
        &self.inner
    }
}

/// Simulates passkey revocation between lookup and counter update by deleting
/// the credential row when `update_after_authentication` runs (OPE-128).
#[derive(Debug, Clone)]
pub struct RevokedOnAuthUpdateAdapter {
    inner: MemoryAdapter,
}

impl RevokedOnAuthUpdateAdapter {
    pub fn new() -> Self {
        Self {
            inner: MemoryAdapter::new(),
        }
    }

    pub fn inner(&self) -> &MemoryAdapter {
        &self.inner
    }
}

impl DbAdapter for RevokedOnAuthUpdateAdapter {
    fn id(&self) -> &str {
        "revoked-on-auth-update-memory"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        self.inner.capabilities()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        self.inner.create(query)
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        self.inner.find_one(query)
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        self.inner.find_many(query)
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        self.inner.count(query)
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        if query.model != "passkey" {
            return self.inner.update(query);
        }
        let inner = self.inner.clone();
        Box::pin(async move {
            if let Some(id) = passkey_id_from_update(&query) {
                inner
                    .delete(
                        Delete::new("passkey").where_clause(Where::new("id", DbValue::String(id))),
                    )
                    .await?;
            }
            Ok(None)
        })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        self.inner.update_many(query)
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        self.inner.delete(query)
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        self.inner.delete_many(query)
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        self.inner.transaction(callback)
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a DbSchema,
        file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        self.inner.create_schema(schema, file)
    }
}

fn passkey_id_from_update(query: &Update) -> Option<String> {
    query.where_clauses.iter().find_map(|clause| {
        (clause.field == "id").then(|| match &clause.value {
            DbValue::String(id) => Some(id.clone()),
            _ => None,
        })?
    })
}

impl DbAdapter for RaceDuplicateAdapter {
    fn id(&self) -> &str {
        "race-duplicate-memory"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        self.inner.capabilities()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        let should_inject = query.model == "passkey"
            && query.data.get("credential_id")
                == Some(&DbValue::String(self.credential_id.clone()))
            && !self.injected.swap(true, Ordering::SeqCst);
        if should_inject {
            return Box::pin(async move {
                self.inner.create(query).await?;
                Err(OpenAuthError::Adapter("duplicate key".to_owned()))
            });
        }
        self.inner.create(query)
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        self.inner.find_one(query)
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        self.inner.find_many(query)
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        self.inner.count(query)
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        self.inner.update(query)
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        self.inner.update_many(query)
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        self.inner.delete(query)
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        self.inner.delete_many(query)
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        self.inner.transaction(callback)
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a DbSchema,
        file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        self.inner.create_schema(schema, file)
    }
}

pub fn get_request_with_origin(
    method: Method,
    authority: &str,
    path: &str,
    origin: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://{authority}{path}"));
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    builder.body(Vec::new())
}

pub fn empty_request(
    method: Method,
    path: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Vec::new())
}

pub fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

pub fn json_request_with_origin(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut request = json_request(method, path, body, cookie)?;
    request.headers_mut().insert(
        header::ORIGIN,
        http::HeaderValue::from_static("http://localhost:3000"),
    );
    Ok(request)
}

pub fn set_cookie_values(response: &http::Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

pub fn cookie_header_from_response(response: &http::Response<Vec<u8>>) -> String {
    set_cookie_values(response)
        .iter()
        .filter_map(|value| {
            parse_set_cookie_header(value)
                .into_iter()
                .next()
                .map(|(name, cookie)| format!("{name}={}", cookie.value))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn join_cookies(values: &[&str]) -> String {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("; ")
}

/// Cookie name the passkey plugin derives for the default test configuration
/// (http base URL, default `cookie_prefix`), routed through the core
/// auth-cookie policy.
pub fn passkey_challenge_cookie_name() -> Result<String, Box<dyn std::error::Error>> {
    Ok(openauth_core::cookies::create_auth_cookie(
        &OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        "better-auth-passkey",
        None,
    )?
    .name)
}

pub fn signed_passkey_challenge_cookie(token: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!(
        "{}={}",
        passkey_challenge_cookie_name()?,
        sign_cookie_value(token, "secret-a-at-least-32-chars-long!!")?
    ))
}

pub async fn expired_registration_challenge_cookie(
    adapter: &MemoryAdapter,
) -> Result<String, Box<dyn std::error::Error>> {
    let token = "expired-registration-token";
    DbVerificationStore::new(adapter)
        .create_verification(CreateVerificationInput::new(
            token.to_owned(),
            serde_json::to_string(&json!({
                "kind": "Registration",
                "state": { "kind": "registration-state" },
                "user": {
                    "id": "user_1",
                    "name": "ada@example.com",
                    "display_name": null,
                },
                "context": null,
            }))?,
            OffsetDateTime::now_utc() - time::Duration::seconds(1),
        ))
        .await?;
    signed_passkey_challenge_cookie(token)
}

pub async fn sign_in_cookie(router: &AuthRouter) -> Result<String, Box<dyn std::error::Error>> {
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"password123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(cookie_header_from_response(&response))
}

pub async fn single_verification_expires_at(
    adapter: &dyn DbAdapter,
) -> Result<OffsetDateTime, Box<dyn std::error::Error>> {
    let records = adapter
        .find_many(FindMany::new("verification").limit(1))
        .await?;
    let record = records
        .first()
        .ok_or("expected one verification challenge")?;
    match record.get("expires_at") {
        Some(DbValue::Timestamp(expires_at)) => Ok(*expires_at),
        _ => Err("verification challenge expires_at must be a timestamp".into()),
    }
}

pub async fn session_cookie_for(
    adapter: &MemoryAdapter,
    user_id: &str,
    token: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("session")
                .data("id", DbValue::String(format!("session-{token}")))
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("token", DbValue::String(token.to_owned()))
                .data(
                    "expires_at",
                    DbValue::Timestamp(now + time::Duration::hours(1)),
                )
                .data("ip_address", DbValue::Null)
                .data("user_agent", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    let context = openauth_core::context::create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let cookies = openauth_core::cookies::set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        openauth_core::cookies::SessionCookieOptions::default(),
    )?;
    Ok(cookies
        .into_iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; "))
}

pub async fn session_cookie_for_created_at(
    adapter: &MemoryAdapter,
    user_id: &str,
    token: &str,
    created_at: OffsetDateTime,
) -> Result<String, Box<dyn std::error::Error>> {
    adapter
        .create(
            Create::new("session")
                .data("id", DbValue::String(format!("session-{token}")))
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("token", DbValue::String(token.to_owned()))
                .data(
                    "expires_at",
                    DbValue::Timestamp(OffsetDateTime::now_utc() + time::Duration::hours(1)),
                )
                .data("ip_address", DbValue::Null)
                .data("user_agent", DbValue::Null)
                .data("created_at", DbValue::Timestamp(created_at))
                .data("updated_at", DbValue::Timestamp(created_at))
                .force_allow_id(),
        )
        .await?;
    let context = openauth_core::context::create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let session = openauth_core::db::Session {
        id: format!("session-{token}"),
        user_id: user_id.to_owned(),
        token: token.to_owned(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
        ip_address: None,
        user_agent: None,
        created_at,
        updated_at: created_at,
    };
    let user = openauth_core::db::User {
        id: user_id.to_owned(),
        name: "Ada".to_owned(),
        email: "ada@example.com".to_owned(),
        email_verified: true,
        image: None,
        username: None,
        display_username: None,
        created_at,
        updated_at: created_at,
    };
    let cookies = openauth_core::cookies::set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        openauth_core::cookies::SessionCookieOptions::default(),
    )?;
    let mut headers = cookies
        .into_iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>();
    headers.extend(
        openauth_core::cookies::set_cookie_cache(
            &context.auth_cookies,
            &context.secret,
            &openauth_core::cookies::CookieCachePayload {
                session,
                user,
                updated_at: created_at.unix_timestamp(),
                version: "1".to_owned(),
            },
            context.options.session.cookie_cache.strategy,
            60 * 5,
        )?
        .into_iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value)),
    );
    Ok(headers.join("; "))
}

pub async fn seed_user(adapter: &MemoryAdapter) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_1".to_owned()))
                .data("name", DbValue::String("Ada".to_owned()))
                .data("email", DbValue::String("ada@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("account")
                .data("id", DbValue::String("account_1".to_owned()))
                .data("provider_id", DbValue::String("credential".to_owned()))
                .data("account_id", DbValue::String("user_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .data("access_token", DbValue::Null)
                .data("refresh_token", DbValue::Null)
                .data("id_token", DbValue::Null)
                .data("access_token_expires_at", DbValue::Null)
                .data("refresh_token_expires_at", DbValue::Null)
                .data("scope", DbValue::Null)
                .data("password", DbValue::String(hash_password("password123")?))
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub async fn seed_user_two(adapter: &MemoryAdapter) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_2".to_owned()))
                .data("name", DbValue::String("Grace".to_owned()))
                .data("email", DbValue::String("grace@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

/// Valid base64 COSE public key (ES256 / P-256) used for legacy passkey rows in tests.
pub const LEGACY_TEST_COSE_PUBLIC_KEY: &str = "pQECAyYgASFYIGXtpaEld8K66ClDf+M4cBoQqqN14btbXeEI3kOcCFUdIlggHlLtdXARY/f55A3fnzQbPcm6hgr34Mp8p+nuzQCE0Zw=";

pub async fn seed_legacy_passkey(
    adapter: &MemoryAdapter,
    id: &str,
    user_id: &str,
    name: &str,
    credential_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    adapter
        .create(
            Create::new("passkey")
                .data("id", DbValue::String(id.to_owned()))
                .data("name", DbValue::String(name.to_owned()))
                .data(
                    "public_key",
                    DbValue::String(LEGACY_TEST_COSE_PUBLIC_KEY.to_owned()),
                )
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("credential_id", DbValue::String(credential_id.to_owned()))
                .data("counter", DbValue::Number(0))
                .data("device_type", DbValue::String("singleDevice".to_owned()))
                .data("backed_up", DbValue::Boolean(false))
                .data("transports", DbValue::String("internal".to_owned()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .data("aaguid", DbValue::Null)
                .data("webauthn_credential", DbValue::Null)
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub async fn seed_passkey(
    adapter: &MemoryAdapter,
    id: &str,
    user_id: &str,
    name: &str,
    credential_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    adapter
        .create(
            Create::new("passkey")
                .data("id", DbValue::String(id.to_owned()))
                .data("name", DbValue::String(name.to_owned()))
                .data("public_key", DbValue::String("public-key".to_owned()))
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("credential_id", DbValue::String(credential_id.to_owned()))
                .data("counter", DbValue::Number(0))
                .data("device_type", DbValue::String("singleDevice".to_owned()))
                .data("backed_up", DbValue::Boolean(false))
                .data("transports", DbValue::String("internal".to_owned()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .data("aaguid", DbValue::String("aaguid".to_owned()))
                .data(
                    "webauthn_credential",
                    DbValue::Json(json!({ "id": credential_id })),
                )
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

#[derive(Default)]
pub struct FakeWebAuthnBackend {
    pub registration_users: Mutex<Vec<String>>,
    pub fail_finish_authentication: AtomicBool,
}

impl PasskeyWebAuthnBackend for FakeWebAuthnBackend {
    fn start_registration(
        &self,
        config: WebAuthnConfig,
        user: &PasskeyRegistrationUser,
        exclude_credentials: Vec<Value>,
        request_options: RegistrationWebAuthnOptions,
    ) -> Result<PasskeyRegistrationStart, openauth_core::error::OpenAuthError> {
        self.registration_users
            .lock()
            .map_err(|_| openauth_core::error::OpenAuthError::Adapter("mutex poisoned".to_owned()))?
            .push(user.id.clone());
        let exclude_credentials: Vec<Value> = exclude_credentials
            .into_iter()
            .map(|value| {
                if let Some(id) = value.as_str() {
                    json!({ "type": "public-key", "id": id })
                } else {
                    value
                }
            })
            .collect();
        let mut options = json!({
            "challenge": "registration-challenge",
            "rp": { "id": config.rp_id, "name": config.rp_name },
            "user": {
                "id": user.id,
                "name": user.name,
                "displayName": user.display_name.as_deref().unwrap_or(&user.name),
            },
            "pubKeyCredParams": [],
            "authenticatorSelection": request_options.authenticator_selection.to_json(),
            "excludeCredentials": exclude_credentials,
        });
        if let Some(extensions) = request_options.extensions {
            options["extensions"] = extensions;
        }
        Ok(PasskeyRegistrationStart {
            options,
            state: json!({ "kind": "registration-state" }),
        })
    }

    fn finish_registration(
        &self,
        _config: WebAuthnConfig,
        response: Value,
        _state: Value,
    ) -> Result<VerifiedPasskeyCredential, openauth_core::error::OpenAuthError> {
        let credential_id = response
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("credential-id")
            .to_owned();
        Ok(VerifiedPasskeyCredential {
            credential_id: credential_id.clone(),
            public_key: "public-key".to_owned(),
            counter: 0,
            device_type: "singleDevice".to_owned(),
            backed_up: false,
            transports: Some("internal".to_owned()),
            aaguid: Some("test-aaguid".to_owned()),
            credential: json!({ "id": credential_id }),
        })
    }

    fn start_authentication(
        &self,
        config: WebAuthnConfig,
        credentials: Vec<Value>,
        extensions: Option<Value>,
    ) -> Result<PasskeyAuthenticationStart, openauth_core::error::OpenAuthError> {
        let mut options = json!({
            "challenge": "authentication-challenge",
            "rpId": config.rp_id,
            "userVerification": "preferred",
        });
        if !credentials.is_empty() {
            options["allowCredentials"] = json!(credentials);
        }
        if let Some(extensions) = extensions {
            options["extensions"] = extensions;
        }
        Ok(PasskeyAuthenticationStart {
            options,
            state: json!({ "kind": "authentication-state" }),
        })
    }

    fn finish_authentication(
        &self,
        _config: WebAuthnConfig,
        _response: Value,
        _state: Value,
        _credential: Option<Value>,
    ) -> Result<VerifiedAuthentication, openauth_core::error::OpenAuthError> {
        if self.fail_finish_authentication.load(Ordering::Relaxed) {
            return Err(openauth_core::error::OpenAuthError::Adapter(
                "authentication failed".to_owned(),
            ));
        }
        Ok(VerifiedAuthentication {
            credential: None,
            new_counter: 1,
        })
    }
}
