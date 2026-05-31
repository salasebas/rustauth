use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, ApiErrorResponse, AuthRouter};
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use openauth_core::cookies::Cookie;
use openauth_core::crypto::password::hash_password;
use openauth_core::db::{
    AdapterFuture, Create, DbAdapter, DbRecord, DbValue, FindOne, MemoryAdapter, Session, User,
    Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_core::plugin::{AuthPlugin, PluginPasswordValidationRejection};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

type RouteAdapter = MemoryAdapter;
type UnitFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

trait RouteAdapterSeed {
    fn insert_user(&self, user: User) -> UnitFuture<'_>;
    fn insert_account(&self, record: DbRecord) -> AdapterFuture<'_, ()>;
    fn insert_session(&self, session: Session) -> UnitFuture<'_>;
}

impl RouteAdapterSeed for RouteAdapter {
    fn insert_user(&self, user: User) -> UnitFuture<'_> {
        Box::pin(async move {
            let _ = self.create(create_query("user", user_record(user))).await;
        })
    }

    fn insert_account(&self, record: DbRecord) -> AdapterFuture<'_, ()> {
        Box::pin(async move {
            self.create(create_query("account", record)).await?;
            Ok(())
        })
    }

    fn insert_session(&self, session: Session) -> UnitFuture<'_> {
        Box::pin(async move {
            let _ = self
                .create(create_query("session", session_record(session)))
                .await;
        })
    }
}

#[cfg(feature = "oauth")]
mod account_tokens;
mod change_email;
mod change_password;
mod delete_user;
mod delete_user_callback;
mod email_verification;
mod error_page;
mod get_session;
mod list_accounts;
mod list_sessions;
mod openapi;
mod password_validators;
mod request_password_reset;
mod reset_password;
mod revoke_other_sessions;
mod revoke_session;
mod revoke_sessions;
mod session_ip_metadata;
mod set_password;
mod sign_in_email;
mod sign_out;
mod sign_up_email;
#[cfg(feature = "oauth")]
mod social_oauth;
mod unlink_account;
mod update_session;
mod update_user;
mod verify_password;

fn router(adapter: Arc<RouteAdapter>) -> Result<AuthRouter, OpenAuthError> {
    router_with_options(adapter, OpenAuthOptions::default())
}

fn router_with_options(
    adapter: Arc<RouteAdapter>,
    options: OpenAuthOptions,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(secret().to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..options
        },
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

/// Build a router preserving the caller's `advanced` options, only forcing the
/// CSRF/origin checks off so tests can exercise `advanced.ip_address`.
fn router_with_advanced(
    adapter: Arc<RouteAdapter>,
    options: OpenAuthOptions,
    mut advanced: AdvancedOptions,
) -> Result<AuthRouter, OpenAuthError> {
    advanced.disable_csrf_check = true;
    advanced.disable_origin_check = true;
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(secret().to_owned()),
            advanced,
            ..options
        },
        adapter.clone(),
    )?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn json_request(
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

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let cookies = openauth_core::cookies::set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        openauth_core::cookies::SessionCookieOptions::default(),
    )?;
    Ok(cookie_header(&cookies))
}

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

fn set_cookie_values(response: &http::Response<Vec<u8>>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

fn user(now: OffsetDateTime) -> User {
    User {
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

fn session(now: OffsetDateTime, expires_at: OffsetDateTime) -> Session {
    Session {
        id: "session_1".to_owned(),
        user_id: "user_1".to_owned(),
        expires_at,
        token: "token_1".to_owned(),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
    }
}

fn user_record(user: User) -> DbRecord {
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
    record.insert("created_at".to_owned(), DbValue::Timestamp(user.created_at));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(user.updated_at));
    record
}

fn create_query(model: &str, record: DbRecord) -> Create {
    record
        .into_iter()
        .fold(Create::new(model), |query, (field, value)| {
            query.data(field, value)
        })
}

async fn record_by_string(
    adapter: &RouteAdapter,
    model: &str,
    field: &str,
    value: &str,
) -> Result<Option<DbRecord>, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new(model).where_clause(Where::new(field, DbValue::String(value.to_owned()))),
        )
        .await
}

async fn contains_record_string(
    adapter: &RouteAdapter,
    model: &str,
    field: &str,
    value: &str,
) -> Result<bool, OpenAuthError> {
    Ok(record_by_string(adapter, model, field, value)
        .await?
        .is_some())
}

fn session_record(session: Session) -> DbRecord {
    let mut record = DbRecord::new();
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

fn credential_account_record(user_id: &str, password_hash: &str, now: OffsetDateTime) -> DbRecord {
    let mut record = linked_account_record("account_1", "credential", user_id, user_id, None, now);
    record.insert(
        "password".to_owned(),
        DbValue::String(password_hash.to_owned()),
    );
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

fn string_field<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing string field `{field}`"
        ))),
    }
}

fn rejecting_password_plugin(path: &'static str) -> AuthPlugin {
    AuthPlugin::new("password-validator").with_password_validator(move |_context, input| {
        Box::pin(async move {
            if input.path == path {
                return Err(PluginPasswordValidationRejection::bad_request(
                    "PASSWORD_COMPROMISED",
                    "compromised",
                ));
            }
            Ok(())
        })
    })
}
