#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use http::{header, Method, Request};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::cookies::Cookie;
use openauth_core::db::{
    run_transaction_without_native_support, AdapterFuture, Count, Create, DbAdapter, DbRecord,
    DbValue, Delete, DeleteMany, FindMany, FindOne, Session, TransactionCallback, Update,
    UpdateMany, User, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, EmailPasswordOptions, OpenAuthOptions};

fn with_test_defaults(mut options: OpenAuthOptions) -> OpenAuthOptions {
    if !options.production {
        options.development = true;
    }
    if !options.email_password.enabled {
        options.email_password = EmailPasswordOptions::new().enabled(true);
    }
    options
}
use time::OffsetDateTime;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct RouteAdapter {
    users: Mutex<HashMap<String, DbRecord>>,
    accounts: Mutex<HashMap<String, DbRecord>>,
    sessions: Mutex<HashMap<String, DbRecord>>,
    verifications: Mutex<HashMap<String, DbRecord>>,
}

impl RouteAdapter {
    pub async fn insert_user(&self, user: User) {
        self.users
            .lock()
            .await
            .insert(user.email.clone(), user_record(user));
    }

    pub async fn insert_user_with_locale(&self, user: User, locale: &str) {
        let mut record = user_record(user.clone());
        record.insert("locale".to_owned(), DbValue::String(locale.to_owned()));
        self.users.lock().await.insert(user.email.clone(), record);
    }

    pub async fn insert_account(&self, record: DbRecord) -> Result<(), OpenAuthError> {
        let id = string_field(&record, "id")?.to_owned();
        self.accounts.lock().await.insert(id, record);
        Ok(())
    }

    pub async fn insert_session(&self, session: Session) {
        self.sessions
            .lock()
            .await
            .insert(session.token.clone(), session_record(session));
    }
}

impl DbAdapter for RouteAdapter {
    fn id(&self) -> &str {
        "route-memory"
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move {
            match query.model.as_str() {
                "user" => {
                    let email = string_field(&query.data, "email")?.to_owned();
                    self.users.lock().await.insert(email, query.data.clone());
                    Ok(query.data)
                }
                "account" => {
                    let id = string_field(&query.data, "id")?.to_owned();
                    self.accounts.lock().await.insert(id, query.data.clone());
                    Ok(query.data)
                }
                "session" => {
                    let token = string_field(&query.data, "token")?.to_owned();
                    self.sessions.lock().await.insert(token, query.data.clone());
                    Ok(query.data)
                }
                "verification" => {
                    let identifier = string_field(&query.data, "identifier")?.to_owned();
                    self.verifications
                        .lock()
                        .await
                        .insert(identifier, query.data.clone());
                    Ok(query.data)
                }
                model => Err(OpenAuthError::Adapter(format!(
                    "unexpected create model `{model}`"
                ))),
            }
        })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            match query.model.as_str() {
                "user" => {
                    if let Ok(email) = string_filter(&query.where_clauses, "email") {
                        return Ok(self.users.lock().await.get(email).cloned());
                    }
                    let id = string_filter(&query.where_clauses, "id")?;
                    Ok(self
                        .users
                        .lock()
                        .await
                        .values()
                        .find(|record| matches!(record.get("id"), Some(DbValue::String(value)) if value == id))
                        .cloned())
                }
                "account" => {
                    let user_id = string_filter(&query.where_clauses, "user_id")?;
                    let provider_id = string_filter(&query.where_clauses, "provider_id")?;
                    Ok(self
                        .accounts
                        .lock()
                        .await
                        .values()
                        .find(|record| {
                            matches!(record.get("user_id"), Some(DbValue::String(value)) if value == user_id)
                                && matches!(record.get("provider_id"), Some(DbValue::String(value)) if value == provider_id)
                        })
                        .cloned())
                }
                "session" => {
                    let token = string_filter(&query.where_clauses, "token")?;
                    Ok(self.sessions.lock().await.get(token).cloned())
                }
                "verification" => {
                    let identifier = string_filter(&query.where_clauses, "identifier")?;
                    Ok(self.verifications.lock().await.get(identifier).cloned())
                }
                model => Err(OpenAuthError::Adapter(format!(
                    "unexpected find_one model `{model}`"
                ))),
            }
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            match query.model.as_str() {
                "account" => {
                    let user_id = string_filter(&query.where_clauses, "user_id")?;
                    Ok(self
                        .accounts
                        .lock()
                        .await
                        .values()
                        .filter(|record| {
                            matches!(record.get("user_id"), Some(DbValue::String(value)) if value == user_id)
                        })
                        .cloned()
                        .collect())
                }
                "session" => {
                    let user_id = string_filter(&query.where_clauses, "user_id")?;
                    Ok(self
                        .sessions
                        .lock()
                        .await
                        .values()
                        .filter(|record| {
                            matches!(record.get("user_id"), Some(DbValue::String(value)) if value == user_id)
                        })
                        .cloned()
                        .collect())
                }
                "verification" => {
                    let identifier = string_filter(&query.where_clauses, "identifier")?;
                    Ok(self
                        .verifications
                        .lock()
                        .await
                        .values()
                        .filter(|record| {
                            matches!(record.get("identifier"), Some(DbValue::String(value)) if value == identifier)
                        })
                        .cloned()
                        .collect())
                }
                _ => Ok(Vec::new()),
            }
        })
    }

    fn count<'a>(&'a self, _query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            let records = match query.model.as_str() {
                "user" => &self.users,
                "account" => &self.accounts,
                "session" => &self.sessions,
                "verification" => &self.verifications,
                model => {
                    return Err(OpenAuthError::Adapter(format!(
                        "unexpected update model `{model}`"
                    )))
                }
            };
            let mut records = records.lock().await;
            let Some((record_key, record)) = records
                .iter_mut()
                .find(|(_, record)| matches_where(record, &query.where_clauses))
                .map(|(key, record)| (key.clone(), record))
            else {
                return Ok(None);
            };
            for (key, value) in query.data.clone() {
                record.insert(key, value);
            }
            let updated = record.clone();
            drop(records);
            if query.model == "user" {
                rekey_user_by_email(&self.users, record_key, &updated).await?;
            }
            Ok(Some(updated))
        })
    }

    fn update_many<'a>(&'a self, _query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            match query.model.as_str() {
                "session" => {
                    let token = string_filter(&query.where_clauses, "token")?;
                    self.sessions.lock().await.remove(token);
                }
                "verification" => {
                    let identifier = string_filter(&query.where_clauses, "identifier")?;
                    self.verifications.lock().await.remove(identifier);
                }
                "account" => {
                    let id = string_filter(&query.where_clauses, "id")?;
                    self.accounts.lock().await.remove(id);
                }
                "user" => {
                    let id = string_filter(&query.where_clauses, "id")?;
                    let mut users = self.users.lock().await;
                    let key = users
                        .iter()
                        .find(|(_, record)| {
                            matches!(record.get("id"), Some(DbValue::String(value)) if value == id)
                        })
                        .map(|(key, _)| key.clone());
                    if let Some(key) = key {
                        users.remove(&key);
                    }
                }
                model => {
                    return Err(OpenAuthError::Adapter(format!(
                        "unexpected delete model `{model}`"
                    )))
                }
            }
            Ok(())
        })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            match query.model.as_str() {
                "session" => {
                    let user_id = string_filter(&query.where_clauses, "user_id")?;
                    let mut sessions = self.sessions.lock().await;
                    let before = sessions.len();
                    sessions.retain(|_, record| {
                        !matches!(record.get("user_id"), Some(DbValue::String(value)) if value == user_id)
                    });
                    Ok((before - sessions.len()) as u64)
                }
                "account" => {
                    let user_id = string_filter(&query.where_clauses, "user_id")?;
                    let mut accounts = self.accounts.lock().await;
                    let before = accounts.len();
                    accounts.retain(|_, record| {
                        !matches!(record.get("user_id"), Some(DbValue::String(value)) if value == user_id)
                    });
                    Ok((before - accounts.len()) as u64)
                }
                _ => Ok(0),
            }
        })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        run_transaction_without_native_support(self, callback)
    }
}

pub fn router_with_options(
    adapter: Arc<RouteAdapter>,
    options: OpenAuthOptions,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context(with_test_defaults(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..options
    }))?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
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

pub fn json_request_with_headers(
    method: Method,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    for (key, value) in headers {
        builder = builder.header(*key, *value);
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

pub fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
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

pub fn user(now: OffsetDateTime) -> User {
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

pub fn session(now: OffsetDateTime, expires_at: OffsetDateTime) -> Session {
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

pub fn credential_account_record(
    user_id: &str,
    password_hash: &str,
    now: OffsetDateTime,
) -> DbRecord {
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

fn matches_where(record: &DbRecord, where_clauses: &[Where]) -> bool {
    where_clauses.iter().all(|where_clause| {
        matches!(
            record.get(&where_clause.field),
            Some(value) if value == &where_clause.value
        )
    })
}

async fn rekey_user_by_email(
    users: &Mutex<HashMap<String, DbRecord>>,
    _old_key: String,
    updated: &DbRecord,
) -> Result<(), OpenAuthError> {
    let id = string_field(updated, "id")?.to_owned();
    let email = string_field(updated, "email")?.to_owned();
    let mut users = users.lock().await;
    let stale_key = users
        .iter()
        .find(
            |(_, record)| matches!(record.get("id"), Some(DbValue::String(value)) if value == &id),
        )
        .map(|(key, _)| key.clone());
    if let Some(stale_key) = stale_key {
        users.remove(&stale_key);
    }
    users.insert(email, updated.clone());
    Ok(())
}

fn string_filter<'a>(where_clauses: &'a [Where], field: &str) -> Result<&'a str, OpenAuthError> {
    where_clauses
        .iter()
        .find_map(|where_clause| {
            match (
                where_clause.field.as_str(),
                where_clause.operator,
                &where_clause.value,
            ) {
                (candidate, WhereOperator::Eq, DbValue::String(value)) if candidate == field => {
                    Some(value.as_str())
                }
                _ => None,
            }
        })
        .ok_or_else(|| OpenAuthError::Adapter(format!("missing {field} filter")))
}

fn string_field<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing string field `{field}`"
        ))),
    }
}
