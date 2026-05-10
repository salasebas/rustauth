use std::collections::HashMap;

use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::{create_auth_context, AuthContext};
use openauth_core::cookies::{
    get_cookies, parse_cookies, set_session_cookie, Cookie, SessionCookieOptions,
};
use openauth_core::db::{
    run_transaction_without_native_support, AdapterFuture, Count, Create, DbAdapter, DbRecord,
    DbValue, Delete, DeleteMany, FindMany, FindOne, Session, TransactionCallback, Update,
    UpdateMany, User, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{CookieCacheOptions, OpenAuthOptions, SessionOptions};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

#[derive(Default)]
struct SessionAuthAdapter {
    users: Mutex<HashMap<String, DbRecord>>,
    sessions: Mutex<HashMap<String, DbRecord>>,
    updates: Mutex<Vec<Update>>,
    deletes: Mutex<Vec<Delete>>,
}

impl SessionAuthAdapter {
    async fn insert_user(&self, user: User) {
        self.users
            .lock()
            .await
            .insert(user.id.clone(), user_record(user));
    }

    async fn insert_session(&self, session: Session) {
        self.sessions
            .lock()
            .await
            .insert(session.token.clone(), session_record(session));
    }
}

impl DbAdapter for SessionAuthAdapter {
    fn id(&self) -> &str {
        "session-auth-memory"
    }

    fn create<'a>(&'a self, _query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async {
            Err(OpenAuthError::Adapter(
                "create should not be called".to_owned(),
            ))
        })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            match query.model.as_str() {
                "session" => {
                    let token = string_filter(&query.where_clauses, "token")?;
                    Ok(self.sessions.lock().await.get(token).cloned())
                }
                "user" => {
                    let id = string_filter(&query.where_clauses, "id")?;
                    Ok(self.users.lock().await.get(id).cloned())
                }
                model => Err(OpenAuthError::Adapter(format!(
                    "unexpected find_one model `{model}`"
                ))),
            }
        })
    }

    fn find_many<'a>(&'a self, _query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn count<'a>(&'a self, _query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            self.updates.lock().await.push(query.clone());
            let token = string_filter(&query.where_clauses, "token")?;
            let mut sessions = self.sessions.lock().await;
            let Some(record) = sessions.get_mut(token) else {
                return Ok(None);
            };
            for (key, value) in query.data {
                record.insert(key, value);
            }
            Ok(Some(record.clone()))
        })
    }

    fn update_many<'a>(&'a self, _query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.deletes.lock().await.push(query.clone());
            let token = string_filter(&query.where_clauses, "token")?;
            self.sessions.lock().await.remove(token);
            Ok(())
        })
    }

    fn delete_many<'a>(&'a self, _query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        run_transaction_without_native_support(self, callback)
    }
}

#[tokio::test]
async fn get_session_returns_db_session_with_user_and_sets_cookie_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = SessionAuthAdapter::default();
    let context = context()?;
    let now = OffsetDateTime::now_utc();
    adapter.insert_user(user(now)).await;
    adapter
        .insert_session(session(now, now + Duration::hours(2)))
        .await;
    let cookie_header = session_cookie_header(&context, "token_1", false)?;

    let result = SessionAuth::new(&adapter, &context)
        .get_session(GetSessionInput::new(cookie_header))
        .await?;

    let Some(result) = result else {
        return Err("missing session result".into());
    };
    assert_eq!(
        result
            .session
            .as_ref()
            .map(|session| session.token.as_str()),
        Some("token_1")
    );
    assert_eq!(
        result.user.as_ref().map(|user| user.id.as_str()),
        Some("user_1")
    );
    assert!(result
        .cookies
        .iter()
        .any(|cookie| cookie.name == context.auth_cookies.session_data.name));
    assert!(adapter.updates.lock().await.is_empty());
    Ok(())
}

#[tokio::test]
async fn get_session_refreshes_due_session_and_session_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = SessionAuthAdapter::default();
    let context = context()?;
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::seconds(10);
    adapter.insert_user(user(now)).await;
    adapter.insert_session(session(now, expires_at)).await;
    let cookie_header = session_cookie_header(&context, "token_1", false)?;

    let result = SessionAuth::new(&adapter, &context)
        .get_session(GetSessionInput::new(cookie_header))
        .await?;

    let Some(result) = result else {
        return Err("missing session result".into());
    };
    let Some(session) = result.session.as_ref() else {
        return Err("missing refreshed session".into());
    };
    assert!(session.expires_at > expires_at);
    assert!(result
        .cookies
        .iter()
        .any(|cookie| cookie.name == context.auth_cookies.session_token.name));
    assert_eq!(adapter.updates.lock().await.len(), 1);
    Ok(())
}

#[tokio::test]
async fn get_session_clears_cookies_when_signed_token_is_missing_from_store(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = SessionAuthAdapter::default();
    let context = context()?;
    let cookie_header = session_cookie_header(&context, "missing_token", false)?;

    let result = SessionAuth::new(&adapter, &context)
        .get_session(GetSessionInput::new(cookie_header))
        .await?;

    let Some(result) = result else {
        return Err("missing anonymous result".into());
    };
    assert!(result.session.is_none());
    assert!(result.cookies.iter().any(|cookie| cookie.name
        == context.auth_cookies.session_token.name
        && cookie.attributes.max_age == Some(0)));
    Ok(())
}

#[tokio::test]
async fn sign_out_deletes_session_and_expires_session_cookies(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = SessionAuthAdapter::default();
    let context = context()?;
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let cookie_header = session_cookie_header(&context, "token_1", false)?;

    let result = SessionAuth::new(&adapter, &context)
        .sign_out(cookie_header)
        .await?;

    assert!(result.success);
    assert!(adapter.sessions.lock().await.is_empty());
    assert_eq!(adapter.deletes.lock().await.len(), 1);
    assert!(result.cookies.iter().any(|cookie| cookie.name
        == context.auth_cookies.session_token.name
        && cookie.attributes.max_age == Some(0)));
    Ok(())
}

#[tokio::test]
async fn sign_out_ignores_forged_session_cookie_but_still_expires_cookies(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = SessionAuthAdapter::default();
    let context = context()?;
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let cookie_header = format!("{}=token_1.bad", context.auth_cookies.session_token.name);

    let result = SessionAuth::new(&adapter, &context)
        .sign_out(cookie_header)
        .await?;

    assert!(result.success);
    assert_eq!(adapter.sessions.lock().await.len(), 1);
    assert!(adapter.deletes.lock().await.is_empty());
    assert!(result.cookies.iter().any(|cookie| cookie.name
        == context.auth_cookies.session_token.name
        && cookie.attributes.max_age == Some(0)));
    Ok(())
}

fn context() -> Result<AuthContext, OpenAuthError> {
    create_auth_context(OpenAuthOptions {
        secret: Some("test-secret-123456789012345678901234".to_owned()),
        session: SessionOptions {
            expires_in: Some(60 * 60),
            update_age: Some(1),
            cookie_cache: CookieCacheOptions {
                enabled: true,
                max_age: Some(60 * 5),
                ..CookieCacheOptions::default()
            },
            ..SessionOptions::default()
        },
        ..OpenAuthOptions::default()
    })
}

fn session_cookie_header(
    context: &AuthContext,
    token: &str,
    dont_remember: bool,
) -> Result<String, OpenAuthError> {
    let cookies = set_session_cookie(
        &get_cookies(&context.options)?,
        &context.secret,
        token,
        SessionCookieOptions {
            dont_remember,
            ..SessionCookieOptions::default()
        },
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

fn user(now: OffsetDateTime) -> User {
    User {
        id: "user_1".to_owned(),
        name: "Ada".to_owned(),
        email: "ada@example.com".to_owned(),
        email_verified: true,
        image: None,
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
        ip_address: Some("192.0.2.1".to_owned()),
        user_agent: Some("test-agent".to_owned()),
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
    record.insert(
        "ip_address".to_owned(),
        session
            .ip_address
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
    record.insert(
        "user_agent".to_owned(),
        session
            .user_agent
            .map(DbValue::String)
            .unwrap_or(DbValue::Null),
    );
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

#[allow(dead_code)]
fn parsed_cookie_value(cookies: &[Cookie], name: &str) -> Option<String> {
    parse_cookies(&cookie_header(cookies)).get(name).cloned()
}
