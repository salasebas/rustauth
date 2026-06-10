use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::AuthContext;
use openauth_core::cookies::{delete_session_cookie, verify_cookie_value};
use openauth_core::db::{Create, DbAdapter, DbRecord, DbValue, FindOne, Session, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::DbUserStore;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnonymousUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub is_anonymous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnonymousSession {
    pub session: Session,
    pub user: AnonymousUser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkedSession {
    pub session: Session,
    pub user: AnonymousUser,
}

pub async fn current_anonymous_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    anonymous_field_name: &str,
    cookie_header: String,
) -> Result<Option<AnonymousSession>, OpenAuthError> {
    let Some(result) = SessionAuth::new(adapter, context)
        .get_session(GetSessionInput::new(cookie_header).disable_refresh())
        .await?
    else {
        return Ok(None);
    };
    let Some(session) = result.session else {
        return Ok(None);
    };
    let Some(user) = find_anonymous_user(adapter, anonymous_field_name, &session.user_id).await?
    else {
        return Ok(None);
    };
    Ok(Some(AnonymousSession { session, user }))
}

pub async fn create_anonymous_user(
    adapter: &dyn DbAdapter,
    anonymous_field_name: &str,
    additional_fields: DbRecord,
    id: String,
    name: String,
    email: String,
) -> Result<AnonymousUser, OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    let mut query = Create::new("user")
        .data("id", DbValue::String(id))
        .data("name", DbValue::String(name))
        .data("email", DbValue::String(email.to_lowercase()))
        .data("email_verified", DbValue::Boolean(false))
        .data("image", DbValue::Null)
        .data("created_at", DbValue::Timestamp(now))
        .data("updated_at", DbValue::Timestamp(now));
    for (field, value) in additional_fields {
        query = query.data(field, value);
    }
    let record = adapter
        .create(
            query
                .data(anonymous_field_name, DbValue::Boolean(true))
                .force_allow_id(),
        )
        .await?;
    anonymous_user_from_record(record, anonymous_field_name)
}

pub async fn create_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user_id: &str,
    additional_fields: DbRecord,
) -> Result<Session, OpenAuthError> {
    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(context.session_config.expires_in as i64);
    DbSessionStore::new(adapter)
        .create_session(
            CreateSessionInput::new(user_id, expires_at).additional_fields_with(additional_fields),
        )
        .await
}

pub async fn find_anonymous_user(
    adapter: &dyn DbAdapter,
    anonymous_field_name: &str,
    user_id: &str,
) -> Result<Option<AnonymousUser>, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String(user_id.to_owned()))),
        )
        .await?
        .map(|record| anonymous_user_from_record(record, anonymous_field_name))
        .transpose()
}

pub async fn linked_session_from_token(
    adapter: &dyn DbAdapter,
    anonymous_field_name: &str,
    token: &str,
) -> Result<Option<LinkedSession>, OpenAuthError> {
    let Some(session) = DbSessionStore::new(adapter).find_session(token).await? else {
        return Ok(None);
    };
    let Some(user) = find_anonymous_user(adapter, anonymous_field_name, &session.user_id).await?
    else {
        return Ok(None);
    };
    Ok(Some(LinkedSession { session, user }))
}

pub fn delete_session_cookies(
    context: &AuthContext,
    cookie_header: &str,
) -> Vec<openauth_core::cookies::Cookie> {
    delete_session_cookie(&context.auth_cookies, cookie_header, false)
}

pub fn verified_cookie_value(
    context: &AuthContext,
    value: &str,
) -> Result<Option<String>, OpenAuthError> {
    verify_cookie_value(value, &context.secret)
}

pub async fn delete_anonymous_user_records(
    adapter: &dyn DbAdapter,
    user_id: &str,
) -> Result<(), OpenAuthError> {
    DbSessionStore::new(adapter)
        .delete_user_sessions(user_id)
        .await?;
    DbUserStore::new(adapter)
        .delete_user_accounts(user_id)
        .await?;
    DbUserStore::new(adapter).delete_user(user_id).await
}

fn anonymous_user_from_record(
    record: DbRecord,
    anonymous_field_name: &str,
) -> Result<AnonymousUser, OpenAuthError> {
    Ok(AnonymousUser {
        id: required_string(&record, "id")?.to_owned(),
        name: required_string(&record, "name")?.to_owned(),
        email: required_string(&record, "email")?.to_owned(),
        email_verified: required_bool(&record, "email_verified")?,
        image: optional_string(&record, "image")?,
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
        is_anonymous: optional_bool(&record, "is_anonymous")?
            .or(optional_bool(&record, anonymous_field_name)?)
            .unwrap_or(false),
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn optional_string(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string or null")),
    }
}

fn required_bool(record: &DbRecord, field: &str) -> Result<bool, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "boolean")),
        None => Err(missing_field(field)),
    }
}

fn optional_bool(record: &DbRecord, field: &str) -> Result<Option<bool>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "boolean or null")),
    }
}

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "timestamp")),
        None => Err(missing_field(field)),
    }
}

fn missing_field(field: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("anonymous user record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!(
        "anonymous user record field `{field}` must be {expected}"
    ))
}
