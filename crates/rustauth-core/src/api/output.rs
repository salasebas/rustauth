//! Shared API output helpers for core routes and server-side plugins.

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::api::additional_fields::{db_value_to_json, insert_returned_fields_http};
use crate::api::http_json::{session_to_http_value, snake_to_camel, user_to_http_value};
use crate::context::AuthContext;
use crate::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions,
};
use crate::db::{filter_output_fields, DbAdapter, DbRecord, DbValue, FindOne, Session, User};
use crate::error::RustAuthError;

#[derive(Debug, Serialize)]
pub struct SessionUserOutput {
    pub session: Value,
    pub user: Value,
}

pub async fn session_user_output(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    session: &Session,
    user: &User,
) -> Result<SessionUserOutput, RustAuthError> {
    Ok(SessionUserOutput {
        session: session_output_value(adapter, context, session).await?,
        user: user_output_value(adapter, context, user).await?,
    })
}

/// Render a user output value from request-supplied additional fields instead
/// of loading them from storage. Used for synthetic duplicate sign-up
/// responses so the payload mirrors a real sign-up without leaking persisted
/// account data.
pub fn user_output_value_from_fields(
    context: &AuthContext,
    user: &User,
    additional_fields: &DbRecord,
) -> Result<Value, RustAuthError> {
    let mut value = user_to_http_value(user)?;
    if context.options.user.additional_fields.is_empty() {
        return Ok(value);
    }
    let Some(object) = value.as_object_mut() else {
        return Err(RustAuthError::Serialization {
            context: "serializing user output",
            message: "expected JSON object".to_owned(),
        });
    };
    insert_returned_fields_http(
        object,
        &context.options.user.additional_fields,
        additional_fields,
    )?;
    Ok(value)
}

pub async fn user_output_value(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
) -> Result<Value, RustAuthError> {
    let users = context.schema().table("user")?;
    let record = adapter
        .find_one(
            FindOne::new(users.model())
                .where_clause(users.where_eq("id", DbValue::String(user.id.clone()))?),
        )
        .await?
        .map(|record| users.map_record(record))
        .transpose()?;
    let mut value = user_to_http_value(user)?;
    let Some(object) = value.as_object_mut() else {
        return Err(RustAuthError::Serialization {
            context: "serializing user output",
            message: "expected JSON object".to_owned(),
        });
    };
    if let Some(record) = record {
        insert_returned_fields_http(object, &context.options.user.additional_fields, &record)?;
        insert_schema_returned_fields(context, "user", object, &record)?;
    }
    Ok(value)
}

pub async fn session_output_value(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    session: &Session,
) -> Result<Value, RustAuthError> {
    let record =
        if let Some(sessions) = context.schema().try_table("session") {
            adapter
                .find_one(FindOne::new(sessions.model()).where_clause(
                    sessions.where_eq("token", DbValue::String(session.token.clone()))?,
                ))
                .await?
                .map(|record| sessions.map_record(record))
                .transpose()?
        } else {
            None
        };
    match record {
        Some(record) => session_value_from_record(context, &record, session),
        None => session_to_http_value(session),
    }
}

pub fn session_value_from_record(
    context: &AuthContext,
    record: &DbRecord,
    session: &Session,
) -> Result<Value, RustAuthError> {
    let mut value = session_to_http_value(session)?;
    let Some(object) = value.as_object_mut() else {
        return Err(RustAuthError::Serialization {
            context: "serializing session output",
            message: "expected JSON object".to_owned(),
        });
    };
    insert_returned_fields_http(object, &context.options.session.additional_fields, record)?;
    insert_schema_returned_fields(context, "session", object, record)?;
    Ok(value)
}

fn insert_schema_returned_fields(
    context: &AuthContext,
    table: &str,
    object: &mut serde_json::Map<String, Value>,
    record: &DbRecord,
) -> Result<(), RustAuthError> {
    let Some(table) = context.db_schema.table(table) else {
        return Ok(());
    };
    for (logical_name, value) in filter_output_fields(record, &table.fields) {
        let http_key = snake_to_camel(&logical_name);
        if object.contains_key(&http_key) || object.contains_key(&logical_name) {
            continue;
        }
        object.insert(http_key, db_value_to_json(&value)?);
    }
    Ok(())
}

pub fn session_response_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
    dont_remember: bool,
) -> Result<Vec<Cookie>, RustAuthError> {
    let mut cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions {
            dont_remember,
            overrides: CookieOptions::default(),
        },
    )?;
    if context.options.session.cookie_cache.enabled {
        let max_age = context
            .options
            .session
            .cookie_cache
            .max_age
            .unwrap_or(time::Duration::minutes(5));
        cookies.extend(set_cookie_cache(
            &context.auth_cookies,
            &context.secret,
            &CookieCachePayload {
                session: session.clone(),
                user: user.clone(),
                updated_at: OffsetDateTime::now_utc().unix_timestamp(),
                version: context
                    .options
                    .session
                    .cookie_cache
                    .version
                    .clone()
                    .unwrap_or_else(|| "1".to_owned()),
            },
            context.options.session.cookie_cache.strategy,
            max_age.whole_seconds() as u64,
        )?);
    }
    Ok(cookies)
}
