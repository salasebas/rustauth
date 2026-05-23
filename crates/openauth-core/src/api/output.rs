//! Shared API output helpers for core routes and server-side plugins.

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::api::additional_fields::insert_returned_fields;
use crate::context::AuthContext;
use crate::cookies::{
    set_cookie_cache, set_session_cookie, Cookie, CookieCachePayload, CookieOptions,
    SessionCookieOptions,
};
use crate::db::{DbAdapter, DbRecord, DbValue, FindOne, Session, User, Where};
use crate::error::OpenAuthError;

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
) -> Result<SessionUserOutput, OpenAuthError> {
    Ok(SessionUserOutput {
        session: session_output_value(adapter, context, session).await?,
        user: user_output_value(adapter, context, user).await?,
    })
}

pub async fn user_output_value(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
) -> Result<Value, OpenAuthError> {
    if context.options.user.additional_fields.is_empty() {
        return serde_json::to_value(user).map_err(|error| OpenAuthError::Serialization {
            context: "serializing user output",
            message: error.to_string(),
        });
    }
    let record = adapter
        .find_one(
            FindOne::new("user").where_clause(Where::new("id", DbValue::String(user.id.clone()))),
        )
        .await?;
    let mut value = serde_json::to_value(user).map_err(|error| OpenAuthError::Serialization {
        context: "serializing user output",
        message: error.to_string(),
    })?;
    let Some(object) = value.as_object_mut() else {
        return Err(OpenAuthError::Serialization {
            context: "serializing user output",
            message: "expected JSON object".to_owned(),
        });
    };
    if let Some(record) = record {
        insert_returned_fields(object, &context.options.user.additional_fields, &record)?;
    }
    Ok(value)
}

pub async fn session_output_value(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    session: &Session,
) -> Result<Value, OpenAuthError> {
    if context.options.session.additional_fields.is_empty() {
        return serde_json::to_value(session).map_err(|error| OpenAuthError::Serialization {
            context: "serializing session output",
            message: error.to_string(),
        });
    }
    let record = adapter
        .find_one(
            FindOne::new("session")
                .where_clause(Where::new("token", DbValue::String(session.token.clone()))),
        )
        .await?;
    match record {
        Some(record) => session_value_from_record(context, &record, session),
        None => serde_json::to_value(session).map_err(|error| OpenAuthError::Serialization {
            context: "serializing session output",
            message: error.to_string(),
        }),
    }
}

pub fn session_value_from_record(
    context: &AuthContext,
    record: &DbRecord,
    session: &Session,
) -> Result<Value, OpenAuthError> {
    let mut value =
        serde_json::to_value(session).map_err(|error| OpenAuthError::Serialization {
            context: "serializing session output",
            message: error.to_string(),
        })?;
    let Some(object) = value.as_object_mut() else {
        return Err(OpenAuthError::Serialization {
            context: "serializing session output",
            message: "expected JSON object".to_owned(),
        });
    };
    insert_returned_fields(object, &context.options.session.additional_fields, record)?;
    Ok(value)
}

pub fn session_response_cookies(
    context: &AuthContext,
    session: &Session,
    user: &User,
    dont_remember: bool,
) -> Result<Vec<Cookie>, OpenAuthError> {
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
            .unwrap_or(60 * 5);
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
            max_age,
        )?);
    }
    Ok(cookies)
}
