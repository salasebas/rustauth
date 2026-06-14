use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::api::additional_fields::json_to_db_value;
use crate::auth::session::{GetSessionInput, GetSessionResult, SessionAuth};
use crate::context::AuthContext;
use crate::db::{DbRecord, DbValue, Session, Update, User, Where};
use crate::error::RustAuthError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::api) struct CurrentSessionInput {
    pub(in crate::api) cookie_header: String,
    pub(in crate::api) disable_cookie_cache: bool,
    pub(in crate::api) disable_refresh: bool,
    pub(in crate::api) defer_refresh: bool,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub(in crate::api) enum UpdateSessionError {
    #[error("body must be an object")]
    BodyMustBeObject,
    #[error("field is not accepted as input")]
    FieldNotInput,
    #[error("invalid session field value")]
    InvalidFieldValue,
    #[error("no fields to update")]
    NoFieldsToUpdate,
    #[error("session was not found")]
    SessionNotFound,
}

#[derive(Debug, thiserror::Error)]
pub(in crate::api) enum UpdateSessionErrorOrRustAuth {
    #[error(transparent)]
    Service(#[from] UpdateSessionError),
    #[error(transparent)]
    RustAuth(#[from] RustAuthError),
}

pub(in crate::api) async fn current_session(
    context: &AuthContext,
    input: CurrentSessionInput,
) -> Result<Option<GetSessionResult>, RustAuthError> {
    let mut session_input = GetSessionInput::new(input.cookie_header);
    if input.disable_cookie_cache {
        session_input = session_input.disable_cookie_cache();
    }
    if input.disable_refresh {
        session_input = session_input.disable_refresh();
    }
    if input.defer_refresh {
        session_input = session_input.defer_refresh();
    }
    SessionAuth::new(context)?.get_session(session_input).await
}

pub(in crate::api) async fn list_sessions(
    context: &AuthContext,
    user: &User,
) -> Result<Vec<Session>, RustAuthError> {
    context.sessions()?.list_user_sessions(&user.id).await
}

pub(in crate::api) async fn revoke_session(
    context: &AuthContext,
    user: &User,
    token: &str,
) -> Result<(), RustAuthError> {
    let store = context.sessions()?;
    if let Some(session) = store.find_session(token).await? {
        if session.user_id == user.id {
            store.delete_session(token).await?;
        }
    }
    Ok(())
}

pub(in crate::api) async fn revoke_sessions(
    context: &AuthContext,
    user: &User,
) -> Result<(), RustAuthError> {
    context.sessions()?.delete_user_sessions(&user.id).await?;
    Ok(())
}

pub(in crate::api) async fn revoke_other_sessions(
    context: &AuthContext,
    current_session: &Session,
    user: &User,
) -> Result<(), RustAuthError> {
    let store = context.sessions()?;
    let sessions = store.list_user_sessions(&user.id).await?;
    for session in sessions {
        if session.token != current_session.token {
            store.delete_session(&session.token).await?;
        }
    }
    Ok(())
}

pub(in crate::api) async fn update_session(
    context: &AuthContext,
    current: &Session,
    body: Value,
) -> Result<DbRecord, UpdateSessionErrorOrRustAuth> {
    let Some(fields) = body.as_object() else {
        return Err(UpdateSessionError::BodyMustBeObject.into());
    };
    update_session_fields(context, current, fields).await
}

async fn update_session_fields(
    context: &AuthContext,
    current: &Session,
    fields: &Map<String, Value>,
) -> Result<DbRecord, UpdateSessionErrorOrRustAuth> {
    let token = DbValue::String(current.token.clone());
    let mut update = if let Some(sessions) = context.schema().try_table("session") {
        Update::new(sessions.model()).where_clause(sessions.where_eq("token", token)?)
    } else {
        Update::new("session").where_clause(Where::new("token", token))
    };
    for (name, value) in fields {
        if is_core_session_field(name) {
            continue;
        }
        let Some(field) = context.options.session.additional_fields.get(name) else {
            continue;
        };
        if !field.input {
            return Err(UpdateSessionError::FieldNotInput.into());
        }
        let Ok(value) = json_to_db_value(name, &field.field_type, value) else {
            return Err(UpdateSessionError::InvalidFieldValue.into());
        };
        update = update.data(name, value);
    }

    if update.data.is_empty() {
        return Err(UpdateSessionError::NoFieldsToUpdate.into());
    }

    update = update.data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()));
    let record = context.adapter_ref()?.update(update).await?;
    let record = if let Some(sessions) = context.schema().try_table("session") {
        record
            .map(|record| sessions.map_record(record))
            .transpose()?
    } else {
        record
    };
    record.ok_or_else(|| UpdateSessionError::SessionNotFound.into())
}

fn is_core_session_field(name: &str) -> bool {
    matches!(
        name,
        "id" | "user_id"
            | "userId"
            | "expires_at"
            | "expiresAt"
            | "token"
            | "ip_address"
            | "ipAddress"
            | "user_agent"
            | "userAgent"
            | "created_at"
            | "createdAt"
            | "updated_at"
            | "updatedAt"
    )
}
