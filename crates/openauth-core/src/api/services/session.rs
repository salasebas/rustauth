use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::api::additional_fields::json_to_db_value;
use crate::auth::session::{GetSessionInput, GetSessionResult, SessionAuth};
use crate::context::AuthContext;
use crate::db::{DbAdapter, DbRecord, DbValue, Session, Update, User, Where};
use crate::error::OpenAuthError;
use crate::session::SessionStore;

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
pub(in crate::api) enum UpdateSessionErrorOrOpenAuth {
    #[error(transparent)]
    Service(#[from] UpdateSessionError),
    #[error(transparent)]
    OpenAuth(#[from] OpenAuthError),
}

pub(in crate::api) async fn current_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    input: CurrentSessionInput,
) -> Result<Option<GetSessionResult>, OpenAuthError> {
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
    SessionAuth::new(adapter, context)
        .get_session(session_input)
        .await
}

pub(in crate::api) async fn list_sessions(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
) -> Result<Vec<Session>, OpenAuthError> {
    SessionStore::new(adapter, context)
        .list_user_sessions(&user.id)
        .await
}

pub(in crate::api) async fn revoke_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
    token: &str,
) -> Result<(), OpenAuthError> {
    let store = SessionStore::new(adapter, context);
    if let Some(session) = store.find_session(token).await? {
        if session.user_id == user.id {
            store.delete_session(token).await?;
        }
    }
    Ok(())
}

pub(in crate::api) async fn revoke_sessions(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
) -> Result<(), OpenAuthError> {
    SessionStore::new(adapter, context)
        .delete_user_sessions(&user.id)
        .await?;
    Ok(())
}

pub(in crate::api) async fn revoke_other_sessions(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    current_session: &Session,
    user: &User,
) -> Result<(), OpenAuthError> {
    let store = SessionStore::new(adapter, context);
    let sessions = store.list_user_sessions(&user.id).await?;
    for session in sessions {
        if session.token != current_session.token {
            store.delete_session(&session.token).await?;
        }
    }
    Ok(())
}

pub(in crate::api) async fn update_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    current: &Session,
    body: Value,
) -> Result<DbRecord, UpdateSessionErrorOrOpenAuth> {
    let Some(fields) = body.as_object() else {
        return Err(UpdateSessionError::BodyMustBeObject.into());
    };
    update_session_fields(adapter, context, current, fields).await
}

async fn update_session_fields(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    current: &Session,
    fields: &Map<String, Value>,
) -> Result<DbRecord, UpdateSessionErrorOrOpenAuth> {
    let mut update = Update::new("session")
        .where_clause(Where::new("token", DbValue::String(current.token.clone())));
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
    adapter
        .update(update)
        .await?
        .ok_or_else(|| UpdateSessionError::SessionNotFound.into())
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
