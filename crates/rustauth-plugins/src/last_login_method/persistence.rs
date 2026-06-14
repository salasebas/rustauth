use rustauth_core::api::ApiRequest;
use rustauth_core::context::request_state::current_new_session;
use rustauth_core::context::AuthContext;
use rustauth_core::db::DbValue;
use rustauth_core::error::RustAuthError;
use rustauth_core::user::UpdateUserInput;

use super::config::{LastLoginMethodOptions, DEFAULT_DATABASE_FIELD_NAME};
use super::resolve::LoginMethodContext;

pub async fn persist_last_login_method(
    context: &AuthContext,
    request: &ApiRequest,
    options: &LastLoginMethodOptions,
) -> Result<(), RustAuthError> {
    if !options.store_in_database {
        return Ok(());
    }
    if context.adapter().is_none() {
        return Ok(());
    }
    let Some(new_session) = current_new_session().ok().flatten() else {
        return Ok(());
    };
    let login_context = LoginMethodContext::from_request(context, request);
    let Some(method) = options.resolve_login_method(&login_context) else {
        return Ok(());
    };

    let mut additional_fields = rustauth_core::db::DbRecord::new();
    additional_fields.insert(
        DEFAULT_DATABASE_FIELD_NAME.to_owned(),
        DbValue::String(method),
    );
    context
        .users()?
        .update_user(
            &new_session.user.id,
            UpdateUserInput::new().additional_fields(additional_fields),
        )
        .await?;
    Ok(())
}
