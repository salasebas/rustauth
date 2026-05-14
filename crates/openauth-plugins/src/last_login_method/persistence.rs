use openauth_core::api::ApiRequest;
use openauth_core::context::request_state::current_new_session;
use openauth_core::context::AuthContext;
use openauth_core::db::{DbValue, Update, Where};
use openauth_core::error::OpenAuthError;

use super::config::{LastLoginMethodOptions, DEFAULT_DATABASE_FIELD_NAME};
use super::resolve::LoginMethodContext;

pub async fn persist_last_login_method(
    context: &AuthContext,
    request: &ApiRequest,
    options: &LastLoginMethodOptions,
) -> Result<(), OpenAuthError> {
    if !options.store_in_database {
        return Ok(());
    }
    let Some(adapter) = context.adapter() else {
        return Ok(());
    };
    let Some(new_session) = current_new_session().ok().flatten() else {
        return Ok(());
    };
    let login_context = LoginMethodContext::from_request(context, request);
    let Some(method) = options.resolve_login_method(&login_context) else {
        return Ok(());
    };

    adapter
        .update(
            Update::new("user")
                .where_clause(Where::new("id", DbValue::String(new_session.user.id)))
                .data(DEFAULT_DATABASE_FIELD_NAME, DbValue::String(method)),
        )
        .await?;
    Ok(())
}
