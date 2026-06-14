use rustauth_core::api::output::user_output_value;
use rustauth_core::context::AuthContext;
use rustauth_core::db::{DbRecord, DbValue, User};
use rustauth_core::error::RustAuthError;
use serde_json::Value;

pub(crate) fn additional_user_create_values(context: &AuthContext) -> DbRecord {
    context
        .options
        .user
        .additional_fields
        .iter()
        .map(|(name, field)| {
            (
                name.clone(),
                field.default_value.clone().unwrap_or(DbValue::Null),
            )
        })
        .collect()
}

pub(crate) async fn user_response_value(
    context: &AuthContext,
    user: &User,
) -> Result<Value, RustAuthError> {
    user_output_value(context.adapter_ref()?, context, user).await
}
