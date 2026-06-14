use rustauth_core::context::AuthContext;
use rustauth_core::db::{DbRecord, DbValue};
use rustauth_core::error::RustAuthError;

pub fn anonymous_user_create_values(
    context: &AuthContext,
    anonymous_field_name: &str,
) -> Result<DbRecord, RustAuthError> {
    let mut values = DbRecord::new();
    for (name, field) in &context.options.user.additional_fields {
        let storage_name = field.db_name.as_deref().unwrap_or(name).to_owned();
        if let Some(value) = &field.default_value {
            values.insert(storage_name, value.clone());
        } else if field.required {
            return Err(RustAuthError::Api(format!(
                "missing default value for required anonymous user field `{name}`"
            )));
        } else {
            values.insert(storage_name, DbValue::Null);
        }
    }
    values.insert(anonymous_field_name.to_owned(), DbValue::Boolean(true));
    Ok(values)
}

pub fn anonymous_session_create_values(context: &AuthContext) -> DbRecord {
    context
        .options
        .session
        .additional_fields
        .iter()
        .map(|(name, field)| {
            (
                field.db_name.clone().unwrap_or_else(|| name.clone()),
                field.default_value.clone().unwrap_or(DbValue::Null),
            )
        })
        .collect()
}
