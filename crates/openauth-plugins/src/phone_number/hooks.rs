use http::StatusCode;
use openauth_core::api::parse_request_body;
use openauth_core::db::DbValue;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{
    PluginBeforeHookAction, PluginDatabaseBeforeAction, PluginDatabaseBeforeInput,
    PluginDatabaseHook,
};
use serde_json::Value;

use super::errors::{error_response, phone_number_cannot_be_updated};
use super::schema::{PHONE_NUMBER_FIELD, PHONE_NUMBER_VERIFIED_FIELD};

pub(crate) fn block_unsafe_update_user(
    _context: &openauth_core::context::AuthContext,
    request: openauth_core::api::ApiRequest,
) -> Result<PluginBeforeHookAction, OpenAuthError> {
    let body: Value = parse_request_body(&request)?;
    if body
        .get("phoneNumber")
        .or_else(|| body.get(PHONE_NUMBER_FIELD))
        .is_some_and(|value| !value.is_null())
    {
        return Ok(PluginBeforeHookAction::Respond(error_response(
            StatusCode::BAD_REQUEST,
            phone_number_cannot_be_updated(),
        )?));
    }
    Ok(PluginBeforeHookAction::Continue(request))
}

pub(crate) fn reset_verified_when_clearing_phone() -> PluginDatabaseHook {
    PluginDatabaseHook::before_update("phone-number-clear-verification", |_context, mut query| {
        if query.model == "user"
            && matches!(query.data.get(PHONE_NUMBER_FIELD), Some(DbValue::Null))
        {
            query.data.insert(
                PHONE_NUMBER_VERIFIED_FIELD.to_owned(),
                DbValue::Boolean(false),
            );
        }
        Ok(PluginDatabaseBeforeAction::Continue(
            PluginDatabaseBeforeInput::Update(query),
        ))
    })
}
