use http::{header, Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AuthEndpointOptions, BodyField, BodySchema,
    JsonSchemaType,
};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::AuthContext;
use openauth_core::db::{DbAdapter, User};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginEndpoint;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::device_authorization::errors::{oauth_error_response, OAuthDeviceError};
use crate::device_authorization::routes::token::required_adapter;
use crate::device_authorization::store::{
    DeviceAuthorizationStatus, DeviceCodeRecord, DeviceCodeStore,
};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeviceApprovalRequest {
    #[serde(rename = "userCode")]
    pub user_code: String,
}

pub fn device_approve() -> PluginEndpoint {
    decision_endpoint("/device/approve", "deviceApprove", Decision::Approve)
}

pub fn device_deny() -> PluginEndpoint {
    decision_endpoint("/device/deny", "deviceDeny", Decision::Deny)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Approve,
    Deny,
}

fn decision_endpoint(
    path: &'static str,
    operation_id: &'static str,
    decision: Decision,
) -> PluginEndpoint {
    create_auth_endpoint(
        path,
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id(operation_id)
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .openapi(super::openapi::device_decision_operation(
                operation_id,
                match decision {
                    Decision::Approve => {
                        "Approve a pending OAuth 2.0 device authorization request."
                    }
                    Decision::Deny => "Deny a pending OAuth 2.0 device authorization request.",
                },
            ))
            .body_schema(BodySchema::object([BodyField::new(
                "userCode",
                JsonSchemaType::String,
            )])),
        move |context, request| {
            Box::pin(async move {
                let adapter = required_adapter(context)?;
                let Some(user) = authenticated_user(context, adapter.as_ref(), &request).await?
                else {
                    return oauth_error_response(
                        StatusCode::UNAUTHORIZED,
                        OAuthDeviceError::Unauthorized,
                        "Authentication required",
                    );
                };
                let body = parse_request_body::<DeviceApprovalRequest>(&request)?;
                let clean = super::clean_user_code(&body.user_code);
                let store = DeviceCodeStore::new(adapter.as_ref());
                let Some(record) = store.find_by_user_code(&clean).await? else {
                    return oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::InvalidRequest,
                        "Invalid user code",
                    );
                };
                if record.expires_at < OffsetDateTime::now_utc() {
                    return oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::ExpiredToken,
                        "User code has expired",
                    );
                }
                if record.status != DeviceAuthorizationStatus::Pending {
                    return oauth_error_response(
                        StatusCode::BAD_REQUEST,
                        OAuthDeviceError::InvalidRequest,
                        "Device code already processed",
                    );
                }
                if record
                    .user_id
                    .as_ref()
                    .is_some_and(|user_id| user_id != &user.id)
                {
                    return oauth_error_response(
                        StatusCode::FORBIDDEN,
                        OAuthDeviceError::AccessDenied,
                        "You are not authorized to process this device authorization",
                    );
                }
                apply_decision(&store, &record, &user, decision).await?;
                super::json_response(StatusCode::OK, &super::SuccessResponse { success: true })
            })
        },
    )
}

async fn authenticated_user(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    request: &openauth_core::api::ApiRequest,
) -> Result<Option<User>, OpenAuthError> {
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let Some(result) = SessionAuth::new(adapter, context)
        .get_session(GetSessionInput::new(cookie_header).disable_refresh())
        .await?
    else {
        return Ok(None);
    };
    Ok(result.user)
}

async fn apply_decision(
    store: &DeviceCodeStore<'_>,
    record: &DeviceCodeRecord,
    user: &User,
    decision: Decision,
) -> Result<(), OpenAuthError> {
    match decision {
        Decision::Approve => {
            store.approve(&record.id, &user.id).await?;
        }
        Decision::Deny => {
            store.deny(&record.id, &user.id).await?;
        }
    }
    Ok(())
}
