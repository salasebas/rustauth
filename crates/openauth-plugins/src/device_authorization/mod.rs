//! OAuth 2.0 device authorization plugin.

mod errors;
mod options;
mod routes;
mod schema;
mod store;

use std::sync::Arc;

use openauth_core::plugin::AuthPlugin;

pub use errors::{
    ACCESS_DENIED, AUTHENTICATION_REQUIRED, AUTHORIZATION_PENDING, DEVICE_CODE_ALREADY_PROCESSED,
    EXPIRED_DEVICE_CODE, EXPIRED_USER_CODE, FAILED_TO_CREATE_SESSION, INVALID_DEVICE_CODE,
    INVALID_DEVICE_CODE_STATUS, INVALID_USER_CODE, POLLING_TOO_FREQUENTLY, USER_NOT_FOUND,
};
pub use options::{
    DeviceAuthorizationOptions, DeviceAuthorizationOptionsError, DeviceAuthorizationSchemaFields,
    DeviceAuthorizationSchemaOptions,
};
pub use routes::{
    DeviceApprovalRequest, DeviceCodeRequest, DeviceCodeResponse, DeviceTokenRequest,
    DeviceTokenResponse, DeviceVerificationResponse,
};
pub use store::{DeviceAuthorizationStatus, DeviceCodeRecord};

pub const UPSTREAM_PLUGIN_ID: &str = "device-authorization";

/// Build the device authorization plugin with default options.
#[must_use]
pub fn device_authorization() -> AuthPlugin {
    device_authorization_with(DeviceAuthorizationOptions::default())
}

/// Build the device authorization plugin with explicit options.
#[must_use]
pub fn device_authorization_with(options: DeviceAuthorizationOptions) -> AuthPlugin {
    let schema_options = options.schema.clone();
    let options = Arc::new(options);
    let init_options = Arc::clone(&options);
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_init(move |_context| {
            init_options.validate().map_err(|error| {
                openauth_core::error::OpenAuthError::InvalidConfig(error.to_string())
            })?;
            Ok(Default::default())
        })
        .with_schema(schema::device_code_table(&schema_options))
        .with_endpoint(routes::device_code(Arc::clone(&options)))
        .with_endpoint(routes::device_token(Arc::clone(&options)))
        .with_endpoint(routes::device_verify())
        .with_endpoint(routes::device_approve())
        .with_endpoint(routes::device_deny())
        .with_error_code(errors::plugin_error_code(
            INVALID_DEVICE_CODE,
            "Invalid device code",
        ))
        .with_error_code(errors::plugin_error_code(
            EXPIRED_DEVICE_CODE,
            "Device code has expired",
        ))
        .with_error_code(errors::plugin_error_code(
            EXPIRED_USER_CODE,
            "User code has expired",
        ))
        .with_error_code(errors::plugin_error_code(
            AUTHORIZATION_PENDING,
            "Authorization pending",
        ))
        .with_error_code(errors::plugin_error_code(ACCESS_DENIED, "Access denied"))
        .with_error_code(errors::plugin_error_code(
            INVALID_USER_CODE,
            "Invalid user code",
        ))
        .with_error_code(errors::plugin_error_code(
            DEVICE_CODE_ALREADY_PROCESSED,
            "Device code already processed",
        ))
        .with_error_code(errors::plugin_error_code(
            POLLING_TOO_FREQUENTLY,
            "Polling too frequently",
        ))
        .with_error_code(errors::plugin_error_code(USER_NOT_FOUND, "User not found"))
        .with_error_code(errors::plugin_error_code(
            FAILED_TO_CREATE_SESSION,
            "Failed to create session",
        ))
        .with_error_code(errors::plugin_error_code(
            INVALID_DEVICE_CODE_STATUS,
            "Invalid device code status",
        ))
        .with_error_code(errors::plugin_error_code(
            AUTHENTICATION_REQUIRED,
            "Authentication required",
        ))
}
