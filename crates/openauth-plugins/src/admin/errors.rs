use http::StatusCode;
use openauth_core::api::{ApiErrorResponse, ApiResponse};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginErrorCode;

pub const ADMIN_ERROR_CODES: &[&str] = &[
    "FAILED_TO_CREATE_USER",
    "USER_ALREADY_EXISTS",
    "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
    "YOU_CANNOT_BAN_YOURSELF",
    "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
    "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS",
    "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS",
    "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS",
    "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
    "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
    "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
    "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
    "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
    "BANNED_USER",
    "YOU_ARE_NOT_ALLOWED_TO_GET_USER",
    "NO_DATA_TO_UPDATE",
    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
    "YOU_CANNOT_REMOVE_YOURSELF",
    "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE",
    "YOU_CANNOT_IMPERSONATE_ADMINS",
    "INVALID_ROLE_TYPE",
];

macro_rules! code {
    ($fn_name:ident, $code:literal, $message:literal) => {
        pub fn $fn_name() -> PluginErrorCode {
            PluginErrorCode::new($code, $message)
        }
    };
}

code!(
    failed_to_create_user,
    "FAILED_TO_CREATE_USER",
    "Failed to create user"
);
code!(
    user_already_exists,
    "USER_ALREADY_EXISTS",
    "User already exists."
);
code!(
    cannot_ban_yourself,
    "YOU_CANNOT_BAN_YOURSELF",
    "You cannot ban yourself"
);
code!(
    not_allowed_to_change_role,
    "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE",
    "You are not allowed to change users role"
);
code!(
    not_allowed_to_create_users,
    "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS",
    "You are not allowed to create users"
);
code!(
    not_allowed_to_list_users,
    "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS",
    "You are not allowed to list users"
);
code!(
    not_allowed_to_list_sessions,
    "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS",
    "You are not allowed to list users sessions"
);
code!(
    not_allowed_to_ban_users,
    "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS",
    "You are not allowed to ban users"
);
code!(
    not_allowed_to_impersonate_users,
    "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS",
    "You are not allowed to impersonate users"
);
code!(
    not_allowed_to_revoke_sessions,
    "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS",
    "You are not allowed to revoke users sessions"
);
code!(
    not_allowed_to_delete_users,
    "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS",
    "You are not allowed to delete users"
);
code!(
    not_allowed_to_set_password,
    "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD",
    "You are not allowed to set users password"
);
code!(
    not_allowed_to_get_user,
    "YOU_ARE_NOT_ALLOWED_TO_GET_USER",
    "You are not allowed to get user"
);
code!(no_data_to_update, "NO_DATA_TO_UPDATE", "No data to update");
code!(
    not_allowed_to_update_users,
    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS",
    "You are not allowed to update users"
);
code!(
    cannot_remove_yourself,
    "YOU_CANNOT_REMOVE_YOURSELF",
    "You cannot remove yourself"
);
code!(
    not_allowed_to_set_unknown_role,
    "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE",
    "You are not allowed to set a non-existent role value"
);
code!(
    cannot_impersonate_admins,
    "YOU_CANNOT_IMPERSONATE_ADMINS",
    "You cannot impersonate admins"
);
code!(invalid_role_type, "INVALID_ROLE_TYPE", "Invalid role type");

pub fn user_already_exists_use_another_email() -> PluginErrorCode {
    PluginErrorCode::new(
        "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
        "User already exists. Use another email.",
    )
}

pub fn banned_user(message: &str) -> PluginErrorCode {
    PluginErrorCode::new("BANNED_USER", message)
}

pub fn error_response(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(&ApiErrorResponse {
        code: code.into(),
        message: message.into(),
        original_message: None,
    })
    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub fn forbidden(error: PluginErrorCode) -> Result<ApiResponse, OpenAuthError> {
    error_response(StatusCode::FORBIDDEN, error.code, error.message)
}

pub fn bad_request(error: PluginErrorCode) -> Result<ApiResponse, OpenAuthError> {
    error_response(StatusCode::BAD_REQUEST, error.code, error.message)
}

pub fn unauthorized() -> Result<ApiResponse, OpenAuthError> {
    error_response(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized")
}

pub fn not_found_user() -> Result<ApiResponse, OpenAuthError> {
    error_response(StatusCode::NOT_FOUND, "USER_NOT_FOUND", "User not found")
}
