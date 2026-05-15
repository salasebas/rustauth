use http::StatusCode;
use openauth_core::api::{ApiErrorResponse, ApiResponse};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginErrorCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymousError {
    InvalidEmailFormat,
    FailedToCreateUser,
    CouldNotCreateSession,
    AnonymousUsersCannotSignInAgainAnonymously,
    FailedToDeleteAnonymousUser,
    UserIsNotAnonymous,
    DeleteAnonymousUserDisabled,
}

pub const ANONYMOUS_ERROR_CODES: &[(&str, &str)] = &[
    (
        "INVALID_EMAIL_FORMAT",
        "Email was not generated in a valid format",
    ),
    ("FAILED_TO_CREATE_USER", "Failed to create user"),
    ("COULD_NOT_CREATE_SESSION", "Could not create session"),
    (
        "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
        "Anonymous users cannot sign in again anonymously",
    ),
    (
        "FAILED_TO_DELETE_ANONYMOUS_USER",
        "Failed to delete anonymous user",
    ),
    ("USER_IS_NOT_ANONYMOUS", "User is not anonymous"),
    (
        "DELETE_ANONYMOUS_USER_DISABLED",
        "Deleting anonymous users is disabled",
    ),
];

impl AnonymousError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidEmailFormat => "INVALID_EMAIL_FORMAT",
            Self::FailedToCreateUser => "FAILED_TO_CREATE_USER",
            Self::CouldNotCreateSession => "COULD_NOT_CREATE_SESSION",
            Self::AnonymousUsersCannotSignInAgainAnonymously => {
                "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"
            }
            Self::FailedToDeleteAnonymousUser => "FAILED_TO_DELETE_ANONYMOUS_USER",
            Self::UserIsNotAnonymous => "USER_IS_NOT_ANONYMOUS",
            Self::DeleteAnonymousUserDisabled => "DELETE_ANONYMOUS_USER_DISABLED",
        }
    }

    pub fn message(self) -> &'static str {
        ANONYMOUS_ERROR_CODES
            .iter()
            .find_map(|(code, message)| (*code == self.code()).then_some(*message))
            .unwrap_or("Anonymous plugin error")
    }
}

pub fn error_codes() -> Vec<PluginErrorCode> {
    ANONYMOUS_ERROR_CODES
        .iter()
        .map(|(code, message)| PluginErrorCode::new(*code, *message))
        .collect()
}

pub fn error_response(
    status: StatusCode,
    error: AnonymousError,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(&ApiErrorResponse {
        code: error.code().to_owned(),
        message: error.message().to_owned(),
        original_message: None,
    })
    .map_err(|err| OpenAuthError::Api(err.to_string()))?;

    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|err| OpenAuthError::Api(err.to_string()))
}
