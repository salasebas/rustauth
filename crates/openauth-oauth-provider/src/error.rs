use http::StatusCode;
use openauth_core::error::OpenAuthError;
use serde::Serialize;

/// OAuth provider runtime error.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{error}: {error_description}")]
pub struct OAuthProviderError {
    pub status: StatusCode,
    pub error: String,
    pub error_description: String,
}

impl OAuthProviderError {
    pub fn new(
        status: StatusCode,
        error: impl Into<String>,
        error_description: impl Into<String>,
    ) -> Self {
        Self {
            status,
            error: error.into(),
            error_description: error_description.into(),
        }
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_client", description)
    }

    pub fn unauthorized(description: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", description)
    }

    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_scope", description)
    }

    pub fn access_denied(description: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "access_denied", description)
    }
}

impl From<OAuthProviderError> for OpenAuthError {
    fn from(error: OAuthProviderError) -> Self {
        OpenAuthError::Api(error.to_string())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct OAuthErrorBody<'a> {
    pub error: &'a str,
    pub error_description: &'a str,
}
