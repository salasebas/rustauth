use thiserror::Error;

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("missing OAuth provider option `{0}`")]
    MissingOption(&'static str),
    #[error("invalid OAuth URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("OAuth HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("OAuth HTTP request failed with status {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("OAuth error response `{error}`{description}")]
    ErrorResponse {
        error: String,
        description: String,
        uri: Option<String>,
    },
    #[error("missing OAuth token field `{0}`")]
    MissingTokenField(&'static str),
    #[error("invalid OAuth claim `{claim}`: {reason}")]
    InvalidClaim { claim: &'static str, reason: String },
    #[error("unsupported OAuth JWT algorithm `{0}`")]
    UnsupportedAlgorithm(String),
    #[error("invalid OAuth configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid OAuth response: {0}")]
    InvalidResponse(String),
    #[error("invalid OAuth token response: {0}")]
    InvalidTokenResponse(String),
    #[error("invalid OAuth client authentication: {0}")]
    InvalidClientAuthentication(String),
    #[error("invalid OAuth JWKS cache configuration: {0}")]
    JwksCache(String),
    #[error("token verification failed: {0}")]
    TokenVerification(String),
    #[error("JOSE operation failed: {0}")]
    Jose(String),
}

#[cfg(feature = "jose")]
impl From<josekit::JoseError> for OAuthError {
    fn from(error: josekit::JoseError) -> Self {
        Self::Jose(error.to_string())
    }
}

pub(crate) fn oauth_error_description(description: Option<String>) -> String {
    description
        .filter(|value| !value.is_empty())
        .map(|value| format!(": {value}"))
        .unwrap_or_default()
}
