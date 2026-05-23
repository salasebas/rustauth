//! Error types for OpenAuth core.

/// Core library error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenAuthError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid request body: {message}")]
    InvalidRequestBody {
        encoding: &'static str,
        message: String,
    },
    #[error("unsupported request content type `{content_type}`")]
    UnsupportedContentType { content_type: String },
    #[error("unsupported request content type: missing Content-Type")]
    MissingContentType,
    #[error("missing path parameter `{name}`")]
    MissingPathParam { name: String },
    #[error("serialization error while {context}: {message}")]
    Serialization {
        context: &'static str,
        message: String,
    },
    #[error("{context} lock poisoned")]
    LockPoisoned { context: &'static str },
    #[error("{record} record is missing `{field}`")]
    MissingRecordField { record: &'static str, field: String },
    #[error("{record} record field `{field}` must be {expected}")]
    InvalidRecordField {
        record: &'static str,
        field: String,
        expected: &'static str,
    },
    #[error("numeric value out of range: {context}")]
    NumericOutOfRange { context: &'static str },
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid secret configuration: {0}")]
    InvalidSecretConfig(String),
    #[error("password hash error: {0}")]
    PasswordHash(String),
    #[error("cookie error: {0}")]
    Cookie(String),
    #[error("api error: {0}")]
    Api(String),
    #[error("oauth error: {0}")]
    OAuth(String),
    #[error("no request state found in the current async scope")]
    RequestStateMissing,
    #[error("request state value had an unexpected type")]
    RequestStateTypeMismatch,
    #[error("schema table `{table}` was not found")]
    TableNotFound { table: String },
    #[error("schema field `{field}` was not found in table `{table}`")]
    FieldNotFound { table: String, field: String },
    #[error(
        "no foreign key found between base model `{base_model}` and join model `{join_model}`"
    )]
    JoinForeignKeyNotFound {
        base_model: String,
        join_model: String,
    },
    #[error(
        "multiple foreign keys found between base model `{base_model}` and join model `{join_model}`"
    )]
    JoinForeignKeyAmbiguous {
        base_model: String,
        join_model: String,
    },
    #[error("adapter error: {0}")]
    Adapter(String),
}

impl From<openauth_oauth::oauth2::OAuthError> for OpenAuthError {
    fn from(error: openauth_oauth::oauth2::OAuthError) -> Self {
        Self::OAuth(error.to_string())
    }
}
