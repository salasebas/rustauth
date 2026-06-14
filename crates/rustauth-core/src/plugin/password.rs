//! Password validation plugin contracts.

use crate::context::AuthContext;
use http::StatusCode;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type PluginPasswordValidatorFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), PluginPasswordValidationRejection>> + Send + 'a>>;

pub type PluginPasswordValidatorHandler = Arc<
    dyn for<'a> Fn(
            &'a AuthContext,
            PluginPasswordValidationInput,
        ) -> PluginPasswordValidatorFuture<'a>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginPasswordValidationInput {
    pub path: String,
    pub password: String,
}

impl PluginPasswordValidationInput {
    pub fn new(path: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            password: password.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginPasswordValidationRejection {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

impl PluginPasswordValidationRejection {
    pub fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn internal_server_error(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "INTERNAL_SERVER_ERROR".to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Clone)]
pub struct PluginPasswordValidator {
    pub handler: PluginPasswordValidatorHandler,
}

impl std::fmt::Debug for PluginPasswordValidator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PluginPasswordValidator")
            .field("handler", &"<password-validator>")
            .finish()
    }
}
