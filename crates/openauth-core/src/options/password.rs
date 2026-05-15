use std::fmt;
use std::sync::Arc;

use http::Request;

use crate::db::User;
use crate::error::OpenAuthError;

/// Payload passed to password reset lifecycle callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordResetPayload {
    pub user: User,
}

/// Hook invoked after a password reset has updated or created the credential.
pub trait OnPasswordReset: Send + Sync + 'static {
    fn on_password_reset(
        &self,
        payload: PasswordResetPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> OnPasswordReset for F
where
    F: for<'a> Fn(PasswordResetPayload, Option<&'a Request<Vec<u8>>>) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn on_password_reset(
        &self,
        payload: PasswordResetPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(payload, request)
    }
}

/// Password policy configuration.
#[derive(Clone)]
pub struct PasswordOptions {
    pub min_password_length: usize,
    pub max_password_length: usize,
    pub on_password_reset: Option<Arc<dyn OnPasswordReset>>,
    pub revoke_sessions_on_password_reset: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            min_password_length: 8,
            max_password_length: 128,
            on_password_reset: None,
            revoke_sessions_on_password_reset: false,
        }
    }
}

impl fmt::Debug for PasswordOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordOptions")
            .field("min_password_length", &self.min_password_length)
            .field("max_password_length", &self.max_password_length)
            .field(
                "on_password_reset",
                &self
                    .on_password_reset
                    .as_ref()
                    .map(|_| "<on-password-reset>"),
            )
            .field(
                "revoke_sessions_on_password_reset",
                &self.revoke_sessions_on_password_reset,
            )
            .finish()
    }
}
