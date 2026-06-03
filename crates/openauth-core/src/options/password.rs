use std::fmt;
use std::sync::Arc;

use http::Request;

use crate::auth::email_password::{PasswordHashFn, PasswordVerifyFn};
use crate::db::User;
use crate::error::OpenAuthError;

/// Payload passed to password reset lifecycle callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordResetPayload {
    pub user: User,
}

/// Payload passed to the password reset email sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordResetEmail {
    pub user: User,
    pub url: String,
    pub token: String,
}

/// Synchronous password reset email sender hook.
pub trait SendResetPassword: Send + Sync + 'static {
    fn send_reset_password(
        &self,
        payload: PasswordResetEmail,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> SendResetPassword for F
where
    F: for<'a> Fn(PasswordResetEmail, Option<&'a Request<Vec<u8>>>) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn send_reset_password(
        &self,
        payload: PasswordResetEmail,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(payload, request)
    }
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
    pub send_reset_password: Option<Arc<dyn SendResetPassword>>,
    pub reset_password_token_expires_in: Option<u64>,
    pub on_password_reset: Option<Arc<dyn OnPasswordReset>>,
    pub revoke_sessions_on_password_reset: bool,
    pub hash_password: Option<PasswordHashFn>,
    pub verify_password: Option<PasswordVerifyFn>,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            min_password_length: 8,
            max_password_length: 128,
            send_reset_password: None,
            reset_password_token_expires_in: None,
            on_password_reset: None,
            revoke_sessions_on_password_reset: false,
            hash_password: None,
            verify_password: None,
        }
    }
}

impl PasswordOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn min_password_length(mut self, length: usize) -> Self {
        self.min_password_length = length;
        self
    }

    #[must_use]
    pub fn max_password_length(mut self, length: usize) -> Self {
        self.max_password_length = length;
        self
    }

    #[must_use]
    pub fn send_reset_password<S>(mut self, sender: S) -> Self
    where
        S: SendResetPassword,
    {
        self.send_reset_password = Some(Arc::new(sender));
        self
    }

    #[must_use]
    pub fn reset_password_token_expires_in(mut self, seconds: u64) -> Self {
        self.reset_password_token_expires_in = Some(seconds);
        self
    }

    #[must_use]
    pub fn on_password_reset<P>(mut self, handler: P) -> Self
    where
        P: OnPasswordReset,
    {
        self.on_password_reset = Some(Arc::new(handler));
        self
    }

    #[must_use]
    pub fn revoke_sessions_on_password_reset(mut self, enabled: bool) -> Self {
        self.revoke_sessions_on_password_reset = enabled;
        self
    }

    #[must_use]
    pub fn hash_password(mut self, hash: PasswordHashFn) -> Self {
        self.hash_password = Some(hash);
        self
    }

    #[must_use]
    pub fn verify_password(mut self, verify: PasswordVerifyFn) -> Self {
        self.verify_password = Some(verify);
        self
    }
}

impl fmt::Debug for PasswordOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordOptions")
            .field("min_password_length", &self.min_password_length)
            .field("max_password_length", &self.max_password_length)
            .field(
                "send_reset_password",
                &self
                    .send_reset_password
                    .as_ref()
                    .map(|_| "<send-reset-password>"),
            )
            .field(
                "reset_password_token_expires_in",
                &self.reset_password_token_expires_in,
            )
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
