use std::fmt;
use std::sync::Arc;

use http::Request;

use crate::db::User;
use crate::error::OpenAuthError;

/// Payload passed to an email verification sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationEmail {
    pub user: User,
    pub url: String,
    pub token: String,
}

/// Synchronous email verification sender hook.
pub trait SendVerificationEmail: Send + Sync + 'static {
    fn send_verification_email(
        &self,
        email: VerificationEmail,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> SendVerificationEmail for F
where
    F: for<'a> Fn(VerificationEmail, Option<&'a Request<Vec<u8>>>) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn send_verification_email(
        &self,
        email: VerificationEmail,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(email, request)
    }
}

/// Payload passed to email verification lifecycle callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailVerificationCallbackPayload {
    pub user: User,
}

/// Hook invoked before an email is marked as verified or changed.
pub trait BeforeEmailVerification: Send + Sync + 'static {
    fn before_email_verification(
        &self,
        payload: EmailVerificationCallbackPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> BeforeEmailVerification for F
where
    F: for<'a> Fn(
            EmailVerificationCallbackPayload,
            Option<&'a Request<Vec<u8>>>,
        ) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn before_email_verification(
        &self,
        payload: EmailVerificationCallbackPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(payload, request)
    }
}

/// Hook invoked after an email is marked as verified or changed.
pub trait AfterEmailVerification: Send + Sync + 'static {
    fn after_email_verification(
        &self,
        payload: EmailVerificationCallbackPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> AfterEmailVerification for F
where
    F: for<'a> Fn(
            EmailVerificationCallbackPayload,
            Option<&'a Request<Vec<u8>>>,
        ) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn after_email_verification(
        &self,
        payload: EmailVerificationCallbackPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(payload, request)
    }
}

/// Email verification configuration.
#[derive(Clone, Default)]
pub struct EmailVerificationOptions {
    pub send_verification_email: Option<Arc<dyn SendVerificationEmail>>,
    pub before_email_verification: Option<Arc<dyn BeforeEmailVerification>>,
    pub after_email_verification: Option<Arc<dyn AfterEmailVerification>>,
    pub expires_in: Option<u64>,
    pub auto_sign_in_after_verification: bool,
}

impl fmt::Debug for EmailVerificationOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailVerificationOptions")
            .field(
                "send_verification_email",
                &self
                    .send_verification_email
                    .as_ref()
                    .map(|_| "<send-verification-email>"),
            )
            .field(
                "before_email_verification",
                &self
                    .before_email_verification
                    .as_ref()
                    .map(|_| "<before-email-verification>"),
            )
            .field(
                "after_email_verification",
                &self
                    .after_email_verification
                    .as_ref()
                    .map(|_| "<after-email-verification>"),
            )
            .field("expires_in", &self.expires_in)
            .field(
                "auto_sign_in_after_verification",
                &self.auto_sign_in_after_verification,
            )
            .finish()
    }
}
