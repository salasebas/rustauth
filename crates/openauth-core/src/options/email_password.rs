use std::fmt;
use std::sync::Arc;

use http::Request;

use crate::db::User;
use crate::error::OpenAuthError;

/// Payload passed when an existing user attempts email/password sign-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingUserSignUpPayload {
    pub user: User,
}

/// Hook invoked for protected duplicate sign-up attempts.
pub trait OnExistingUserSignUp: Send + Sync + 'static {
    fn on_existing_user_sign_up(
        &self,
        payload: ExistingUserSignUpPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> OnExistingUserSignUp for F
where
    F: for<'a> Fn(
            ExistingUserSignUpPayload,
            Option<&'a Request<Vec<u8>>>,
        ) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn on_existing_user_sign_up(
        &self,
        payload: ExistingUserSignUpPayload,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(payload, request)
    }
}

/// Email/password authentication configuration.
#[derive(Clone)]
pub struct EmailPasswordOptions {
    pub enabled: bool,
    pub disable_sign_up: bool,
    pub auto_sign_in: bool,
    pub require_email_verification: bool,
    pub on_existing_user_sign_up: Option<Arc<dyn OnExistingUserSignUp>>,
    pub another_email_error_on_duplicate: bool,
}

impl Default for EmailPasswordOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            disable_sign_up: false,
            auto_sign_in: true,
            require_email_verification: false,
            on_existing_user_sign_up: None,
            another_email_error_on_duplicate: false,
        }
    }
}

impl EmailPasswordOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    #[must_use]
    pub fn disable_sign_up(mut self, disabled: bool) -> Self {
        self.disable_sign_up = disabled;
        self
    }

    #[must_use]
    pub fn auto_sign_in(mut self, enabled: bool) -> Self {
        self.auto_sign_in = enabled;
        self
    }

    #[must_use]
    pub fn require_email_verification(mut self, required: bool) -> Self {
        self.require_email_verification = required;
        self
    }

    #[must_use]
    pub fn on_existing_user_sign_up<H>(mut self, handler: H) -> Self
    where
        H: OnExistingUserSignUp,
    {
        self.on_existing_user_sign_up = Some(Arc::new(handler));
        self
    }

    #[must_use]
    pub fn another_email_error_on_duplicate(mut self, enabled: bool) -> Self {
        self.another_email_error_on_duplicate = enabled;
        self
    }
}

impl fmt::Debug for EmailPasswordOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailPasswordOptions")
            .field("enabled", &self.enabled)
            .field("disable_sign_up", &self.disable_sign_up)
            .field("auto_sign_in", &self.auto_sign_in)
            .field(
                "require_email_verification",
                &self.require_email_verification,
            )
            .field(
                "on_existing_user_sign_up",
                &self
                    .on_existing_user_sign_up
                    .as_ref()
                    .map(|_| "<on-existing-user-sign-up>"),
            )
            .finish()
    }
}
