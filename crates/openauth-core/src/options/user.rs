use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use http::Request;

use super::model_schema::ModelSchemaOptions;
use crate::db::{DbFieldType, DbValue, User};
use crate::error::OpenAuthError;

/// User lifecycle configuration.
#[derive(Debug, Clone, Default)]
pub struct UserOptions {
    pub schema: ModelSchemaOptions,
    pub change_email: ChangeEmailOptions,
    pub delete_user: DeleteUserOptions,
    pub additional_fields: BTreeMap<String, UserAdditionalField>,
}

impl UserOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn schema(mut self, schema: ModelSchemaOptions) -> Self {
        self.schema = schema;
        self
    }

    #[must_use]
    pub fn change_email(mut self, change_email: ChangeEmailOptions) -> Self {
        self.change_email = change_email;
        self
    }

    #[must_use]
    pub fn delete_user(mut self, delete_user: DeleteUserOptions) -> Self {
        self.delete_user = delete_user;
        self
    }

    #[must_use]
    pub fn additional_field(mut self, name: impl Into<String>, field: UserAdditionalField) -> Self {
        self.additional_fields.insert(name.into(), field);
        self
    }
}

/// Runtime metadata for custom user fields accepted by user-writing endpoints.
#[derive(Debug, Clone, PartialEq)]
pub struct UserAdditionalField {
    pub field_type: DbFieldType,
    pub required: bool,
    pub input: bool,
    pub returned: bool,
    pub default_value: Option<DbValue>,
    pub db_name: Option<String>,
}

impl UserAdditionalField {
    pub fn new(field_type: DbFieldType) -> Self {
        Self {
            field_type,
            required: true,
            input: true,
            returned: true,
            default_value: None,
            db_name: None,
        }
    }

    #[must_use]
    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    #[must_use]
    pub fn generated(mut self) -> Self {
        self.input = false;
        self
    }

    #[must_use]
    pub fn hidden(mut self) -> Self {
        self.returned = false;
        self
    }

    #[must_use]
    pub fn default_value(mut self, value: DbValue) -> Self {
        self.default_value = Some(value);
        self
    }

    #[must_use]
    pub fn db_name(mut self, db_name: impl Into<String>) -> Self {
        self.db_name = Some(db_name.into());
        self
    }
}

/// Email change behavior.
#[derive(Clone, Default)]
pub struct ChangeEmailOptions {
    pub enabled: bool,
    pub update_email_without_verification: bool,
    pub send_change_email_confirmation: Option<Arc<dyn SendChangeEmailConfirmation>>,
}

impl fmt::Debug for ChangeEmailOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangeEmailOptions")
            .field("enabled", &self.enabled)
            .field(
                "update_email_without_verification",
                &self.update_email_without_verification,
            )
            .field(
                "send_change_email_confirmation",
                &self
                    .send_change_email_confirmation
                    .as_ref()
                    .map(|_| "<send-change-email-confirmation>"),
            )
            .finish()
    }
}

impl ChangeEmailOptions {
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
    pub fn update_email_without_verification(mut self, enabled: bool) -> Self {
        self.update_email_without_verification = enabled;
        self
    }

    #[must_use]
    pub fn send_change_email_confirmation<S>(mut self, sender: S) -> Self
    where
        S: SendChangeEmailConfirmation,
    {
        self.send_change_email_confirmation = Some(Arc::new(sender));
        self
    }
}

/// Payload for notifying the current email address about a pending change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEmailConfirmation {
    pub user: User,
    pub new_email: String,
    pub url: String,
    pub token: String,
}

/// Notifies the user's current email that a change was requested.
pub trait SendChangeEmailConfirmation: Send + Sync + 'static {
    fn send_change_email_confirmation(
        &self,
        payload: ChangeEmailConfirmation,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> SendChangeEmailConfirmation for F
where
    F: for<'a> Fn(
            ChangeEmailConfirmation,
            Option<&'a Request<Vec<u8>>>,
        ) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn send_change_email_confirmation(
        &self,
        payload: ChangeEmailConfirmation,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(payload, request)
    }
}

/// User deletion behavior.
#[derive(Clone, Default)]
pub struct DeleteUserOptions {
    pub enabled: bool,
    pub send_delete_account_verification: Option<Arc<dyn SendDeleteAccountVerification>>,
    pub before_delete: Option<Arc<dyn BeforeDeleteUser>>,
    pub after_delete: Option<Arc<dyn AfterDeleteUser>>,
    pub delete_token_expires_in: Option<u64>,
}

impl fmt::Debug for DeleteUserOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeleteUserOptions")
            .field("enabled", &self.enabled)
            .field(
                "send_delete_account_verification",
                &self
                    .send_delete_account_verification
                    .as_ref()
                    .map(|_| "<send-delete-account-verification>"),
            )
            .field(
                "before_delete",
                &self.before_delete.as_ref().map(|_| "<before-delete>"),
            )
            .field(
                "after_delete",
                &self.after_delete.as_ref().map(|_| "<after-delete>"),
            )
            .field("delete_token_expires_in", &self.delete_token_expires_in)
            .finish()
    }
}

impl DeleteUserOptions {
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
    pub fn send_delete_account_verification<S>(mut self, sender: S) -> Self
    where
        S: SendDeleteAccountVerification,
    {
        self.send_delete_account_verification = Some(Arc::new(sender));
        self
    }

    #[must_use]
    pub fn before_delete<B>(mut self, hook: B) -> Self
    where
        B: BeforeDeleteUser,
    {
        self.before_delete = Some(Arc::new(hook));
        self
    }

    #[must_use]
    pub fn after_delete<A>(mut self, hook: A) -> Self
    where
        A: AfterDeleteUser,
    {
        self.after_delete = Some(Arc::new(hook));
        self
    }

    #[must_use]
    pub fn delete_token_expires_in(mut self, seconds: u64) -> Self {
        self.delete_token_expires_in = Some(seconds);
        self
    }
}

/// Payload for delete-account verification emails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteAccountVerificationEmail {
    pub user: User,
    pub url: String,
    pub token: String,
}

/// Sends a verification email before deleting the account.
pub trait SendDeleteAccountVerification: Send + Sync + 'static {
    fn send_delete_account_verification(
        &self,
        payload: DeleteAccountVerificationEmail,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> SendDeleteAccountVerification for F
where
    F: for<'a> Fn(
            DeleteAccountVerificationEmail,
            Option<&'a Request<Vec<u8>>>,
        ) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn send_delete_account_verification(
        &self,
        payload: DeleteAccountVerificationEmail,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(payload, request)
    }
}

/// Hook invoked before a user is deleted.
pub trait BeforeDeleteUser: Send + Sync + 'static {
    fn before_delete(
        &self,
        user: &User,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> BeforeDeleteUser for F
where
    F: for<'a> Fn(&User, Option<&'a Request<Vec<u8>>>) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn before_delete(
        &self,
        user: &User,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(user, request)
    }
}

/// Hook invoked after a user is deleted.
pub trait AfterDeleteUser: Send + Sync + 'static {
    fn after_delete(
        &self,
        user: &User,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> AfterDeleteUser for F
where
    F: for<'a> Fn(&User, Option<&'a Request<Vec<u8>>>) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn after_delete(
        &self,
        user: &User,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(user, request)
    }
}
