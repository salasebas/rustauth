//! Email/password auth service built on top of core DB stores.

use std::error::Error;
use std::fmt;

use time::{Duration, OffsetDateTime};

use crate::crypto::password::{hash_password, verify_password};
use crate::db::{DbAdapter, DbRecord, Session, User};
use crate::error::OpenAuthError;
use crate::session::{CreateSessionInput, DbSessionStore};
use crate::user::{CreateCredentialAccountInput, CreateUserInput, DbUserStore};

pub type PasswordHashFn = fn(&str) -> Result<String, OpenAuthError>;
pub type PasswordVerifyFn = fn(&str, &str) -> Result<bool, OpenAuthError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFlowErrorCode {
    InvalidEmail,
    InvalidPasswordLength,
    InvalidEmailOrPassword,
    UserAlreadyExists,
    EmailNotVerified,
    FailedToCreateSession,
    StorageError,
}

impl AuthFlowErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidEmail => "INVALID_EMAIL",
            Self::InvalidPasswordLength => "INVALID_PASSWORD_LENGTH",
            Self::InvalidEmailOrPassword => "INVALID_EMAIL_OR_PASSWORD",
            Self::UserAlreadyExists => "USER_ALREADY_EXISTS",
            Self::EmailNotVerified => "EMAIL_NOT_VERIFIED",
            Self::FailedToCreateSession => "FAILED_TO_CREATE_SESSION",
            Self::StorageError => "STORAGE_ERROR",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidEmail => "Invalid email",
            Self::InvalidPasswordLength => "Invalid password length",
            Self::InvalidEmailOrPassword => "Invalid email or password",
            Self::UserAlreadyExists => "User already exists",
            Self::EmailNotVerified => "Email not verified",
            Self::FailedToCreateSession => "Failed to create session",
            Self::StorageError => "Storage error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFlowError {
    code: AuthFlowErrorCode,
    message: String,
}

impl AuthFlowError {
    pub fn new(code: AuthFlowErrorCode) -> Self {
        Self {
            code,
            message: code.message().to_owned(),
        }
    }

    pub fn storage(error: OpenAuthError) -> Self {
        Self {
            code: AuthFlowErrorCode::StorageError,
            message: error.to_string(),
        }
    }

    pub fn code(&self) -> AuthFlowErrorCode {
        self.code
    }

    pub fn code_str(&self) -> &'static str {
        self.code.as_str()
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }
}

impl fmt::Display for AuthFlowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for AuthFlowError {}

impl From<OpenAuthError> for AuthFlowError {
    fn from(error: OpenAuthError) -> Self {
        Self::storage(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailPasswordConfig {
    pub session_expires_in: u64,
    pub dont_remember_session_expires_in: u64,
    pub min_password_length: usize,
    pub max_password_length: usize,
    pub require_email_verification: bool,
}

impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            session_expires_in: 60 * 60 * 24 * 7,
            dont_remember_session_expires_in: 60 * 60 * 24,
            min_password_length: 8,
            max_password_length: 128,
            require_email_verification: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignUpInput {
    pub name: String,
    pub email: String,
    pub password: String,
    pub image: Option<String>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub remember_me: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub additional_user_fields: DbRecord,
    pub additional_session_fields: DbRecord,
}

impl SignUpInput {
    pub fn new(
        name: impl Into<String>,
        email: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            email: email.into(),
            password: password.into(),
            image: None,
            username: None,
            display_username: None,
            remember_me: true,
            ip_address: None,
            user_agent: None,
            additional_user_fields: DbRecord::new(),
            additional_session_fields: DbRecord::new(),
        }
    }

    #[must_use]
    pub fn image(mut self, image: impl Into<String>) -> Self {
        self.image = Some(image.into());
        self
    }

    #[must_use]
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    #[must_use]
    pub fn display_username(mut self, display_username: impl Into<String>) -> Self {
        self.display_username = Some(display_username.into());
        self
    }

    #[must_use]
    pub fn remember_me(mut self, remember_me: bool) -> Self {
        self.remember_me = remember_me;
        self
    }

    #[must_use]
    pub fn ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = Some(ip_address.into());
        self
    }

    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    #[must_use]
    pub fn additional_user_fields(mut self, fields: DbRecord) -> Self {
        self.additional_user_fields = fields;
        self
    }

    #[must_use]
    pub fn additional_session_fields(mut self, fields: DbRecord) -> Self {
        self.additional_session_fields = fields;
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignInInput {
    pub email: String,
    pub password: String,
    pub remember_me: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub additional_session_fields: DbRecord,
}

impl SignInInput {
    pub fn new(email: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            password: password.into(),
            remember_me: true,
            ip_address: None,
            user_agent: None,
            additional_session_fields: DbRecord::new(),
        }
    }

    #[must_use]
    pub fn remember_me(mut self, remember_me: bool) -> Self {
        self.remember_me = remember_me;
        self
    }

    #[must_use]
    pub fn ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = Some(ip_address.into());
        self
    }

    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    #[must_use]
    pub fn additional_session_fields(mut self, fields: DbRecord) -> Self {
        self.additional_session_fields = fields;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailPasswordAuthResult {
    pub user: User,
    pub session: Session,
}

#[derive(Clone)]
pub struct EmailPasswordAuth<'a> {
    adapter: &'a dyn DbAdapter,
    config: EmailPasswordConfig,
    hash_password: PasswordHashFn,
    verify_password: PasswordVerifyFn,
}

impl<'a> EmailPasswordAuth<'a> {
    pub fn new(
        adapter: &'a dyn DbAdapter,
        config: EmailPasswordConfig,
        hash_password: PasswordHashFn,
        verify_password: PasswordVerifyFn,
    ) -> Self {
        Self {
            adapter,
            config,
            hash_password,
            verify_password,
        }
    }

    pub fn with_defaults(adapter: &'a dyn DbAdapter, config: EmailPasswordConfig) -> Self {
        Self::new(adapter, config, hash_password, verify_password)
    }

    pub async fn sign_up(
        &self,
        input: SignUpInput,
    ) -> Result<EmailPasswordAuthResult, AuthFlowError> {
        self.validate_email_and_password(&input.email, &input.password)?;
        let users = DbUserStore::new(self.adapter);
        if users.find_user_by_email(&input.email).await?.is_some() {
            return Err(AuthFlowError::new(AuthFlowErrorCode::UserAlreadyExists));
        }

        let password_hash = (self.hash_password)(&input.password)?;
        let mut create_user = CreateUserInput::new(input.name, input.email)
            .additional_fields(input.additional_user_fields);
        if let Some(image) = input.image {
            create_user = create_user.image(image);
        }
        if let Some(username) = input.username {
            create_user = create_user.username(username);
        }
        if let Some(display_username) = input.display_username {
            create_user = create_user.display_username(display_username);
        }
        let user = users.create_user(create_user).await?;
        users
            .create_credential_account(CreateCredentialAccountInput::new(
                user.id.clone(),
                password_hash,
            ))
            .await?;
        let session = self
            .create_session(
                &user.id,
                input.remember_me,
                input.ip_address,
                input.user_agent,
                input.additional_session_fields,
            )
            .await?;

        Ok(EmailPasswordAuthResult { user, session })
    }

    pub async fn sign_in(
        &self,
        input: SignInInput,
    ) -> Result<EmailPasswordAuthResult, AuthFlowError> {
        validate_email(&input.email)?;
        let users = DbUserStore::new(self.adapter);
        let Some(user_with_accounts) = users.find_user_by_email_with_accounts(&input.email).await?
        else {
            let _ = (self.hash_password)(&input.password);
            return Err(AuthFlowError::new(
                AuthFlowErrorCode::InvalidEmailOrPassword,
            ));
        };
        let Some(account) = user_with_accounts
            .accounts
            .iter()
            .find(|account| account.provider_id == "credential")
        else {
            let _ = (self.hash_password)(&input.password);
            return Err(AuthFlowError::new(
                AuthFlowErrorCode::InvalidEmailOrPassword,
            ));
        };
        let Some(password_hash) = account.password.as_deref() else {
            let _ = (self.hash_password)(&input.password);
            return Err(AuthFlowError::new(
                AuthFlowErrorCode::InvalidEmailOrPassword,
            ));
        };
        if !(self.verify_password)(password_hash, &input.password)? {
            return Err(AuthFlowError::new(
                AuthFlowErrorCode::InvalidEmailOrPassword,
            ));
        }
        if self.config.require_email_verification && !user_with_accounts.user.email_verified {
            return Err(AuthFlowError::new(AuthFlowErrorCode::EmailNotVerified));
        }
        let session = self
            .create_session(
                &user_with_accounts.user.id,
                input.remember_me,
                input.ip_address,
                input.user_agent,
                input.additional_session_fields,
            )
            .await?;

        Ok(EmailPasswordAuthResult {
            user: user_with_accounts.user,
            session,
        })
    }

    fn validate_email_and_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(), AuthFlowError> {
        validate_email(email)?;
        if password.len() < self.config.min_password_length
            || password.len() > self.config.max_password_length
        {
            return Err(AuthFlowError::new(AuthFlowErrorCode::InvalidPasswordLength));
        }
        Ok(())
    }

    async fn create_session(
        &self,
        user_id: &str,
        remember_me: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
        additional_fields: DbRecord,
    ) -> Result<Session, AuthFlowError> {
        let expires_in = if remember_me {
            self.config.session_expires_in
        } else {
            self.config.dont_remember_session_expires_in
        };
        let seconds = i64::try_from(expires_in)
            .map_err(|_| AuthFlowError::new(AuthFlowErrorCode::FailedToCreateSession))?;
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(seconds);
        let mut input =
            CreateSessionInput::new(user_id, expires_at).additional_fields(additional_fields);
        if let Some(ip_address) = ip_address {
            input = input.ip_address(ip_address);
        }
        if let Some(user_agent) = user_agent {
            input = input.user_agent(user_agent);
        }

        DbSessionStore::new(self.adapter)
            .create_session(input)
            .await
            .map_err(|_| AuthFlowError::new(AuthFlowErrorCode::FailedToCreateSession))
    }
}

fn validate_email(email: &str) -> Result<(), AuthFlowError> {
    let email = email.trim();
    let Some((local, domain)) = email.split_once('@') else {
        return Err(AuthFlowError::new(AuthFlowErrorCode::InvalidEmail));
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
    {
        return Err(AuthFlowError::new(AuthFlowErrorCode::InvalidEmail));
    }
    Ok(())
}
