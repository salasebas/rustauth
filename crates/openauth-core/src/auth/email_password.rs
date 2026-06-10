//! Email/password auth service built on top of core DB stores.

use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use time::{Duration, OffsetDateTime};

use crate::crypto::password::{hash_password, verify_password};
use crate::db::{DbAdapter, DbRecord, Session, User};
use crate::error::OpenAuthError;
use crate::options::SecondaryStorage;
use crate::session::{CreateSessionInput, SessionStore};
use crate::user::{CreateCredentialAccountInput, CreateUserInput, DbUserStore};

pub type PasswordHashFn = fn(&str) -> Result<String, OpenAuthError>;
pub type PasswordVerifyFn = fn(&str, &str) -> Result<bool, OpenAuthError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFlowErrorCode {
    InvalidEmail,
    InvalidPasswordLength,
    InvalidEmailOrPassword,
    UserAlreadyExists,
    UserAlreadyExistsUseAnotherEmail,
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
            Self::UserAlreadyExists => crate::error_codes::USER_ALREADY_EXISTS,
            Self::UserAlreadyExistsUseAnotherEmail => {
                crate::error_codes::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL
            }
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
            Self::UserAlreadyExistsUseAnotherEmail => "User already exists. Use another email.",
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

#[derive(Clone)]
pub struct EmailPasswordConfig {
    pub session_expires_in: u64,
    pub dont_remember_session_expires_in: u64,
    pub min_password_length: usize,
    pub max_password_length: usize,
    pub require_email_verification: bool,
    pub secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    pub store_session_in_database: bool,
    pub preserve_session_in_database: bool,
}

impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            session_expires_in: 60 * 60 * 24 * 7,
            dont_remember_session_expires_in: 60 * 60 * 24,
            min_password_length: 8,
            max_password_length: 128,
            require_email_verification: false,
            secondary_storage: None,
            store_session_in_database: false,
            preserve_session_in_database: false,
        }
    }
}

impl fmt::Debug for EmailPasswordConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailPasswordConfig")
            .field("session_expires_in", &self.session_expires_in)
            .field(
                "dont_remember_session_expires_in",
                &self.dont_remember_session_expires_in,
            )
            .field("min_password_length", &self.min_password_length)
            .field("max_password_length", &self.max_password_length)
            .field(
                "require_email_verification",
                &self.require_email_verification,
            )
            .field(
                "secondary_storage",
                &self
                    .secondary_storage
                    .as_ref()
                    .map(|_| "<secondary-storage>"),
            )
            .field("store_session_in_database", &self.store_session_in_database)
            .field(
                "preserve_session_in_database",
                &self.preserve_session_in_database,
            )
            .finish()
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
            .additional_fields_with(input.additional_user_fields);
        if let Some(image) = input.image {
            create_user = create_user.image(image);
        }
        if let Some(username) = input.username {
            create_user = create_user.username(username);
        }
        if let Some(display_username) = input.display_username {
            create_user = create_user.display_username(display_username);
        }
        let result = Arc::new(Mutex::new(None));
        let result_for_transaction = Arc::clone(&result);
        let config = self.config.clone();
        let transaction_status = self
            .adapter
            .transaction(Box::new(move |transaction| {
                Box::pin(async move {
                    let outcome = create_sign_up_records(SignUpRecordsInput {
                        adapter: transaction.as_ref(),
                        config: &config,
                        create_user,
                        password_hash,
                        remember_me: input.remember_me,
                        ip_address: input.ip_address,
                        user_agent: input.user_agent,
                        additional_session_fields: input.additional_session_fields,
                    })
                    .await;
                    match outcome {
                        Ok(result) => {
                            store_sign_up_result(&result_for_transaction, Ok(result))?;
                            Ok(())
                        }
                        Err(error) => {
                            let transaction_error = OpenAuthError::Adapter(error.to_string());
                            store_sign_up_result(&result_for_transaction, Err(error))?;
                            Err(transaction_error)
                        }
                    }
                })
            }))
            .await;

        match transaction_status {
            Ok(()) => match take_sign_up_result(&result)? {
                Some(Ok(result)) => Ok(result),
                Some(Err(error)) => Err(error),
                None => Err(AuthFlowError::storage(OpenAuthError::Adapter(
                    "sign-up transaction completed without a result".to_owned(),
                ))),
            },
            Err(error) => match take_sign_up_result(&result)? {
                Some(Err(auth_error)) => Err(auth_error),
                _ => Err(AuthFlowError::storage(error)),
            },
        }
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
        let session = create_session_record(
            self.adapter,
            &self.config,
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
}

struct SignUpRecordsInput<'a> {
    adapter: &'a dyn DbAdapter,
    config: &'a EmailPasswordConfig,
    create_user: CreateUserInput,
    password_hash: String,
    remember_me: bool,
    ip_address: Option<String>,
    user_agent: Option<String>,
    additional_session_fields: DbRecord,
}

async fn create_sign_up_records(
    input: SignUpRecordsInput<'_>,
) -> Result<EmailPasswordAuthResult, AuthFlowError> {
    let users = DbUserStore::new(input.adapter);
    let user = users.create_user(input.create_user).await?;
    users
        .create_credential_account(CreateCredentialAccountInput::new(
            user.id.clone(),
            input.password_hash,
        ))
        .await?;
    let session = create_session_record(
        input.adapter,
        input.config,
        &user.id,
        input.remember_me,
        input.ip_address,
        input.user_agent,
        input.additional_session_fields,
    )
    .await?;

    Ok(EmailPasswordAuthResult { user, session })
}

async fn create_session_record(
    adapter: &dyn DbAdapter,
    config: &EmailPasswordConfig,
    user_id: &str,
    remember_me: bool,
    ip_address: Option<String>,
    user_agent: Option<String>,
    additional_fields: DbRecord,
) -> Result<Session, AuthFlowError> {
    let expires_in = if remember_me {
        config.session_expires_in
    } else {
        config.dont_remember_session_expires_in
    };
    let seconds = i64::try_from(expires_in)
        .map_err(|_| AuthFlowError::new(AuthFlowErrorCode::FailedToCreateSession))?;
    let expires_at = OffsetDateTime::now_utc() + Duration::seconds(seconds);
    let mut input =
        CreateSessionInput::new(user_id, expires_at).additional_fields_with(additional_fields);
    if let Some(ip_address) = ip_address {
        input = input.ip_address(ip_address);
    }
    if let Some(user_agent) = user_agent {
        input = input.user_agent(user_agent);
    }

    SessionStore::with_storage(
        adapter,
        config.secondary_storage.clone(),
        config.store_session_in_database,
        config.preserve_session_in_database,
    )
    .create_session(input)
    .await
    .map_err(|_| AuthFlowError::new(AuthFlowErrorCode::FailedToCreateSession))
}

fn store_sign_up_result(
    result: &Mutex<Option<Result<EmailPasswordAuthResult, AuthFlowError>>>,
    value: Result<EmailPasswordAuthResult, AuthFlowError>,
) -> Result<(), OpenAuthError> {
    let mut guard = result.lock().map_err(|_| OpenAuthError::LockPoisoned {
        context: "sign-up result",
    })?;
    *guard = Some(value);
    Ok(())
}

fn take_sign_up_result(
    result: &Mutex<Option<Result<EmailPasswordAuthResult, AuthFlowError>>>,
) -> Result<Option<Result<EmailPasswordAuthResult, AuthFlowError>>, AuthFlowError> {
    result
        .lock()
        .map_err(|_| {
            AuthFlowError::storage(OpenAuthError::LockPoisoned {
                context: "sign-up result",
            })
        })
        .map(|mut guard| guard.take())
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
