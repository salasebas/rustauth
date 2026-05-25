use time::{Duration, OffsetDateTime};

use crate::api::plugin_pipeline::run_password_validators;
use crate::api::{request_base_url, ApiRequest};
use crate::context::AuthContext;
use crate::crypto::random::generate_random_string;
use crate::db::{DbAdapter, Session, User};
use crate::error::OpenAuthError;
use crate::options::{PasswordResetEmail, PasswordResetPayload};
use crate::plugin::PluginPasswordValidationRejection;
use crate::session::{CreateSessionInput, SessionStore};
use crate::user::{CreateCredentialAccountInput, DbUserStore};
use crate::verification::{CreateVerificationInput, VerificationStore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::api) struct ChangePasswordInput {
    pub(in crate::api) current_password: String,
    pub(in crate::api) new_password: String,
    pub(in crate::api) revoke_other_sessions: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::api) struct SetPasswordInput {
    pub(in crate::api) new_password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::api) struct VerifyPasswordInput {
    pub(in crate::api) password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::api) struct RequestPasswordResetInput {
    pub(in crate::api) email: String,
    pub(in crate::api) redirect_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::api) struct ResetPasswordInput {
    pub(in crate::api) token: String,
    pub(in crate::api) new_password: String,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub(in crate::api) enum PasswordServiceError {
    #[error("credential account not found")]
    CredentialAccountNotFound,
    #[error("invalid password")]
    InvalidPassword,
    #[error("invalid token")]
    InvalidToken,
    #[error("password already set")]
    PasswordAlreadySet,
    #[error("password is too long")]
    PasswordTooLong,
    #[error("password is too short")]
    PasswordTooShort,
    #[error("password validation rejected the request")]
    PasswordValidation(PluginPasswordValidationRejection),
}

pub(in crate::api) async fn change_password(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
    input: ChangePasswordInput,
) -> Result<Option<Session>, PasswordServiceErrorOrOpenAuth> {
    validate_password_length(context, &input.new_password)?;
    let users = DbUserStore::new(adapter);
    let Some(account) = users.find_credential_account(&user.id).await? else {
        return Err(PasswordServiceError::CredentialAccountNotFound.into());
    };
    let Some(password_hash) = account.password.as_deref() else {
        return Err(PasswordServiceError::CredentialAccountNotFound.into());
    };
    if !(context.password.verify)(password_hash, &input.current_password)? {
        return Err(PasswordServiceError::InvalidPassword.into());
    }
    run_password_validators(context, "/change-password", &input.new_password)
        .await
        .map_err(PasswordServiceError::PasswordValidation)?;

    let new_hash = (context.password.hash)(&input.new_password)?;
    users
        .update_credential_password(&user.id, &new_hash)
        .await?;

    if !input.revoke_other_sessions {
        return Ok(None);
    }

    let sessions = SessionStore::new(adapter, context);
    sessions.delete_user_sessions(&user.id).await?;
    Ok(Some(
        sessions
            .create_session(CreateSessionInput::new(
                &user.id,
                OffsetDateTime::now_utc()
                    + Duration::seconds(context.session_config.expires_in as i64),
            ))
            .await?,
    ))
}

pub(in crate::api) async fn set_password(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
    input: SetPasswordInput,
) -> Result<(), PasswordServiceErrorOrOpenAuth> {
    validate_password_length(context, &input.new_password)?;
    let users = DbUserStore::new(adapter);
    if users.find_credential_account(&user.id).await?.is_some() {
        return Err(PasswordServiceError::PasswordAlreadySet.into());
    }
    let hash = (context.password.hash)(&input.new_password)?;
    users
        .create_credential_account(CreateCredentialAccountInput::new(&user.id, hash))
        .await?;
    Ok(())
}

pub(in crate::api) async fn verify_password(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
    input: VerifyPasswordInput,
) -> Result<(), PasswordServiceErrorOrOpenAuth> {
    let Some(account) = DbUserStore::new(adapter)
        .find_credential_account(&user.id)
        .await?
    else {
        return Err(PasswordServiceError::InvalidPassword.into());
    };
    let Some(password_hash) = account.password.as_deref() else {
        return Err(PasswordServiceError::InvalidPassword.into());
    };
    if !(context.password.verify)(password_hash, &input.password)? {
        return Err(PasswordServiceError::InvalidPassword.into());
    }
    Ok(())
}

pub(in crate::api) async fn request_password_reset(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: Option<&ApiRequest>,
    input: RequestPasswordResetInput,
) -> Result<(), OpenAuthError> {
    let Some(user) = DbUserStore::new(adapter)
        .find_user_by_email(&input.email)
        .await?
    else {
        return Ok(());
    };
    let token = generate_random_string(24);
    let expires_in = context
        .options
        .password
        .reset_password_token_expires_in
        .unwrap_or(60 * 60);
    let expires_in = i64::try_from(expires_in).map_err(|_| OpenAuthError::NumericOutOfRange {
        context: "reset_password_token_expires_in",
    })?;
    VerificationStore::new(adapter, context)
        .create_verification(CreateVerificationInput::new(
            format!("reset-password:{token}"),
            user.id.clone(),
            OffsetDateTime::now_utc() + Duration::seconds(expires_in),
        ))
        .await?;
    if let Some(sender) = &context.options.password.send_reset_password {
        let url = password_reset_url(context, request, &token, input.redirect_to.as_deref());
        sender.send_reset_password(PasswordResetEmail { user, url, token }, request)?;
    }
    Ok(())
}

pub(in crate::api) async fn reset_password(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: Option<&ApiRequest>,
    input: ResetPasswordInput,
) -> Result<(), PasswordServiceErrorOrOpenAuth> {
    validate_password_length(context, &input.new_password)?;
    let identifier = format!("reset-password:{}", input.token);
    let verifications = VerificationStore::new(adapter, context);
    let Some(verification) = verifications.find_verification(&identifier).await? else {
        return Err(PasswordServiceError::InvalidToken.into());
    };
    if verification.expires_at <= OffsetDateTime::now_utc() {
        return Err(PasswordServiceError::InvalidToken.into());
    }
    run_password_validators(context, "/reset-password", &input.new_password)
        .await
        .map_err(PasswordServiceError::PasswordValidation)?;

    let user_id = verification.value;
    let users = DbUserStore::new(adapter);
    let Some(user) = users.find_user_by_id(&user_id).await? else {
        verifications.delete_verification(&identifier).await?;
        return Err(PasswordServiceError::InvalidToken.into());
    };
    let new_hash = (context.password.hash)(&input.new_password)?;
    if users
        .update_credential_password(&user_id, &new_hash)
        .await?
        .is_none()
    {
        users
            .create_credential_account(CreateCredentialAccountInput::new(&user_id, new_hash))
            .await?;
    }
    verifications.delete_verification(&identifier).await?;
    if let Some(callback) = &context.options.password.on_password_reset {
        callback.on_password_reset(PasswordResetPayload { user: user.clone() }, request)?;
    }
    if context.options.password.revoke_sessions_on_password_reset {
        SessionStore::new(adapter, context)
            .delete_user_sessions(&user.id)
            .await?;
    }
    Ok(())
}

pub(in crate::api) async fn reset_password_callback_token_is_valid(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    token: &str,
) -> Result<bool, OpenAuthError> {
    let identifier = format!("reset-password:{token}");
    let verification = VerificationStore::new(adapter, context)
        .find_verification(&identifier)
        .await?;
    Ok(matches!(
        verification,
        Some(verification) if verification.expires_at > OffsetDateTime::now_utc()
    ))
}

#[derive(Debug, thiserror::Error)]
pub(in crate::api) enum PasswordServiceErrorOrOpenAuth {
    #[error(transparent)]
    Service(#[from] PasswordServiceError),
    #[error(transparent)]
    OpenAuth(#[from] OpenAuthError),
}

fn validate_password_length(
    context: &AuthContext,
    password: &str,
) -> Result<(), PasswordServiceError> {
    if password.len() < context.password.config.min_password_length {
        return Err(PasswordServiceError::PasswordTooShort);
    }
    if password.len() > context.password.config.max_password_length {
        return Err(PasswordServiceError::PasswordTooLong);
    }
    Ok(())
}

fn password_reset_url(
    context: &AuthContext,
    request: Option<&ApiRequest>,
    token: &str,
    redirect_to: Option<&str>,
) -> String {
    let callback_url = redirect_to.unwrap_or("/");
    format!(
        "{}/reset-password/{token}?callbackURL={}",
        request_base_url(context, request),
        percent_encode(callback_url)
    )
}

fn percent_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
