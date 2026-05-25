use time::OffsetDateTime;

use crate::api::{request_base_url, ApiRequest};
use crate::context::AuthContext;
use crate::db::{DbAdapter, Session, User};
use crate::error::OpenAuthError;
use crate::options::VerificationEmail;
use crate::session::SessionStore;
use crate::user::DbUserStore;
use crate::verification::VerificationStore;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub(in crate::api) enum DeleteUserError {
    #[error("invalid password")]
    InvalidPassword,
    #[error("invalid token")]
    InvalidToken,
    #[error("session expired")]
    SessionExpired,
}

#[derive(Debug, thiserror::Error)]
pub(in crate::api) enum DeleteUserErrorOrOpenAuth {
    #[error(transparent)]
    Service(#[from] DeleteUserError),
    #[error(transparent)]
    OpenAuth(#[from] OpenAuthError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::api) struct ChangeEmailInput {
    pub(in crate::api) new_email: String,
    pub(in crate::api) callback_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::api) enum ChangeEmailResult {
    Updated(User),
    VerificationSent,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub(in crate::api) enum ChangeEmailError {
    #[error("change email is disabled")]
    Disabled,
    #[error("email is the same")]
    EmailIsSame,
    #[error("verification email is not enabled")]
    VerificationEmailNotEnabled,
}

#[derive(Debug, thiserror::Error)]
pub(in crate::api) enum ChangeEmailErrorOrOpenAuth {
    #[error(transparent)]
    Service(#[from] ChangeEmailError),
    #[error(transparent)]
    OpenAuth(#[from] OpenAuthError),
}

pub(in crate::api) async fn change_email(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: Option<&ApiRequest>,
    user: User,
    input: ChangeEmailInput,
) -> Result<ChangeEmailResult, ChangeEmailErrorOrOpenAuth> {
    if !context.options.user.change_email.enabled {
        return Err(ChangeEmailError::Disabled.into());
    }
    let new_email = input.new_email.to_lowercase();
    if new_email == user.email {
        return Err(ChangeEmailError::EmailIsSame.into());
    }

    let users = DbUserStore::new(adapter);
    if users.find_user_by_email(&new_email).await?.is_some() {
        super::super::routes::email_verification::create_email_verification_token(
            context,
            &user.email,
            Some(&new_email),
            None,
        )?;
        return Ok(ChangeEmailResult::VerificationSent);
    }

    if !user.email_verified
        && context
            .options
            .user
            .change_email
            .update_email_without_verification
    {
        let updated = users
            .update_user_email(&user.id, &new_email, false)
            .await?
            .unwrap_or(user);
        return Ok(ChangeEmailResult::Updated(updated));
    }

    let Some(sender) = context
        .options
        .email_verification
        .send_verification_email
        .clone()
    else {
        return Err(ChangeEmailError::VerificationEmailNotEnabled.into());
    };
    let token = super::super::routes::email_verification::create_email_verification_token(
        context,
        &user.email,
        Some(&new_email),
        Some("change-email-verification"),
    )?;
    let callback_url = input.callback_url.unwrap_or_else(|| "/".to_owned());
    let url = format!(
        "{}/verify-email?token={token}&callbackURL={}",
        request_base_url(context, request),
        percent_encode(&callback_url)
    );
    sender.send_verification_email(
        VerificationEmail {
            user: User {
                email: new_email,
                ..user
            },
            url,
            token,
        },
        request,
    )?;
    Ok(ChangeEmailResult::VerificationSent)
}

pub(in crate::api) async fn delete_user_with_password_or_fresh_session(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    session: &Session,
    user: &User,
    password: Option<&str>,
) -> Result<(), DeleteUserErrorOrOpenAuth> {
    if let Some(password) = password {
        if !verify_delete_password(adapter, context, &user.id, password).await? {
            return Err(DeleteUserError::InvalidPassword.into());
        }
    } else if context.session_config.fresh_age != 0 {
        let age = OffsetDateTime::now_utc() - session.created_at;
        if age.whole_seconds() >= context.session_config.fresh_age as i64 {
            return Err(DeleteUserError::SessionExpired.into());
        }
    }
    delete_user_records(adapter, context, &user.id).await?;
    Ok(())
}

pub(in crate::api) async fn delete_user_with_token(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
    token: &str,
) -> Result<(), DeleteUserErrorOrOpenAuth> {
    let identifier = format!("delete-account-{token}");
    let verifications = VerificationStore::new(adapter, context);
    let Some(verification) = verifications.find_verification(&identifier).await? else {
        return Err(DeleteUserError::InvalidToken.into());
    };
    if verification.value != user.id {
        return Err(DeleteUserError::InvalidToken.into());
    }
    delete_user_records(adapter, context, &user.id).await?;
    verifications.delete_verification(&identifier).await?;
    Ok(())
}

async fn verify_delete_password(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user_id: &str,
    password: &str,
) -> Result<bool, OpenAuthError> {
    let Some(account) = DbUserStore::new(adapter)
        .find_credential_account(user_id)
        .await?
    else {
        return Ok(false);
    };
    let Some(password_hash) = account.password.as_deref() else {
        return Ok(false);
    };
    (context.password.verify)(password_hash, password)
}

async fn delete_user_records(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user_id: &str,
) -> Result<(), OpenAuthError> {
    let users = DbUserStore::new(adapter);
    users.delete_user_accounts(user_id).await?;
    SessionStore::new(adapter, context)
        .delete_user_sessions(user_id)
        .await?;
    users.delete_user(user_id).await
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
