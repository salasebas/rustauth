use http::header;

use crate::api::plugin_pipeline::run_password_validators;
use crate::api::{request_base_url, ApiRequest};
use crate::auth::email_password::{
    AuthFlowError, AuthFlowErrorCode, EmailPasswordAuth, EmailPasswordConfig, SignInInput,
    SignUpInput,
};
use crate::context::AuthContext;
use crate::db::{DbAdapter, DbRecord, Session, User};
use crate::error::OpenAuthError;
use crate::options::{ExistingUserSignUpPayload, VerificationEmail};
use crate::plugin::PluginPasswordValidationRejection;
use crate::session::SessionStore;
use crate::user::DbUserStore;

#[derive(Debug)]
pub(in crate::api) struct SignUpEmailInput {
    pub(in crate::api) name: String,
    pub(in crate::api) email: String,
    pub(in crate::api) password: String,
    pub(in crate::api) image: Option<String>,
    pub(in crate::api) username: Option<String>,
    pub(in crate::api) display_username: Option<String>,
    pub(in crate::api) remember_me: bool,
    pub(in crate::api) callback_url: Option<String>,
    pub(in crate::api) additional_user_fields: DbRecord,
    pub(in crate::api) additional_session_fields: DbRecord,
}

#[derive(Debug)]
pub(in crate::api) struct SignInEmailInput {
    pub(in crate::api) email: String,
    pub(in crate::api) password: String,
    pub(in crate::api) remember_me: bool,
    pub(in crate::api) callback_url: Option<String>,
    pub(in crate::api) additional_session_fields: DbRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::api) struct EmailAuthResult {
    pub(in crate::api) user: User,
    pub(in crate::api) session: Option<Session>,
    pub(in crate::api) remember_me: bool,
}

#[derive(Debug, thiserror::Error)]
pub(in crate::api) enum EmailPasswordServiceError {
    #[error("email/password authentication is disabled")]
    Disabled,
    #[error("email/password sign-up is disabled")]
    SignUpDisabled,
    #[error("username is already taken")]
    UsernameTaken,
    #[error(transparent)]
    AuthFlow(#[from] AuthFlowError),
    #[error("password validation rejected the request")]
    PasswordValidation(PluginPasswordValidationRejection),
    #[error(transparent)]
    OpenAuth(#[from] OpenAuthError),
}

pub(in crate::api) async fn sign_up_email(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: &ApiRequest,
    input: SignUpEmailInput,
) -> Result<EmailAuthResult, EmailPasswordServiceError> {
    if !context.options.email_password.enabled || context.options.email_password.disable_sign_up {
        return Err(EmailPasswordServiceError::SignUpDisabled);
    }

    let mut sign_up = SignUpInput::new(input.name, input.email.to_lowercase(), input.password)
        .remember_me(input.remember_me);
    if let Some(image) = input.image {
        sign_up = sign_up.image(image);
    }
    if let Some(username) = input.username {
        sign_up = sign_up.username(username);
    }
    if let Some(display_username) = input.display_username {
        sign_up = sign_up.display_username(display_username);
    }
    sign_up = sign_up
        .additional_user_fields(input.additional_user_fields)
        .additional_session_fields(input.additional_session_fields);
    sign_up = with_sign_up_request_metadata(sign_up, context, request);

    if context.has_plugin("username") {
        if let Some(username) = sign_up.username.as_deref() {
            if DbUserStore::new(adapter)
                .find_user_by_username(username)
                .await?
                .is_some()
            {
                return Err(EmailPasswordServiceError::UsernameTaken);
            }
        }
    }

    if let Some(existing_user) = DbUserStore::new(adapter)
        .find_user_by_email(&sign_up.email)
        .await?
    {
        if context.options.email_password.require_email_verification
            || !context.options.email_password.auto_sign_in
        {
            let _ = (context.password.hash)(&sign_up.password);
            if let Some(callback) = &context.options.email_password.on_existing_user_sign_up {
                callback.on_existing_user_sign_up(
                    ExistingUserSignUpPayload {
                        user: existing_user.clone(),
                    },
                    Some(request),
                )?;
            }
            return Ok(EmailAuthResult {
                user: existing_user,
                session: None,
                remember_me: input.remember_me,
            });
        }
        return Err(AuthFlowError::new(AuthFlowErrorCode::UserAlreadyExists).into());
    }

    run_password_validators(context, "/sign-up/email", &sign_up.password)
        .await
        .map_err(EmailPasswordServiceError::PasswordValidation)?;

    let auth = EmailPasswordAuth::new(
        adapter,
        email_password_config(context),
        context.password.hash,
        context.password.verify,
    );
    let result = auth.sign_up(sign_up).await?;
    if should_send_verification_on_sign_up(context) {
        send_verification_email(context, request, result.user.clone(), input.callback_url)?;
    }
    if context.options.email_password.require_email_verification
        || !context.options.email_password.auto_sign_in
    {
        SessionStore::new(adapter, context)
            .delete_session(&result.session.token)
            .await?;
        return Ok(EmailAuthResult {
            user: result.user,
            session: None,
            remember_me: input.remember_me,
        });
    }

    Ok(EmailAuthResult {
        user: result.user,
        session: Some(result.session),
        remember_me: input.remember_me,
    })
}

pub(in crate::api) async fn sign_in_email(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: &ApiRequest,
    input: SignInEmailInput,
) -> Result<EmailAuthResult, EmailPasswordServiceError> {
    if !context.options.email_password.enabled {
        return Err(EmailPasswordServiceError::Disabled);
    }

    let email = input.email.to_lowercase();
    maybe_send_sign_in_verification_email(
        adapter,
        context,
        request,
        &email,
        &input.password,
        input.callback_url.as_deref(),
    )
    .await?;

    let sign_in = with_sign_in_request_metadata(
        SignInInput::new(email, input.password)
            .remember_me(input.remember_me)
            .additional_session_fields(input.additional_session_fields),
        context,
        request,
    );
    let auth = EmailPasswordAuth::new(
        adapter,
        email_password_config(context),
        context.password.hash,
        context.password.verify,
    );
    let result = auth.sign_in(sign_in).await?;
    Ok(EmailAuthResult {
        user: result.user,
        session: Some(result.session),
        remember_me: input.remember_me,
    })
}

fn email_password_config(context: &AuthContext) -> EmailPasswordConfig {
    EmailPasswordConfig {
        session_expires_in: context.session_config.expires_in,
        dont_remember_session_expires_in: 60 * 60 * 24,
        min_password_length: context.password.config.min_password_length,
        max_password_length: context.password.config.max_password_length,
        require_email_verification: context.options.email_password.require_email_verification,
        secondary_storage: context.secondary_storage(),
        store_session_in_database: context.options.session.store_session_in_database,
        preserve_session_in_database: context.options.session.preserve_session_in_database,
    }
}

fn should_send_verification_on_sign_up(context: &AuthContext) -> bool {
    context.options.email_password.require_email_verification
        || context.options.email_verification.send_on_sign_up
}

async fn maybe_send_sign_in_verification_email(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    request: &ApiRequest,
    email: &str,
    password: &str,
    callback_url: Option<&str>,
) -> Result<(), EmailPasswordServiceError> {
    if !context.options.email_password.require_email_verification {
        return Ok(());
    }

    let Some(user_with_accounts) = DbUserStore::new(adapter)
        .find_user_by_email_with_accounts(email)
        .await?
    else {
        return Ok(());
    };
    let Some(account) = user_with_accounts
        .accounts
        .iter()
        .find(|account| account.provider_id == "credential")
    else {
        return Ok(());
    };
    let Some(password_hash) = account.password.as_deref() else {
        return Ok(());
    };
    if !(context.password.verify)(password_hash, password)?
        || user_with_accounts.user.email_verified
    {
        return Ok(());
    }

    if context.options.email_verification.send_on_sign_in {
        send_verification_email(
            context,
            request,
            user_with_accounts.user,
            callback_url.map(str::to_owned),
        )?;
    }
    Err(AuthFlowError::new(AuthFlowErrorCode::EmailNotVerified).into())
}

fn send_verification_email(
    context: &AuthContext,
    request: &ApiRequest,
    user: User,
    callback_url: Option<String>,
) -> Result<(), OpenAuthError> {
    let Some(sender) = context
        .options
        .email_verification
        .send_verification_email
        .clone()
    else {
        return Ok(());
    };
    let token = super::super::routes::email_verification::create_email_verification_token(
        context,
        &user.email,
        None,
        None,
    )?;
    let callback_url = callback_url.unwrap_or_else(|| "/".to_owned());
    let url = format!(
        "{}/verify-email?token={token}&callbackURL={}",
        request_base_url(context, Some(request)),
        percent_encode(&callback_url)
    );
    sender.send_verification_email(VerificationEmail { user, url, token }, Some(request))
}

fn with_sign_up_request_metadata(
    mut input: SignUpInput,
    context: &AuthContext,
    request: &ApiRequest,
) -> SignUpInput {
    if let Some(ip_address) = crate::rate_limit::resolve_client_ip(context, request) {
        input = input.ip_address(ip_address);
    }
    if let Some(user_agent) = request_user_agent(request) {
        input = input.user_agent(user_agent);
    }
    input
}

fn with_sign_in_request_metadata(
    mut input: SignInInput,
    context: &AuthContext,
    request: &ApiRequest,
) -> SignInInput {
    if let Some(ip_address) = crate::rate_limit::resolve_client_ip(context, request) {
        input = input.ip_address(ip_address);
    }
    if let Some(user_agent) = request_user_agent(request) {
        input = input.user_agent(user_agent);
    }
    input
}

fn request_user_agent(request: &ApiRequest) -> Option<String> {
    request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
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
