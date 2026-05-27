use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

use crate::context::AuthContext;
use crate::cookies::{ChunkedCookieStore, Cookie};
#[cfg(feature = "jose")]
use crate::crypto::symmetric_encode_jwt_with_salt;
use crate::db::{Account, DbAdapter, Session, User};
use crate::error::OpenAuthError;
use crate::session::{CreateSessionInput, SessionStore};
use crate::user::{
    CreateOAuthAccountInput, CreateUserInput, DbUserStore, UpdateAccountInput, UpdateUserInput,
};

use super::errors::OAuthUserInfoError;
use super::tokens::set_token_util;

#[cfg(feature = "jose")]
const ACCOUNT_COOKIE_SALT: &str = "better-auth-account";
pub(crate) const ACCOUNT_ALREADY_LINKED_TO_DIFFERENT_USER: &str =
    "account_already_linked_to_different_user";
pub(crate) const EMAIL_DOES_NOT_MATCH_LINKED_USER: &str = "email_doesn't_match";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub id: String,
    pub name: String,
    pub email: String,
    pub image: Option<String>,
    pub email_verified: bool,
    pub raw_attributes: Option<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthAccountInput {
    pub provider_id: String,
    pub account_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandleOAuthUserInfoInput {
    pub user_info: OAuthUserInfo,
    pub account: OAuthAccountInput,
    pub callback_url: Option<String>,
    pub disable_sign_up: bool,
    pub override_user_info: bool,
    pub is_trusted_provider: bool,
    pub require_trusted_provider_for_implicit_link: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthSessionUser {
    pub session: Session,
    pub user: User,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreatedOAuthSessionUser {
    session: Session,
    user: User,
    account: Account,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleOAuthUserInfoResult {
    pub data: Option<OAuthSessionUser>,
    pub error: Option<OAuthUserInfoError>,
    pub is_register: bool,
    pub cookies: Vec<Cookie>,
}

pub async fn handle_oauth_user_info(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    input: HandleOAuthUserInfoInput,
) -> Result<HandleOAuthUserInfoResult, OpenAuthError> {
    let users = DbUserStore::new(adapter);
    let normalized_email = input.user_info.email.to_lowercase();
    let db_user = users
        .find_oauth_user(
            &normalized_email,
            &input.account.account_id,
            &input.account.provider_id,
        )
        .await?;
    let mut user = db_user.as_ref().map(|lookup| lookup.user.clone());
    let account_cookie;
    let is_register = user.is_none();
    let mut created_session = None;

    if let Some(lookup) = db_user {
        let linked_account = lookup.linked_account.or_else(|| {
            lookup
                .accounts
                .iter()
                .find(|account| {
                    account.provider_id == input.account.provider_id
                        && account.account_id == input.account.account_id
                })
                .cloned()
        });
        if let Some(linked_account) = linked_account {
            account_cookie = Some(
                update_linked_account(context, &users, &linked_account, &input.account).await?,
            );
            if input.override_user_info {
                user = override_linked_user_info(&users, &lookup.user, &input.user_info).await?;
            } else if input.user_info.email_verified
                && !lookup.user.email_verified
                && same_email(&input.user_info.email, &lookup.user.email)
            {
                user = users
                    .update_user_email_verified(&lookup.user.id, true)
                    .await?
                    .or(user);
            }
        } else if !can_implicitly_link(context, &input) {
            return Ok(result_error(OAuthUserInfoError::AccountNotLinked, false));
        } else {
            let account = account_input(context, &input.account, &lookup.user.id)?;
            let linked_account = users
                .link_account(account)
                .await
                .map_err(|_| OpenAuthError::Adapter("unable to link OAuth account".to_owned()))?;
            account_cookie = Some(linked_account);
            if input.user_info.email_verified
                && !lookup.user.email_verified
                && same_email(&input.user_info.email, &lookup.user.email)
            {
                user = users
                    .update_user_email_verified(&lookup.user.id, true)
                    .await?
                    .or(Some(lookup.user));
            } else {
                user = Some(lookup.user);
            }
        }
    } else {
        if input.disable_sign_up {
            return Ok(result_error(OAuthUserInfoError::SignupDisabled, false));
        }
        let mut user_input = CreateUserInput::new(input.user_info.name.clone(), normalized_email)
            .email_verified(input.user_info.email_verified);
        if let Some(image) = input.user_info.image.clone() {
            user_input = user_input.image(image);
        }
        let created = create_oauth_session_user(
            context,
            adapter,
            user_input,
            account_input(context, &input.account, "")?,
        )
        .await?;
        account_cookie = Some(created.account);
        created_session = Some(created.session);
        user = Some(created.user);
    }

    let Some(user) = user else {
        return Ok(result_error(OAuthUserInfoError::UnableToCreateUser, false));
    };
    let session = match created_session {
        Some(session) => session,
        None => SessionStore::new(adapter, context)
            .create_session(CreateSessionInput::new(
                &user.id,
                OffsetDateTime::now_utc()
                    + Duration::seconds(context.session_config.expires_in as i64),
            ))
            .await
            .map_err(|_| OpenAuthError::Adapter("unable to create OAuth session".to_owned()))?,
    };
    let cookies = if context.options.account.store_account_cookie {
        account_cookie
            .as_ref()
            .map(|account| set_account_cookie(context, account))
            .transpose()?
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Ok(HandleOAuthUserInfoResult {
        data: Some(OAuthSessionUser { session, user }),
        error: None,
        is_register,
        cookies,
    })
}

async fn create_oauth_session_user(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    user_input: CreateUserInput,
    account_input: CreateOAuthAccountInput,
) -> Result<CreatedOAuthSessionUser, OpenAuthError> {
    let result = Arc::new(Mutex::new(None));
    let result_for_transaction = Arc::clone(&result);
    let expires_in = context.session_config.expires_in;
    let secondary_storage = context.secondary_storage();
    let store_session_in_database = context.options.session.store_session_in_database;
    let preserve_session_in_database = context.options.session.preserve_session_in_database;
    let transaction_status = adapter
        .transaction(Box::new(move |transaction| {
            let secondary_storage = secondary_storage.clone();
            Box::pin(async move {
                let users = DbUserStore::new(transaction.as_ref());
                let created = users
                    .create_oauth_user(user_input, account_input)
                    .await
                    .map_err(|_| {
                        OpenAuthError::Adapter("unable to create OAuth user".to_owned())
                    })?;
                let session = SessionStore::with_storage(
                    transaction.as_ref(),
                    secondary_storage,
                    store_session_in_database,
                    preserve_session_in_database,
                )
                .create_session(CreateSessionInput::new(
                    &created.user.id,
                    OffsetDateTime::now_utc() + Duration::seconds(expires_in as i64),
                ))
                .await
                .map_err(|_| OpenAuthError::Adapter("unable to create OAuth session".to_owned()))?;
                store_created_oauth_session_user(
                    &result_for_transaction,
                    CreatedOAuthSessionUser {
                        session,
                        user: created.user,
                        account: created.account,
                    },
                )?;
                Ok(())
            })
        }))
        .await;

    match transaction_status {
        Ok(()) => take_created_oauth_session_user(&result)?.ok_or_else(|| {
            OpenAuthError::Adapter(
                "create OAuth session transaction completed without a result".to_owned(),
            )
        }),
        Err(error) => Err(error),
    }
}

fn store_created_oauth_session_user(
    result: &Mutex<Option<CreatedOAuthSessionUser>>,
    value: CreatedOAuthSessionUser,
) -> Result<(), OpenAuthError> {
    let mut guard = result.lock().map_err(|_| OpenAuthError::LockPoisoned {
        context: "create OAuth session result",
    })?;
    *guard = Some(value);
    Ok(())
}

fn take_created_oauth_session_user(
    result: &Mutex<Option<CreatedOAuthSessionUser>>,
) -> Result<Option<CreatedOAuthSessionUser>, OpenAuthError> {
    result
        .lock()
        .map_err(|_| OpenAuthError::LockPoisoned {
            context: "create OAuth session result",
        })
        .map(|mut guard| guard.take())
}

fn can_implicitly_link(context: &AuthContext, input: &HandleOAuthUserInfoInput) -> bool {
    let linking = &context.options.account.account_linking;
    if !linking.enabled || linking.disable_implicit_linking {
        return false;
    }
    let trusted = input.is_trusted_provider
        || linking
            .trusted_providers
            .iter()
            .any(|provider| provider == &input.account.provider_id);
    if input.require_trusted_provider_for_implicit_link {
        return trusted;
    }
    trusted || input.user_info.email_verified
}

async fn update_linked_account(
    context: &AuthContext,
    users: &DbUserStore<'_>,
    linked_account: &Account,
    account: &OAuthAccountInput,
) -> Result<Account, OpenAuthError> {
    if !context.options.account.update_account_on_sign_in {
        return Ok(linked_account.clone());
    }
    let updated = users
        .update_account(&linked_account.id, account_update_input(context, account)?)
        .await?;
    Ok(updated.unwrap_or_else(|| linked_account.clone()))
}

fn set_account_cookie(
    context: &AuthContext,
    account: &Account,
) -> Result<Vec<Cookie>, OpenAuthError> {
    let max_age = context
        .auth_cookies
        .account_data
        .attributes
        .max_age
        .unwrap_or(60 * 5);
    #[cfg(feature = "jose")]
    let data = symmetric_encode_jwt_with_salt(
        account,
        &context.secret_config,
        ACCOUNT_COOKIE_SALT,
        max_age,
    )?;
    #[cfg(not(feature = "jose"))]
    let data = encode_account_cookie_data(account)?;
    let mut attributes = context.auth_cookies.account_data.attributes.clone();
    attributes.max_age = Some(max_age);
    Ok(ChunkedCookieStore::new(
        context.auth_cookies.account_data.name.clone(),
        attributes,
        "",
    )
    .chunk(&data))
}

#[cfg(not(feature = "jose"))]
fn encode_account_cookie_data(_account: &Account) -> Result<String, OpenAuthError> {
    Err(OpenAuthError::FeatureDisabled { feature: "jose" })
}

async fn override_linked_user_info(
    users: &DbUserStore<'_>,
    existing: &User,
    provider: &OAuthUserInfo,
) -> Result<Option<User>, OpenAuthError> {
    let normalized_email = provider.email.to_lowercase();
    let email_verified = if normalized_email == existing.email {
        existing.email_verified || provider.email_verified
    } else {
        provider.email_verified
    };
    let updated = users
        .update_user(
            &existing.id,
            UpdateUserInput::new()
                .name(provider.name.clone())
                .image(provider.image.clone()),
        )
        .await?;
    users
        .update_user_email(&existing.id, &normalized_email, email_verified)
        .await
        .map(|user| user.or(updated))
}

fn account_input(
    context: &AuthContext,
    account: &OAuthAccountInput,
    user_id: &str,
) -> Result<CreateOAuthAccountInput, OpenAuthError> {
    Ok(CreateOAuthAccountInput {
        id: None,
        provider_id: account.provider_id.clone(),
        account_id: account.account_id.clone(),
        user_id: user_id.to_owned(),
        access_token: set_token_util(account.access_token.as_deref(), context)?,
        refresh_token: set_token_util(account.refresh_token.as_deref(), context)?,
        id_token: account.id_token.clone(),
        access_token_expires_at: account.access_token_expires_at,
        refresh_token_expires_at: account.refresh_token_expires_at,
        scope: account.scope.clone(),
    })
}

fn account_update_input(
    context: &AuthContext,
    account: &OAuthAccountInput,
) -> Result<UpdateAccountInput, OpenAuthError> {
    let mut input = UpdateAccountInput::default();
    if account.access_token.is_some() {
        input.access_token = Some(set_token_util(account.access_token.as_deref(), context)?);
    }
    if account.refresh_token.is_some() {
        input.refresh_token = Some(set_token_util(account.refresh_token.as_deref(), context)?);
    }
    if account.id_token.is_some() {
        input.id_token = Some(account.id_token.clone());
    }
    if account.access_token_expires_at.is_some() {
        input.access_token_expires_at = Some(account.access_token_expires_at);
    }
    if account.refresh_token_expires_at.is_some() {
        input.refresh_token_expires_at = Some(account.refresh_token_expires_at);
    }
    if account.scope.is_some() {
        input.scope = Some(account.scope.clone());
    }
    Ok(input)
}

fn same_email(provider_email: &str, user_email: &str) -> bool {
    provider_email.eq_ignore_ascii_case(user_email)
}

fn result_error(error: OAuthUserInfoError, is_register: bool) -> HandleOAuthUserInfoResult {
    HandleOAuthUserInfoResult {
        data: None,
        error: Some(error),
        is_register,
        cookies: Vec::new(),
    }
}
