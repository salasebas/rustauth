use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::context::AuthContext;
use crate::cookies::{ChunkedCookieStore, Cookie};
use crate::crypto::symmetric_encode_jwt_with_salt;
use crate::db::{Account, DbAdapter, Session, User};
use crate::error::OpenAuthError;
use crate::session::{CreateSessionInput, DbSessionStore};
use crate::user::{
    CreateOAuthAccountInput, CreateUserInput, DbUserStore, UpdateAccountInput, UpdateUserInput,
};

use super::errors::OAuthUserInfoError;
use super::tokens::set_token_util;

const ACCOUNT_COOKIE_SALT: &str = "better-auth-account";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub id: String,
    pub name: String,
    pub email: String,
    pub image: Option<String>,
    pub email_verified: bool,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthSessionUser {
    pub session: Session,
    pub user: User,
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
        let created = users
            .create_oauth_user(user_input, account_input(context, &input.account, "")?)
            .await
            .map_err(|_| OpenAuthError::Adapter("unable to create OAuth user".to_owned()))?;
        account_cookie = Some(created.account);
        user = Some(created.user);
    }

    let Some(user) = user else {
        return Ok(result_error(OAuthUserInfoError::UnableToCreateUser, false));
    };
    let session = DbSessionStore::new(adapter)
        .create_session(CreateSessionInput::new(
            &user.id,
            OffsetDateTime::now_utc() + Duration::seconds(context.session_config.expires_in as i64),
        ))
        .await
        .map_err(|_| OpenAuthError::Adapter("unable to create OAuth session".to_owned()))?;
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
        .update_account(
            &linked_account.id,
            UpdateAccountInput {
                access_token: Some(set_token_util(account.access_token.as_deref(), context)?),
                refresh_token: Some(set_token_util(account.refresh_token.as_deref(), context)?),
                id_token: Some(account.id_token.clone()),
                access_token_expires_at: Some(account.access_token_expires_at),
                refresh_token_expires_at: Some(account.refresh_token_expires_at),
                scope: Some(account.scope.clone()),
            },
        )
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
    let data = symmetric_encode_jwt_with_salt(
        account,
        &context.secret_config,
        ACCOUNT_COOKIE_SALT,
        max_age,
    )?;
    let mut attributes = context.auth_cookies.account_data.attributes.clone();
    attributes.max_age = Some(max_age);
    Ok(ChunkedCookieStore::new(
        context.auth_cookies.account_data.name.clone(),
        attributes,
        "",
    )
    .chunk(&data))
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
