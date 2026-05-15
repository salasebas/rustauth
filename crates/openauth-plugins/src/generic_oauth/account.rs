use openauth_core::auth::oauth::{
    set_token_util, OAuthAccountInput, OAuthStateLink, OAuthUserInfo,
};
use openauth_core::context::AuthContext;
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::user::{CreateOAuthAccountInput, DbUserStore, UpdateAccountInput};
use openauth_oauth::oauth2::{OAuth2Tokens, OAuth2UserInfo};

use super::config::GenericOAuthConfig;

pub(super) async fn link_account(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    config: &GenericOAuthConfig,
    link: &OAuthStateLink,
    info: &OAuth2UserInfo,
    tokens: &OAuth2Tokens,
) -> Result<(), OpenAuthError> {
    let normalized = normalize_user_info(info)?;
    if normalized.email.to_lowercase() != link.email.to_lowercase()
        && !context
            .options
            .account
            .account_linking
            .allow_different_emails
    {
        return Err(OpenAuthError::Api("email_doesn't_match".to_owned()));
    }
    let store = DbUserStore::new(adapter);
    if let Some(existing) = store
        .find_account_by_provider_account(&normalized.id, &config.provider_id)
        .await?
    {
        if existing.user_id != link.user_id {
            return Err(OpenAuthError::Api(
                "account_already_linked_to_different_user".to_owned(),
            ));
        }
        store
            .update_account(
                &existing.id,
                UpdateAccountInput {
                    access_token: Some(set_token_util(tokens.access_token.as_deref(), context)?),
                    refresh_token: Some(set_token_util(tokens.refresh_token.as_deref(), context)?),
                    id_token: Some(tokens.id_token.clone()),
                    access_token_expires_at: Some(tokens.access_token_expires_at),
                    refresh_token_expires_at: Some(tokens.refresh_token_expires_at),
                    scope: Some((!tokens.scopes.is_empty()).then(|| tokens.scopes.join(","))),
                },
            )
            .await?;
        return Ok(());
    }
    store
        .link_account(CreateOAuthAccountInput {
            id: None,
            provider_id: config.provider_id.clone(),
            account_id: normalized.id,
            user_id: link.user_id.clone(),
            access_token: set_token_util(tokens.access_token.as_deref(), context)?,
            refresh_token: set_token_util(tokens.refresh_token.as_deref(), context)?,
            id_token: tokens.id_token.clone(),
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
        })
        .await?;
    Ok(())
}

pub(super) fn oauth_account(
    context: &AuthContext,
    provider_id: &str,
    account_id: &str,
    tokens: &OAuth2Tokens,
) -> Result<OAuthAccountInput, OpenAuthError> {
    Ok(OAuthAccountInput {
        provider_id: provider_id.to_owned(),
        account_id: account_id.to_owned(),
        access_token: set_token_util(tokens.access_token.as_deref(), context)?,
        refresh_token: set_token_util(tokens.refresh_token.as_deref(), context)?,
        id_token: tokens.id_token.clone(),
        access_token_expires_at: tokens.access_token_expires_at,
        refresh_token_expires_at: tokens.refresh_token_expires_at,
        scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
    })
}

pub(super) fn normalize_user_info(info: &OAuth2UserInfo) -> Result<OAuthUserInfo, OpenAuthError> {
    let email = info
        .email
        .clone()
        .ok_or_else(|| OpenAuthError::Api("OAuth provider did not return an email".to_owned()))?;
    Ok(OAuthUserInfo {
        id: info.id.clone(),
        name: info.name.clone().unwrap_or_default(),
        email,
        image: info.image.clone(),
        email_verified: info.email_verified,
    })
}

pub(super) fn link_error_code(error: &OpenAuthError) -> &str {
    match error {
        OpenAuthError::Api(code) if code == "email_doesn't_match" => "email_doesn't_match",
        OpenAuthError::Api(code) if code == "account_already_linked_to_different_user" => {
            "account_already_linked_to_different_user"
        }
        _ => "unable_to_link_account",
    }
}
