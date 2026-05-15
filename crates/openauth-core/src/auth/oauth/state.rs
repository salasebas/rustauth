use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::context::AuthContext;
use crate::crypto::random::generate_random_string;
use crate::db::DbAdapter;
use crate::error::OpenAuthError;
use crate::options::OAuthStateStoreStrategy;
use crate::verification::{CreateVerificationInput, DbVerificationStore};

use super::tokens::{decrypt_with_context, encrypt_with_context};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthStateLink {
    pub email: String,
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthStateData {
    pub callback_url: String,
    pub code_verifier: String,
    pub error_url: Option<String>,
    pub new_user_url: Option<String>,
    pub link: Option<OAuthStateLink>,
    pub expires_at: OffsetDateTime,
    pub request_sign_up: bool,
    pub additional_data: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OAuthStateInput {
    pub callback_url: String,
    pub error_url: Option<String>,
    pub new_user_url: Option<String>,
    pub link: Option<OAuthStateLink>,
    pub request_sign_up: bool,
    pub additional_data: Value,
    pub expires_at: Option<OffsetDateTime>,
}

impl Default for OAuthStateInput {
    fn default() -> Self {
        Self {
            callback_url: String::new(),
            error_url: None,
            new_user_url: None,
            link: None,
            request_sign_up: false,
            additional_data: Value::Null,
            expires_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeneratedOAuthState {
    pub state: String,
    pub data: OAuthStateData,
}

pub async fn generate_oauth_state(
    context: &AuthContext,
    adapter: Option<&dyn DbAdapter>,
    input: OAuthStateInput,
) -> Result<GeneratedOAuthState, OpenAuthError> {
    if input.callback_url.is_empty() {
        return Err(OpenAuthError::Api("callback URL is required".to_owned()));
    }
    let data = OAuthStateData {
        callback_url: input.callback_url,
        code_verifier: generate_random_string(128),
        error_url: input.error_url,
        new_user_url: input.new_user_url,
        link: input.link,
        expires_at: input
            .expires_at
            .unwrap_or_else(|| OffsetDateTime::now_utc() + Duration::minutes(10)),
        request_sign_up: input.request_sign_up,
        additional_data: input.additional_data,
    };
    let state = match context.options.account.store_state_strategy {
        OAuthStateStoreStrategy::Cookie => {
            let json = serde_json::to_string(&data)
                .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
            encrypt_with_context(&json, context)?
        }
        OAuthStateStoreStrategy::Database => {
            let adapter = adapter.ok_or_else(|| {
                OpenAuthError::Adapter("database OAuth state requires an adapter".to_owned())
            })?;
            let state = generate_random_string(32);
            let json = serde_json::to_string(&data)
                .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
            DbVerificationStore::new(adapter)
                .create_verification(CreateVerificationInput::new(
                    oauth_state_identifier(&state),
                    json,
                    data.expires_at,
                ))
                .await?;
            state
        }
    };
    Ok(GeneratedOAuthState { state, data })
}

pub async fn parse_oauth_state(
    context: &AuthContext,
    adapter: Option<&dyn DbAdapter>,
    state: &str,
) -> Result<OAuthStateData, OpenAuthError> {
    let data = match context.options.account.store_state_strategy {
        OAuthStateStoreStrategy::Cookie => {
            let json = decrypt_with_context(state, context)?;
            serde_json::from_str::<OAuthStateData>(&json)
                .map_err(|error| OpenAuthError::Crypto(error.to_string()))?
        }
        OAuthStateStoreStrategy::Database => {
            let adapter = adapter.ok_or_else(|| {
                OpenAuthError::Adapter("database OAuth state requires an adapter".to_owned())
            })?;
            let verifications = DbVerificationStore::new(adapter);
            let identifier = oauth_state_identifier(state);
            let verification = verifications
                .find_verification(&identifier)
                .await?
                .ok_or_else(|| OpenAuthError::Api("invalid OAuth state".to_owned()))?;
            let data = serde_json::from_str::<OAuthStateData>(&verification.value)
                .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
            if data.expires_at > OffsetDateTime::now_utc() {
                verifications.delete_verification(&identifier).await?;
            }
            data
        }
    };
    if data.expires_at <= OffsetDateTime::now_utc() {
        return Err(OpenAuthError::Api("OAuth state expired".to_owned()));
    }
    Ok(data)
}

pub fn oauth_state_identifier(state: &str) -> String {
    format!("oauth-state-{state}")
}
