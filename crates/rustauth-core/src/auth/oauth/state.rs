use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use crate::context::AuthContext;
use crate::crypto::random::generate_random_string;
use crate::db::DbAdapter;
use crate::error::RustAuthError;
use crate::options::OAuthStateStoreStrategy;
use crate::verification::{CreateVerificationInput, DbVerificationStore};

use super::tokens::{decrypt_with_context, encrypt_with_context};

fn verification_store<'a>(
    context: &'a AuthContext,
    adapter: &'a dyn DbAdapter,
) -> DbVerificationStore<'a> {
    DbVerificationStore::with_options(
        adapter,
        context.db_schema.clone(),
        context.options.verification.clone(),
    )
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthStateLink {
    pub email: String,
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthStateData {
    pub callback_url: String,
    pub code_verifier: String,
    pub oauth_state: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthStateParseInput<'a> {
    pub state: &'a str,
    pub oauth_state: Option<&'a str>,
    pub skip_state_cookie_check: bool,
}

pub async fn generate_oauth_state(
    context: &AuthContext,
    adapter: Option<&dyn DbAdapter>,
    input: OAuthStateInput,
) -> Result<GeneratedOAuthState, RustAuthError> {
    if input.callback_url.is_empty() {
        return Err(RustAuthError::Api("callback URL is required".to_owned()));
    }
    let data = OAuthStateData {
        callback_url: input.callback_url,
        code_verifier: generate_random_string(128),
        oauth_state: generate_random_string(32),
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
                .map_err(|error| RustAuthError::Crypto(error.to_string()))?;
            let encrypted = encrypt_with_context(&json, context)?;
            // Cookie-mode state is single-use: persist a server-side marker bound
            // to this exact ciphertext. `parse_oauth_state` consumes the marker on
            // first use, so a captured `state` cannot be replayed within its TTL
            // (OPE-19). Without an adapter we cannot store a marker, so we fall back
            // to the legacy stateless behavior.
            if let Some(adapter) = adapter {
                verification_store(context, adapter)
                    .create_verification(CreateVerificationInput::new(
                        cookie_state_single_use_identifier(&encrypted),
                        String::new(),
                        data.expires_at,
                    ))
                    .await?;
            }
            encrypted
        }
        OAuthStateStoreStrategy::Database => {
            let adapter = adapter.ok_or_else(|| {
                RustAuthError::Adapter("database OAuth state requires an adapter".to_owned())
            })?;
            let state = generate_random_string(32);
            let json = serde_json::to_string(&data)
                .map_err(|error| RustAuthError::Crypto(error.to_string()))?;
            verification_store(context, adapter)
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
) -> Result<OAuthStateData, RustAuthError> {
    parse_oauth_state_with_input(
        context,
        adapter,
        OAuthStateParseInput {
            state,
            oauth_state: None,
            skip_state_cookie_check: true,
        },
    )
    .await
}

pub async fn parse_oauth_state_with_input(
    context: &AuthContext,
    adapter: Option<&dyn DbAdapter>,
    input: OAuthStateParseInput<'_>,
) -> Result<OAuthStateData, RustAuthError> {
    let state = input.state;
    let data = match context.options.account.store_state_strategy {
        OAuthStateStoreStrategy::Cookie => {
            // Enforce single-use when a server-side marker exists. Cookie-mode
            // states generated with an adapter create a marker at generation time;
            // atomically consuming it here rejects replays and parallel callbacks
            // (OPE-19, OPE-106). A missing marker means the state was already
            // consumed or never issued with an adapter.
            if let Some(adapter) = adapter {
                let verifications = verification_store(context, adapter);
                let identifier = cookie_state_single_use_identifier(state);
                if verifications
                    .consume_verification_including_expired(&identifier)
                    .await?
                    .is_none()
                {
                    return Err(RustAuthError::Api("invalid OAuth state".to_owned()));
                }
            }
            let json = decrypt_with_context(state, context)?;
            serde_json::from_str::<OAuthStateData>(&json)
                .map_err(|error| RustAuthError::Crypto(error.to_string()))?
        }
        OAuthStateStoreStrategy::Database => {
            let adapter = adapter.ok_or_else(|| {
                RustAuthError::Adapter("database OAuth state requires an adapter".to_owned())
            })?;
            let verifications = verification_store(context, adapter);
            let identifier = oauth_state_identifier(state);
            let verification = verifications
                .consume_verification_including_expired(&identifier)
                .await?
                .ok_or_else(|| RustAuthError::Api("invalid OAuth state".to_owned()))?;
            serde_json::from_str::<OAuthStateData>(&verification.value)
                .map_err(|error| RustAuthError::Crypto(error.to_string()))?
        }
    };
    if data.expires_at <= OffsetDateTime::now_utc() {
        return Err(RustAuthError::Api("OAuth state expired".to_owned()));
    }
    if !input.skip_state_cookie_check && input.oauth_state != Some(data.oauth_state.as_str()) {
        return Err(RustAuthError::Api("invalid OAuth state".to_owned()));
    }
    Ok(data)
}

pub fn oauth_state_identifier(state: &str) -> String {
    format!("oauth-state-{state}")
}

/// Verification identifier for the single-use marker of a cookie-mode OAuth
/// `state`.
///
/// The marker is keyed by the SHA-256 of the encrypted `state` so the stored
/// row never contains the ciphertext itself, stays a fixed length, and binds
/// one-to-one to the exact cookie value issued to the client.
fn cookie_state_single_use_identifier(encrypted_state: &str) -> String {
    let digest = Sha256::digest(encrypted_state.as_bytes());
    format!("oauth-state-cookie-{}", hex::encode(digest))
}
