use rustauth_core::context::AuthContext;
use rustauth_core::crypto::random::generate_random_string;
use rustauth_core::error::RustAuthError;
use rustauth_core::verification::CreateVerificationInput;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::options::PasskeyRegistrationUser;

pub const CHALLENGE_MAX_AGE_SECONDS: u64 = 60 * 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeKind {
    Registration,
    Authentication,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChallengeValue {
    pub kind: ChallengeKind,
    pub state: Value,
    pub user: Option<PasskeyRegistrationUser>,
    pub context: Option<String>,
}

pub async fn create_challenge(
    context: &AuthContext,
    value: ChallengeValue,
) -> Result<String, RustAuthError> {
    let token = generate_random_string(32);
    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(CHALLENGE_MAX_AGE_SECONDS as i64);
    context
        .verifications()?
        .create_verification(CreateVerificationInput::new(
            token.clone(),
            serde_json::to_string(&value).map_err(|error| RustAuthError::Api(error.to_string()))?,
            expires_at,
        ))
        .await?;
    Ok(token)
}

/// Consume a challenge token so it cannot be verified again.
pub async fn consume_challenge(
    context: &AuthContext,
    token: &str,
) -> Result<Option<ChallengeValue>, RustAuthError> {
    context
        .verifications()?
        .take_verification(token)
        .await?
        .map(|verification| {
            serde_json::from_str::<ChallengeValue>(&verification.value)
                .map_err(|error| RustAuthError::Api(error.to_string()))
        })
        .transpose()
}
