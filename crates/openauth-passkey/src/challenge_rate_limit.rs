use http::Request;
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use openauth_core::rate_limit::{consume_scoped_rate_limit, RateLimitRejection};
use openauth_core::utils::url::normalize_pathname;

use crate::options::PasskeyOptions;

pub async fn consume_verify_challenge_rate_limit(
    context: &AuthContext,
    options: &PasskeyOptions,
    request: &Request<Vec<u8>>,
    path: &str,
    challenge_token: &str,
) -> Result<Option<RateLimitRejection>, OpenAuthError> {
    let Some(rule) = options.challenge_rate_limit.rule() else {
        return Ok(None);
    };
    let path = normalize_pathname(path, &context.base_path);
    consume_scoped_rate_limit(context, request, &path, challenge_token, rule).await
}
