use fred::clients::Client;
use fred::interfaces::ClientLike;
use fred::prelude::{Builder, Config};
use fred::types::scripts::Script;
use rustauth_core::error::RustAuthError;
use rustauth_core::options::{
    validate_rate_limit_rule, RateLimitConsumeInput, RateLimitDecision, RateLimitFuture,
    RateLimitStore,
};

use crate::config::FredRateLimitOptions;
use crate::error::fred_error;
use crate::script::{parse_rate_limit_script_result, RATE_LIMIT_SCRIPT};
use crate::url::normalize_fred_url;

#[derive(Clone)]
pub struct FredRateLimitStore {
    client: Client,
    options: FredRateLimitOptions,
    script: Script,
}

impl FredRateLimitStore {
    pub async fn connect(url: &str) -> Result<Self, RustAuthError> {
        Self::connect_with_options(url, FredRateLimitOptions::default()).await
    }

    pub async fn connect_with_options(
        url: &str,
        options: FredRateLimitOptions,
    ) -> Result<Self, RustAuthError> {
        let client = connect_client(url).await?;
        Ok(Self::new(client, options))
    }

    pub fn new(client: Client, options: FredRateLimitOptions) -> Self {
        Self {
            client,
            options,
            script: Script::from_lua(RATE_LIMIT_SCRIPT),
        }
    }

    fn key(&self, key: &str) -> Result<String, RustAuthError> {
        validate_rate_limit_key_prefix(&self.options.key_prefix)?;
        Ok(format!("{}rate-limit:{key}", self.options.key_prefix))
    }
}

fn validate_rate_limit_key_prefix(prefix: &str) -> Result<(), RustAuthError> {
    if prefix.is_empty() {
        return Err(RustAuthError::InvalidConfig(
            "rate limit key prefix must not be empty".to_owned(),
        ));
    }
    Ok(())
}

impl RateLimitStore for FredRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move {
            let window_ms = validate_rate_limit_rule(&input.rule)?;
            let redis_key = self.key(&input.key)?;
            let result = self
                .script
                .evalsha_with_reload(
                    &self.client,
                    vec![redis_key],
                    vec![
                        input.now_ms.to_string(),
                        window_ms.to_string(),
                        input.rule.max.to_string(),
                    ],
                )
                .await
                .map_err(|error| fred_error("eval rate limit script", error))?;
            let result = parse_rate_limit_script_result(result)?;
            let retry_ms = result
                .last_request
                .saturating_add(window_ms)
                .saturating_sub(input.now_ms)
                .max(0);
            Ok(RateLimitDecision {
                permitted: result.permitted,
                retry_after: if result.permitted {
                    0
                } else {
                    ceil_millis_to_seconds(retry_ms)
                },
                limit: input.rule.max,
                remaining: input.rule.max.saturating_sub(result.count),
                reset_after: ceil_millis_to_seconds(retry_ms),
            })
        })
    }
}

pub(crate) async fn connect_client(url: &str) -> Result<Client, RustAuthError> {
    let url = normalize_fred_url(url);
    let config = Config::from_url(url.as_ref()).map_err(|error| fred_error("parse url", error))?;
    let client = Builder::from_config(config)
        .build()
        .map_err(|error| fred_error("build client", error))?;
    client
        .init()
        .await
        .map_err(|error| fred_error("connect", error))?;
    Ok(client)
}

fn ceil_millis_to_seconds(milliseconds: i64) -> u64 {
    if milliseconds <= 0 {
        return 0;
    }
    ((milliseconds as u64).saturating_add(999)) / 1000
}
