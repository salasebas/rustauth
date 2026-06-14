use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::Request;
use rustauth_core::context::AuthContext;
use rustauth_core::error::RustAuthError;
use rustauth_core::options::RateLimitRule;
use rustauth_core::outbound::OutboundSendFuture;
use serde_json::Value;
use time::Duration;

use super::token::TokenStorage;

pub type MagicLinkFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RustAuthError>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq)]
pub struct MagicLinkEmail {
    pub email: String,
    pub url: String,
    pub token: String,
    pub metadata: Option<Value>,
}

#[derive(Clone, Copy)]
pub struct MagicLinkSendContext<'a> {
    pub context: &'a AuthContext,
    pub request: &'a Request<Vec<u8>>,
}

pub type SendMagicLink = Arc<dyn Fn(MagicLinkEmail) -> MagicLinkFuture<'static, ()> + Send + Sync>;
pub type SendMagicLinkWithContext = Arc<
    dyn for<'a> Fn(MagicLinkEmail, MagicLinkSendContext<'a>) -> OutboundSendFuture + Send + Sync,
>;
pub type GenerateToken = Arc<dyn for<'a> Fn(&'a str) -> MagicLinkFuture<'a, String> + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicLinkRateLimit {
    pub window: Duration,
    pub max: u64,
}

impl Default for MagicLinkRateLimit {
    fn default() -> Self {
        Self {
            window: Duration::minutes(1),
            max: 5,
        }
    }
}

#[derive(Clone)]
pub struct MagicLinkOptions {
    pub(crate) expires_in: Duration,
    pub(crate) allowed_attempts: AllowedAttempts,
    pub(crate) send_magic_link: SendMagicLinkWithContext,
    pub(crate) disable_sign_up: bool,
    pub(crate) rate_limit: MagicLinkRateLimit,
    pub(crate) generate_token: Option<GenerateToken>,
    pub(crate) store_token: TokenStorage,
}

impl MagicLinkOptions {
    pub fn new<F>(send_magic_link: F) -> Self
    where
        F: Fn(MagicLinkEmail) -> MagicLinkFuture<'static, ()> + Send + Sync + 'static,
    {
        let send_magic_link: SendMagicLink = Arc::new(send_magic_link);
        Self::new_with_context(move |email, _ctx| {
            let send_magic_link = Arc::clone(&send_magic_link);
            send_magic_link(email)
        })
    }

    pub fn new_with_context<F>(send_magic_link: F) -> Self
    where
        F: for<'a> Fn(MagicLinkEmail, MagicLinkSendContext<'a>) -> OutboundSendFuture
            + Send
            + Sync
            + 'static,
    {
        Self {
            expires_in: Duration::minutes(5),
            allowed_attempts: AllowedAttempts::Limited(1),
            send_magic_link: Arc::new(send_magic_link),
            disable_sign_up: false,
            rate_limit: MagicLinkRateLimit::default(),
            generate_token: None,
            store_token: TokenStorage::Plain,
        }
    }

    #[must_use]
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = expires_in;
        self
    }

    #[must_use]
    pub fn allowed_attempts(mut self, attempts: u64) -> Self {
        self.allowed_attempts = AllowedAttempts::Limited(attempts);
        self
    }

    #[must_use]
    pub fn unlimited_attempts(mut self) -> Self {
        self.allowed_attempts = AllowedAttempts::Unlimited;
        self
    }

    #[must_use]
    pub fn disable_sign_up(mut self, disabled: bool) -> Self {
        self.disable_sign_up = disabled;
        self
    }

    #[must_use]
    pub fn rate_limit(mut self, rate_limit: MagicLinkRateLimit) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    #[must_use]
    pub fn generate_token<F>(mut self, generate_token: F) -> Self
    where
        F: for<'a> Fn(&'a str) -> MagicLinkFuture<'a, String> + Send + Sync + 'static,
    {
        self.generate_token = Some(Arc::new(generate_token));
        self
    }

    #[must_use]
    pub fn store_token(mut self, store_token: TokenStorage) -> Self {
        self.store_token = store_token;
        self
    }

    pub(crate) fn rate_limit_rule(&self) -> RateLimitRule {
        RateLimitRule {
            window: self.rate_limit.window,
            max: self.rate_limit.max,
        }
    }

    #[must_use]
    pub fn builder() -> MagicLinkOptionsBuilder {
        MagicLinkOptionsBuilder::default()
    }
}

#[derive(Clone, Default)]
pub struct MagicLinkOptionsBuilder {
    send_magic_link: Option<SendMagicLinkWithContext>,
    expires_in: Option<Duration>,
    allowed_attempts: Option<AllowedAttempts>,
    disable_sign_up: Option<bool>,
    rate_limit: Option<MagicLinkRateLimit>,
    generate_token: Option<GenerateToken>,
    store_token: Option<TokenStorage>,
}

impl MagicLinkOptionsBuilder {
    #[must_use]
    pub fn send_magic_link<F>(mut self, send_magic_link: F) -> Self
    where
        F: for<'a> Fn(MagicLinkEmail, MagicLinkSendContext<'a>) -> OutboundSendFuture
            + Send
            + Sync
            + 'static,
    {
        self.send_magic_link = Some(Arc::new(send_magic_link));
        self
    }

    pub fn build(self) -> Result<MagicLinkOptions, rustauth_core::error::RustAuthError> {
        let Some(send_magic_link) = self.send_magic_link else {
            return Err(rustauth_core::error::RustAuthError::InvalidConfig(
                "magic-link plugin requires a send_magic_link callback".to_owned(),
            ));
        };
        Ok(MagicLinkOptions {
            expires_in: self.expires_in.unwrap_or(Duration::minutes(5)),
            allowed_attempts: self.allowed_attempts.unwrap_or(AllowedAttempts::Limited(1)),
            send_magic_link,
            disable_sign_up: self.disable_sign_up.unwrap_or(false),
            rate_limit: self.rate_limit.unwrap_or_default(),
            generate_token: self.generate_token,
            store_token: self.store_token.unwrap_or(TokenStorage::Plain),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AllowedAttempts {
    Limited(u64),
    Unlimited,
}

impl AllowedAttempts {
    pub(crate) fn exceeded(self, attempt: u64) -> bool {
        match self {
            Self::Limited(limit) => attempt >= limit,
            Self::Unlimited => false,
        }
    }
}
