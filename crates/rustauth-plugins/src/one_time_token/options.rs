use std::sync::Arc;

use rustauth_core::context::AuthContext;
use rustauth_core::db::{Session, User};
use rustauth_core::error::RustAuthError;
use time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimeTokenSession {
    pub session: Session,
    pub user: User,
}

pub type GenerateToken =
    Arc<dyn Fn(&OneTimeTokenSession, &AuthContext) -> Result<String, RustAuthError> + Send + Sync>;
pub type HashToken = Arc<dyn Fn(&str) -> Result<String, RustAuthError> + Send + Sync>;

#[derive(Clone)]
pub enum StoreToken {
    Plain,
    Hashed,
    Custom(HashToken),
}

impl StoreToken {
    pub fn custom<F>(hash: F) -> Self
    where
        F: Fn(&str) -> Result<String, RustAuthError> + Send + Sync + 'static,
    {
        Self::Custom(Arc::new(hash))
    }
}

#[derive(Clone)]
pub struct OneTimeTokenOptions {
    pub expires_in: Duration,
    pub disable_client_request: bool,
    pub generate_token: Option<GenerateToken>,
    pub disable_set_session_cookie: bool,
    pub store_token: StoreToken,
    pub set_ott_header_on_new_session: bool,
}

impl Default for OneTimeTokenOptions {
    fn default() -> Self {
        Self {
            expires_in: Duration::minutes(3),
            disable_client_request: false,
            generate_token: None,
            disable_set_session_cookie: false,
            store_token: StoreToken::Plain,
            set_ott_header_on_new_session: false,
        }
    }
}

impl OneTimeTokenOptions {
    #[must_use]
    pub fn expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = expires_in;
        self
    }

    #[must_use]
    pub fn disable_client_request(mut self, disable: bool) -> Self {
        self.disable_client_request = disable;
        self
    }

    #[must_use]
    pub fn generate_token<F>(mut self, generate: F) -> Self
    where
        F: Fn(&OneTimeTokenSession, &AuthContext) -> Result<String, RustAuthError>
            + Send
            + Sync
            + 'static,
    {
        self.generate_token = Some(Arc::new(generate));
        self
    }

    #[must_use]
    pub fn disable_set_session_cookie(mut self, disable: bool) -> Self {
        self.disable_set_session_cookie = disable;
        self
    }

    #[must_use]
    pub fn store_token(mut self, store_token: StoreToken) -> Self {
        self.store_token = store_token;
        self
    }

    #[must_use]
    pub fn set_ott_header_on_new_session(mut self, set_header: bool) -> Self {
        self.set_ott_header_on_new_session = set_header;
        self
    }

    #[must_use]
    pub fn builder() -> OneTimeTokenOptionsBuilder {
        OneTimeTokenOptionsBuilder::default()
    }

    pub(crate) fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "expiresIn": self.expires_in.whole_minutes(),
            "disableClientRequest": self.disable_client_request,
            "disableSetSessionCookie": self.disable_set_session_cookie,
            "storeToken": self.store_token.as_metadata_value(),
            "setOttHeaderOnNewSession": self.set_ott_header_on_new_session,
        })
    }
}

#[derive(Clone, Default)]
pub struct OneTimeTokenOptionsBuilder {
    expires_in: Option<Duration>,
    disable_client_request: Option<bool>,
    generate_token: Option<GenerateToken>,
    disable_set_session_cookie: Option<bool>,
    store_token: Option<StoreToken>,
    set_ott_header_on_new_session: Option<bool>,
}

impl OneTimeTokenOptionsBuilder {
    pub fn build(self) -> OneTimeTokenOptions {
        let defaults = OneTimeTokenOptions::default();
        OneTimeTokenOptions {
            expires_in: self.expires_in.unwrap_or(defaults.expires_in),
            disable_client_request: self
                .disable_client_request
                .unwrap_or(defaults.disable_client_request),
            generate_token: self.generate_token.or(defaults.generate_token),
            disable_set_session_cookie: self
                .disable_set_session_cookie
                .unwrap_or(defaults.disable_set_session_cookie),
            store_token: self.store_token.unwrap_or(defaults.store_token),
            set_ott_header_on_new_session: self
                .set_ott_header_on_new_session
                .unwrap_or(defaults.set_ott_header_on_new_session),
        }
    }
}

impl StoreToken {
    fn as_metadata_value(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Hashed => "hashed",
            Self::Custom(_) => "custom-hasher",
        }
    }
}
