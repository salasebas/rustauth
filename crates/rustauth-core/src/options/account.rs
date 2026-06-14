use std::fmt;
use std::sync::Arc;

use crate::api::ApiRequest;
use crate::error::RustAuthError;

use super::model_schema::ModelSchemaOptions;

pub trait TrustedProvidersProvider: Send + Sync + 'static {
    fn trusted_providers(&self) -> Result<Vec<String>, RustAuthError>;
}

impl<F> TrustedProvidersProvider for F
where
    F: Fn() -> Result<Vec<String>, RustAuthError> + Send + Sync + 'static,
{
    fn trusted_providers(&self) -> Result<Vec<String>, RustAuthError> {
        self()
    }
}

pub trait TrustedProvidersRequestProvider: Send + Sync + 'static {
    fn trusted_providers_for_request(
        &self,
        request: Option<&ApiRequest>,
    ) -> Result<Vec<String>, RustAuthError>;
}

impl<F> TrustedProvidersRequestProvider for F
where
    F: for<'a> Fn(Option<&'a ApiRequest>) -> Result<Vec<String>, RustAuthError>
        + Send
        + Sync
        + 'static,
{
    fn trusted_providers_for_request(
        &self,
        request: Option<&ApiRequest>,
    ) -> Result<Vec<String>, RustAuthError> {
        self(request)
    }
}

/// Account and OAuth account behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountOptions {
    pub schema: ModelSchemaOptions,
    pub update_account_on_sign_in: bool,
    pub encrypt_oauth_tokens: bool,
    pub store_account_cookie: bool,
    pub store_state_strategy: OAuthStateStoreStrategy,
    pub skip_state_cookie_check: bool,
    pub account_linking: AccountLinkingOptions,
}

impl Default for AccountOptions {
    fn default() -> Self {
        Self {
            schema: ModelSchemaOptions::default(),
            update_account_on_sign_in: true,
            encrypt_oauth_tokens: false,
            store_account_cookie: false,
            store_state_strategy: OAuthStateStoreStrategy::Cookie,
            skip_state_cookie_check: false,
            account_linking: AccountLinkingOptions::default(),
        }
    }
}

impl AccountOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn schema(mut self, schema: ModelSchemaOptions) -> Self {
        self.schema = schema;
        self
    }

    #[must_use]
    pub fn update_account_on_sign_in(mut self, enabled: bool) -> Self {
        self.update_account_on_sign_in = enabled;
        self
    }

    #[must_use]
    pub fn encrypt_oauth_tokens(mut self, enabled: bool) -> Self {
        self.encrypt_oauth_tokens = enabled;
        self
    }

    #[must_use]
    pub fn store_account_cookie(mut self, enabled: bool) -> Self {
        self.store_account_cookie = enabled;
        self
    }

    #[must_use]
    pub fn store_state_strategy(mut self, strategy: OAuthStateStoreStrategy) -> Self {
        self.store_state_strategy = strategy;
        self
    }

    #[must_use]
    pub fn skip_state_cookie_check(mut self, skip: bool) -> Self {
        self.skip_state_cookie_check = skip;
        self
    }

    #[must_use]
    pub fn account_linking(mut self, account_linking: AccountLinkingOptions) -> Self {
        self.account_linking = account_linking;
        self
    }
}

/// Where the OAuth `state` (and the PKCE verifier / OIDC nonce it carries) is
/// persisted between the authorization redirect and the callback.
///
/// Both strategies enforce single-use semantics: the `state` is consumed on the
/// first successful callback, so a captured value cannot be replayed within its
/// TTL. `Cookie` keeps the payload in an encrypted, client-held value and binds
/// it to a short server-side single-use marker; `Database` stores the full
/// payload server-side and deletes it on first use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OAuthStateStoreStrategy {
    #[default]
    Cookie,
    Database,
}

#[derive(Clone)]
pub struct AccountLinkingOptions {
    pub enabled: bool,
    pub disable_implicit_linking: bool,
    pub trusted_providers: Vec<String>,
    pub trusted_providers_provider: Option<Arc<dyn TrustedProvidersProvider>>,
    pub trusted_providers_request_provider: Option<Arc<dyn TrustedProvidersRequestProvider>>,
    pub allow_different_emails: bool,
    pub allow_unlinking_all: bool,
    pub update_user_info_on_link: bool,
}

impl Default for AccountLinkingOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            disable_implicit_linking: false,
            trusted_providers: Vec::new(),
            trusted_providers_provider: None,
            trusted_providers_request_provider: None,
            allow_different_emails: false,
            allow_unlinking_all: false,
            update_user_info_on_link: false,
        }
    }
}

impl AccountLinkingOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    #[must_use]
    pub fn disable_implicit_linking(mut self, enabled: bool) -> Self {
        self.disable_implicit_linking = enabled;
        self
    }

    #[must_use]
    pub fn trusted_provider(mut self, provider: impl Into<String>) -> Self {
        self.trusted_providers.push(provider.into());
        self
    }

    #[must_use]
    pub fn trusted_providers<I, S>(mut self, providers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.trusted_providers
            .extend(providers.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn trusted_providers_provider<P>(mut self, provider: P) -> Self
    where
        P: TrustedProvidersProvider,
    {
        self.trusted_providers_provider = Some(Arc::new(provider));
        self
    }

    #[must_use]
    pub fn trusted_providers_for_request_provider<P>(mut self, provider: P) -> Self
    where
        P: TrustedProvidersRequestProvider,
    {
        self.trusted_providers_request_provider = Some(Arc::new(provider));
        self
    }

    #[must_use]
    pub fn allow_different_emails(mut self, enabled: bool) -> Self {
        self.allow_different_emails = enabled;
        self
    }

    #[must_use]
    pub fn allow_unlinking_all(mut self, enabled: bool) -> Self {
        self.allow_unlinking_all = enabled;
        self
    }

    #[must_use]
    pub fn update_user_info_on_link(mut self, enabled: bool) -> Self {
        self.update_user_info_on_link = enabled;
        self
    }
}

impl fmt::Debug for AccountLinkingOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountLinkingOptions")
            .field("enabled", &self.enabled)
            .field("disable_implicit_linking", &self.disable_implicit_linking)
            .field("trusted_providers", &self.trusted_providers)
            .field(
                "trusted_providers_provider",
                &self
                    .trusted_providers_provider
                    .as_ref()
                    .map(|_| "<dynamic>"),
            )
            .field(
                "trusted_providers_request_provider",
                &self
                    .trusted_providers_request_provider
                    .as_ref()
                    .map(|_| "<request-dynamic>"),
            )
            .field("allow_different_emails", &self.allow_different_emails)
            .field("allow_unlinking_all", &self.allow_unlinking_all)
            .field("update_user_info_on_link", &self.update_user_info_on_link)
            .finish()
    }
}

impl PartialEq for AccountLinkingOptions {
    fn eq(&self, other: &Self) -> bool {
        self.enabled == other.enabled
            && self.disable_implicit_linking == other.disable_implicit_linking
            && self.trusted_providers == other.trusted_providers
            && self.trusted_providers_provider.is_some()
                == other.trusted_providers_provider.is_some()
            && self.trusted_providers_request_provider.is_some()
                == other.trusted_providers_request_provider.is_some()
            && self.allow_different_emails == other.allow_different_emails
            && self.allow_unlinking_all == other.allow_unlinking_all
            && self.update_user_info_on_link == other.update_user_info_on_link
    }
}

impl Eq for AccountLinkingOptions {}
