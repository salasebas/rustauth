/// Account and OAuth account behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountOptions {
    pub update_account_on_sign_in: bool,
    pub encrypt_oauth_tokens: bool,
    pub store_account_cookie: bool,
    pub store_state_strategy: OAuthStateStoreStrategy,
    pub account_linking: AccountLinkingOptions,
}

impl Default for AccountOptions {
    fn default() -> Self {
        Self {
            update_account_on_sign_in: true,
            encrypt_oauth_tokens: false,
            store_account_cookie: false,
            store_state_strategy: OAuthStateStoreStrategy::Cookie,
            account_linking: AccountLinkingOptions::default(),
        }
    }
}

impl AccountOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLinkingOptions {
    pub enabled: bool,
    pub disable_implicit_linking: bool,
    pub trusted_providers: Vec<String>,
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

    pub fn builder() -> Self {
        Self::new()
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
