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
