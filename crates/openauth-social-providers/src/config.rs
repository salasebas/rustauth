//! Application-facing social provider configuration.

use openauth_oauth::oauth2::{ClientId, OAuthError, ProviderOptions};

/// Stable provider identifier used by OpenAuth social sign-in routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProviderId(&'static str);

impl ProviderId {
    pub const APPLE: Self = Self("apple");
    pub const ATLASSIAN: Self = Self("atlassian");
    pub const COGNITO: Self = Self("cognito");
    pub const DISCORD: Self = Self("discord");
    pub const DROPBOX: Self = Self("dropbox");
    pub const FACEBOOK: Self = Self("facebook");
    pub const FIGMA: Self = Self("figma");
    pub const GITHUB: Self = Self("github");
    pub const GITLAB: Self = Self("gitlab");
    pub const GOOGLE: Self = Self("google");
    pub const HUGGINGFACE: Self = Self("huggingface");
    pub const KAKAO: Self = Self("kakao");
    pub const KICK: Self = Self("kick");
    pub const LINE: Self = Self("line");
    pub const LINEAR: Self = Self("linear");
    pub const LINKEDIN: Self = Self("linkedin");
    pub const MICROSOFT: Self = Self("microsoft");
    pub const NAVER: Self = Self("naver");
    pub const NOTION: Self = Self("notion");
    pub const PAYBIN: Self = Self("paybin");
    pub const PAYPAL: Self = Self("paypal");
    pub const POLAR: Self = Self("polar");
    pub const RAILWAY: Self = Self("railway");
    pub const REDDIT: Self = Self("reddit");
    pub const ROBLOX: Self = Self("roblox");
    pub const SALESFORCE: Self = Self("salesforce");
    pub const SLACK: Self = Self("slack");
    pub const SPOTIFY: Self = Self("spotify");
    pub const TIKTOK: Self = Self("tiktok");
    pub const TWITCH: Self = Self("twitch");
    pub const TWITTER: Self = Self("twitter");
    pub const VERCEL: Self = Self("vercel");
    pub const VK: Self = Self("vk");
    pub const WECHAT: Self = Self("wechat");
    pub const ZOOM: Self = Self("zoom");

    /// Returns the stable string id registered with OpenAuth.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

/// Shared OAuth client credentials and common provider flags for app setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocialProviderConfig {
    client_id: String,
    client_secret: String,
    client_key: Option<String>,
    scope: Vec<String>,
    disable_default_scope: bool,
    redirect_uri: Option<String>,
    authorization_endpoint: Option<String>,
    disable_id_token_sign_in: bool,
    disable_implicit_sign_up: bool,
    disable_sign_up: bool,
    prompt: Option<String>,
    response_mode: Option<String>,
    override_user_info_on_sign_in: bool,
}

/// Builder for [`SocialProviderConfig`].
///
/// Use this when credentials or options are loaded from separate sources. For the
/// common case, [`SocialProviderConfig::new`] remains the shortest path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocialProviderConfigBuilder {
    client_id: Option<String>,
    client_secret: Option<String>,
    client_key: Option<String>,
    scope: Vec<String>,
    disable_default_scope: bool,
    redirect_uri: Option<String>,
    authorization_endpoint: Option<String>,
    disable_id_token_sign_in: bool,
    disable_implicit_sign_up: bool,
    disable_sign_up: bool,
    prompt: Option<String>,
    response_mode: Option<String>,
    override_user_info_on_sign_in: bool,
}

impl SocialProviderConfig {
    /// Creates configuration with the OAuth client id and secret from your provider console.
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            client_key: None,
            scope: Vec::new(),
            disable_default_scope: false,
            redirect_uri: None,
            authorization_endpoint: None,
            disable_id_token_sign_in: false,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            prompt: None,
            response_mode: None,
            override_user_info_on_sign_in: false,
        }
    }

    /// Returns a builder for staged configuration (for example loading credentials from env).
    pub fn builder() -> SocialProviderConfigBuilder {
        SocialProviderConfigBuilder::new()
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    pub fn client_key(&self) -> Option<&str> {
        self.client_key.as_deref()
    }

    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    pub fn disable_default_scope(&self) -> bool {
        self.disable_default_scope
    }

    pub fn redirect_uri(&self) -> Option<&str> {
        self.redirect_uri.as_deref()
    }

    pub fn authorization_endpoint(&self) -> Option<&str> {
        self.authorization_endpoint.as_deref()
    }

    pub fn disable_id_token_sign_in(&self) -> bool {
        self.disable_id_token_sign_in
    }

    pub fn disable_implicit_sign_up(&self) -> bool {
        self.disable_implicit_sign_up
    }

    pub fn disable_sign_up(&self) -> bool {
        self.disable_sign_up
    }

    pub fn prompt(&self) -> Option<&str> {
        self.prompt.as_deref()
    }

    pub fn response_mode(&self) -> Option<&str> {
        self.response_mode.as_deref()
    }

    pub fn override_user_info_on_sign_in(&self) -> bool {
        self.override_user_info_on_sign_in
    }

    /// Converts this config into the shared OAuth options struct used by provider runtimes.
    pub fn into_provider_options(self) -> ProviderOptions {
        ProviderOptions {
            client_id: Some(ClientId::Single(self.client_id)),
            client_secret: Some(self.client_secret),
            client_key: self.client_key,
            scope: self.scope,
            disable_default_scope: self.disable_default_scope,
            redirect_uri: self.redirect_uri,
            authorization_endpoint: self.authorization_endpoint,
            disable_id_token_sign_in: self.disable_id_token_sign_in,
            disable_implicit_sign_up: self.disable_implicit_sign_up,
            disable_sign_up: self.disable_sign_up,
            prompt: self.prompt,
            response_mode: self.response_mode,
            override_user_info_on_sign_in: self.override_user_info_on_sign_in,
        }
    }
}

impl SocialProviderConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    #[must_use]
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    #[must_use]
    pub fn client_key(mut self, client_key: impl Into<String>) -> Self {
        self.client_key = Some(client_key.into());
        self
    }

    #[must_use]
    pub fn scope<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scope = scopes.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn disable_default_scope(mut self, disable: bool) -> Self {
        self.disable_default_scope = disable;
        self
    }

    #[must_use]
    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }

    #[must_use]
    pub fn authorization_endpoint(mut self, authorization_endpoint: impl Into<String>) -> Self {
        self.authorization_endpoint = Some(authorization_endpoint.into());
        self
    }

    #[must_use]
    pub fn disable_id_token_sign_in(mut self, disable: bool) -> Self {
        self.disable_id_token_sign_in = disable;
        self
    }

    #[must_use]
    pub fn disable_implicit_sign_up(mut self, disable: bool) -> Self {
        self.disable_implicit_sign_up = disable;
        self
    }

    #[must_use]
    pub fn disable_sign_up(mut self, disable: bool) -> Self {
        self.disable_sign_up = disable;
        self
    }

    #[must_use]
    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    #[must_use]
    pub fn response_mode(mut self, response_mode: impl Into<String>) -> Self {
        self.response_mode = Some(response_mode.into());
        self
    }

    #[must_use]
    pub fn override_user_info_on_sign_in(mut self, override_user_info: bool) -> Self {
        self.override_user_info_on_sign_in = override_user_info;
        self
    }

    /// Validates required credentials and returns a [`SocialProviderConfig`].
    pub fn build(self) -> Result<SocialProviderConfig, OAuthError> {
        let client_id = require_non_empty(self.client_id, "client_id")?;
        let client_secret = require_non_empty(self.client_secret, "client_secret")?;

        Ok(SocialProviderConfig {
            client_id,
            client_secret,
            client_key: optional_non_empty(self.client_key),
            scope: self.scope,
            disable_default_scope: self.disable_default_scope,
            redirect_uri: optional_non_empty(self.redirect_uri),
            authorization_endpoint: optional_non_empty(self.authorization_endpoint),
            disable_id_token_sign_in: self.disable_id_token_sign_in,
            disable_implicit_sign_up: self.disable_implicit_sign_up,
            disable_sign_up: self.disable_sign_up,
            prompt: optional_non_empty(self.prompt),
            response_mode: optional_non_empty(self.response_mode),
            override_user_info_on_sign_in: self.override_user_info_on_sign_in,
        })
    }
}

fn require_non_empty(value: Option<String>, field: &'static str) -> Result<String, OAuthError> {
    match value {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_) => Err(OAuthError::InvalidConfiguration(format!(
            "{field} must not be empty"
        ))),
        None => Err(OAuthError::MissingOption(field)),
    }
}

fn optional_non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

/// Amazon Cognito user-pool metadata required in addition to OAuth client credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitoPoolConfig {
    pub domain: String,
    pub region: String,
    pub user_pool_id: String,
}

impl CognitoPoolConfig {
    pub fn new(
        domain: impl Into<String>,
        region: impl Into<String>,
        user_pool_id: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            region: region.into(),
            user_pool_id: user_pool_id.into(),
        }
    }

    pub(crate) fn into_cognito_options(
        self,
        config: SocialProviderConfig,
    ) -> crate::cognito::CognitoOptions {
        let oauth = config.into_provider_options();
        crate::cognito::CognitoOptions {
            client_id: oauth.client_id.unwrap_or(ClientId::Single(String::new())),
            client_secret: oauth.client_secret,
            client_key: oauth.client_key,
            domain: self.domain,
            region: self.region,
            user_pool_id: self.user_pool_id,
            require_client_secret: false,
            scope: oauth.scope,
            disable_default_scope: oauth.disable_default_scope,
            redirect_uri: oauth.redirect_uri,
            authorization_endpoint: oauth.authorization_endpoint,
            disable_id_token_sign_in: oauth.disable_id_token_sign_in,
            prompt: oauth.prompt,
            response_mode: oauth.response_mode,
            map_profile_to_user: None,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "builder validation tests assert specific failures"
)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_required_credentials() {
        let config = SocialProviderConfig::new("client-id", "client-secret");
        assert_eq!(config.client_id(), "client-id");
        assert_eq!(config.client_secret(), "client-secret");
    }

    #[test]
    fn builder_builds_full_config() -> Result<(), OAuthError> {
        let config = SocialProviderConfig::builder()
            .client_id("client-id")
            .client_secret("client-secret")
            .client_key("client-key")
            .scope(["repo", "workflow"])
            .disable_default_scope(true)
            .redirect_uri("https://app.example.com/callback")
            .authorization_endpoint("https://issuer.example.com/authorize")
            .disable_id_token_sign_in(true)
            .disable_implicit_sign_up(true)
            .disable_sign_up(true)
            .prompt("consent")
            .response_mode("query")
            .override_user_info_on_sign_in(true)
            .build()?;

        assert_eq!(config.client_id(), "client-id");
        assert_eq!(config.client_secret(), "client-secret");
        assert_eq!(config.client_key(), Some("client-key"));
        assert_eq!(config.scope(), &["repo", "workflow"]);
        assert!(config.disable_default_scope());
        assert_eq!(
            config.redirect_uri(),
            Some("https://app.example.com/callback")
        );
        assert_eq!(
            config.authorization_endpoint(),
            Some("https://issuer.example.com/authorize")
        );
        assert!(config.disable_id_token_sign_in());
        assert!(config.disable_implicit_sign_up());
        assert!(config.disable_sign_up());
        assert_eq!(config.prompt(), Some("consent"));
        assert_eq!(config.response_mode(), Some("query"));
        assert!(config.override_user_info_on_sign_in());

        let options = config.into_provider_options();
        assert_eq!(
            options.client_id,
            Some(ClientId::Single("client-id".to_owned()))
        );
        assert_eq!(options.client_secret, Some("client-secret".to_owned()));
        assert_eq!(options.client_key, Some("client-key".to_owned()));
        assert_eq!(
            options.scope,
            vec!["repo".to_owned(), "workflow".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn builder_requires_client_id() {
        let error = SocialProviderConfig::builder()
            .client_secret("client-secret")
            .build()
            .expect_err("missing client_id should fail");
        assert!(matches!(error, OAuthError::MissingOption("client_id")));
    }

    #[test]
    fn builder_requires_client_secret() {
        let error = SocialProviderConfig::builder()
            .client_id("client-id")
            .build()
            .expect_err("missing client_secret should fail");
        assert!(matches!(error, OAuthError::MissingOption("client_secret")));
    }

    #[test]
    fn builder_rejects_empty_client_id() {
        let error = SocialProviderConfig::builder()
            .client_id("")
            .client_secret("client-secret")
            .build()
            .expect_err("empty client_id should fail");
        assert!(matches!(error, OAuthError::InvalidConfiguration(_)));
        assert!(error.to_string().contains("client_id"));
    }

    #[test]
    fn builder_rejects_empty_client_secret() {
        let error = SocialProviderConfig::builder()
            .client_id("client-id")
            .client_secret("")
            .build()
            .expect_err("empty client_secret should fail");
        assert!(matches!(error, OAuthError::InvalidConfiguration(_)));
        assert!(error.to_string().contains("client_secret"));
    }

    #[test]
    fn builder_omits_empty_optional_strings() -> Result<(), OAuthError> {
        let config = SocialProviderConfig::builder()
            .client_id("client-id")
            .client_secret("client-secret")
            .client_key("")
            .redirect_uri("")
            .build()?;

        assert_eq!(config.client_key(), None);
        assert_eq!(config.redirect_uri(), None);
        Ok(())
    }
}
