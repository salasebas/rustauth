//! Social catalog routes and generic-oauth plugin routes coexist like upstream Better Auth.

use std::sync::Arc;

use rustauth_core::api::{core_auth_async_endpoints, AuthRouter};
use rustauth_core::context::create_auth_context_with_adapter;
use rustauth_core::db::MemoryAdapter;
use rustauth_core::options::RustAuthOptions;
use rustauth_core::plugin::AuthPlugin;
use rustauth_oauth::oauth2::{
    ClientSecret, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
    SocialAuthorizationCodeRequest, SocialAuthorizationUrlRequest, SocialIdTokenRequest,
    SocialOAuthProvider, SocialProviderFuture,
};
use rustauth_plugins::generic_oauth::{generic_oauth, GenericOAuthConfig, GenericOAuthOptions};
use url::Url;

#[derive(Clone)]
struct FakeSocialProvider {
    id: String,
    options: ProviderOptions,
}

impl FakeSocialProvider {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            options: ProviderOptions {
                client_id: Some("client-id".into()),
                client_secret: ClientSecret::new("client-secret").ok(),
                ..ProviderOptions::default()
            },
        }
    }
}

impl SocialOAuthProvider for FakeSocialProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        "Fake Provider"
    }

    fn provider_options(&self) -> ProviderOptions {
        self.options.clone()
    }

    fn create_authorization_url(
        &self,
        input: SocialAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        Url::parse(&format!(
            "https://provider.example.com/oauth?state={}&redirect_uri={}",
            input.state, input.redirect_uri
        ))
        .map_err(OAuthError::InvalidUrl)
    }

    fn validate_authorization_code(
        &self,
        _input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async { Ok(OAuth2Tokens::default()) })
    }

    fn get_user_info(
        &self,
        _tokens: OAuth2Tokens,
        _provider_user: Option<serde_json::Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        Box::pin(async { Ok(None) })
    }

    fn verify_id_token(&self, _input: SocialIdTokenRequest) -> SocialProviderFuture<'_, bool> {
        Box::pin(async { Ok(false) })
    }
}

#[test]
fn social_and_generic_oauth_endpoints_register_without_conflict(
) -> Result<(), Box<dyn std::error::Error>> {
    let generic = generic_oauth(GenericOAuthOptions {
        config: vec![GenericOAuthConfig::new(
            "custom-idp",
            "client",
            Some("secret"),
            "https://idp.example.com/oauth/authorize",
            "https://idp.example.com/oauth/token",
        )],
    });

    let plugins: Vec<AuthPlugin> = vec![generic];
    let options = RustAuthOptions {
        base_url: Some("http://127.0.0.1:3000/api/auth".to_owned()),
        social_providers: vec![Arc::new(FakeSocialProvider::new("github"))],
        plugins,
        ..RustAuthOptions::default()
    };

    let context = create_auth_context_with_adapter(options, Arc::new(MemoryAdapter::new()))?;
    assert!(context.social_provider("github").is_some());
    assert!(context.social_provider("custom-idp").is_some());

    let router =
        AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints())?;
    let paths: Vec<String> = router
        .endpoint_registry()
        .iter()
        .map(|endpoint| format!("{} {}", endpoint.method, endpoint.path))
        .collect();

    assert!(paths
        .iter()
        .any(|line| line.contains("POST /sign-in/social")));
    assert!(paths
        .iter()
        .any(|line| line.contains("POST /sign-in/oauth2")));
    assert!(paths.iter().any(|line| line.contains("/callback/")));
    assert!(paths.iter().any(|line| line.contains("/oauth2/callback/")));
    assert!(paths.iter().any(|line| line.contains("POST /oauth2/link")));
    assert!(paths.iter().any(|line| line.contains("POST /link-social")));
    Ok(())
}
