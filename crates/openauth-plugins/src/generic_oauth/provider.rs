use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, refresh_access_token,
    refresh_access_token_request, validate_authorization_code, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError,
    OAuthFormRequest, ProviderOptions, RefreshAccessTokenRequest, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};
use url::Url;

use super::config::{GenericOAuthConfig, GenericOAuthTokenRequest};
use super::discovery::DiscoveryCache;
use super::user_info;

/// Social provider implementation used by the generic OAuth plugin.
///
/// `SocialOAuthProvider::create_authorization_url` is synchronous, so providers that only
/// define `discovery_url` cannot resolve their authorization endpoint through this trait method.
/// Use the plugin routes (`/sign-in/oauth2`, `/oauth2/callback/:providerId`, `/oauth2/link`) as
/// the canonical flow for discovery-only generic providers.
#[derive(Debug, Clone)]
pub struct GenericOAuthProvider {
    config: GenericOAuthConfig,
    discovery_cache: Option<DiscoveryCache>,
}

impl GenericOAuthProvider {
    pub fn new(config: GenericOAuthConfig) -> Self {
        Self {
            config,
            discovery_cache: None,
        }
    }

    pub(crate) fn with_discovery_cache(
        config: GenericOAuthConfig,
        discovery_cache: DiscoveryCache,
    ) -> Self {
        Self {
            config,
            discovery_cache: Some(discovery_cache),
        }
    }

    pub fn config(&self) -> &GenericOAuthConfig {
        &self.config
    }

    pub fn authorization_code_request(
        &self,
        input: SocialAuthorizationCodeRequest,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(self.authorization_code_input(input)?)
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        refresh_access_token_request(RefreshAccessTokenRequest {
            refresh_token: refresh_token.into(),
            options: self.config.provider_options(),
            authentication: self.config.authentication,
            extra_params: self.config.token_url_params.clone(),
            ..RefreshAccessTokenRequest::default()
        })
    }

    fn authorization_code_input(
        &self,
        input: SocialAuthorizationCodeRequest,
    ) -> Result<AuthorizationCodeRequest, OAuthError> {
        Ok(AuthorizationCodeRequest {
            code: input.code,
            redirect_uri: input.redirect_uri,
            options: self.config.provider_options(),
            code_verifier: self.config.pkce.then_some(input.code_verifier).flatten(),
            device_id: input.device_id,
            authentication: self.config.authentication,
            headers: super::discovery::headers(&self.config.authorization_headers),
            additional_params: self.config.token_url_params.clone(),
            ..AuthorizationCodeRequest::default()
        })
    }

    async fn token_endpoint(&self) -> Result<String, OAuthError> {
        if let Some(token_url) = &self.config.token_url {
            return Ok(token_url.clone());
        }
        let Some(discovery_cache) = &self.discovery_cache else {
            return Err(OAuthError::InvalidResponse(
                "Invalid OAuth configuration. Token URL not found.".to_owned(),
            ));
        };
        let discovery = discovery_cache
            .fetch(&self.config)
            .await
            .map_err(|error| OAuthError::InvalidResponse(error.to_string()))?
            .ok_or_else(|| {
                OAuthError::InvalidResponse(
                    "Invalid OAuth configuration. Token URL not found.".to_owned(),
                )
            })?;
        discovery.token_endpoint.ok_or_else(|| {
            OAuthError::InvalidResponse(
                "Invalid OAuth configuration. Token URL not found.".to_owned(),
            )
        })
    }
}

impl SocialOAuthProvider for GenericOAuthProvider {
    fn id(&self) -> &str {
        &self.config.provider_id
    }

    fn name(&self) -> &str {
        &self.config.provider_id
    }

    fn provider_options(&self) -> ProviderOptions {
        self.config.provider_options()
    }

    fn create_authorization_url(
        &self,
        input: SocialAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let Some(authorization_endpoint) = self.config.authorization_url.clone() else {
            return Err(OAuthError::InvalidResponse(
                "Invalid OAuth configuration".to_owned(),
            ));
        };
        create_authorization_url(AuthorizationUrlRequest {
            id: self.config.provider_id.clone(),
            options: self.config.provider_options(),
            authorization_endpoint,
            redirect_uri: input.redirect_uri,
            state: input.state,
            code_verifier: self.config.pkce.then_some(input.code_verifier).flatten(),
            scopes: self.config.scopes(input.scopes),
            prompt: self.config.prompt.clone(),
            access_type: self.config.access_type.clone(),
            response_type: self.config.response_type.clone(),
            response_mode: self.config.response_mode.clone(),
            login_hint: input.login_hint,
            additional_params: self.config.authorization_url_params.clone(),
            ..AuthorizationUrlRequest::default()
        })
    }

    fn validate_authorization_code(
        &self,
        input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async move {
            if let Some(get_token) = &self.config.get_token {
                return get_token(GenericOAuthTokenRequest {
                    code: input.code,
                    redirect_uri: self
                        .config
                        .redirect_uri
                        .clone()
                        .unwrap_or(input.redirect_uri),
                    code_verifier: self.config.pkce.then_some(input.code_verifier).flatten(),
                    device_id: input.device_id,
                })
                .await;
            }
            let token_endpoint = self.token_endpoint().await?;
            validate_authorization_code(ClientTokenRequest {
                token_endpoint,
                request: self.authorization_code_input(input)?,
            })
            .await
        })
    }

    fn get_user_info(
        &self,
        tokens: OAuth2Tokens,
        _provider_user: Option<serde_json::Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
        Box::pin(async move {
            let user = if let Some(get_user_info) = &self.config.get_user_info {
                get_user_info(tokens).await?
            } else {
                user_info::get_user_info(&tokens, self.config.user_info_url.as_deref()).await?
            };
            if let Some(map_profile) = &self.config.map_profile_to_user {
                if let Some(user) = user {
                    return map_profile(user).await.map(Some);
                }
                return Ok(None);
            }
            Ok(user)
        })
    }

    fn verify_id_token(&self, input: SocialIdTokenRequest) -> SocialProviderFuture<'_, bool> {
        Box::pin(async move {
            if let Some(verify_id_token) = &self.config.verify_id_token {
                return verify_id_token(input).await;
            }
            Ok(false)
        })
    }

    fn refresh_access_token(
        &self,
        refresh_token_value: String,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async move {
            if let Some(refresh_access_token) = &self.config.refresh_access_token {
                return refresh_access_token(refresh_token_value).await;
            }
            let token_endpoint = self.token_endpoint().await?;
            refresh_access_token(ClientTokenRequest {
                token_endpoint,
                request: RefreshAccessTokenRequest {
                    refresh_token: refresh_token_value,
                    options: self.config.provider_options(),
                    authentication: self.config.authentication,
                    extra_params: self.config.token_url_params.clone(),
                    ..RefreshAccessTokenRequest::default()
                },
            })
            .await
        })
    }

    fn revoke_token(&self, token: String) -> SocialProviderFuture<'_, ()> {
        Box::pin(async move {
            if let Some(revoke_token) = &self.config.revoke_token {
                return revoke_token(token).await;
            }
            Err(OAuthError::InvalidResponse(format!(
                "provider does not support token revocation for token `{token}`"
            )))
        })
    }
}
