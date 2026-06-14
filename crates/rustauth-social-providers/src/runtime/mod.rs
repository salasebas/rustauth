use rustauth_oauth::oauth2::{
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, SocialAuthorizationCodeRequest,
    SocialAuthorizationUrlRequest, SocialIdTokenRequest, SocialOAuthProvider, SocialProviderFuture,
};

/// Provider identity used by the social runtime macro (distinct from [`SocialOAuthProvider`]).
pub trait ProviderIdentity {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
}
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::Url;

macro_rules! impl_social_oauth_provider {
    (
        $provider:ty,
        options |$options_self:ident| $options:block,
        authorization |$auth_self:ident, $auth_input:ident| $authorization:block,
        code |$code_self:ident, $code_input:ident| $code:block,
        user |$user_self:ident, $tokens:ident, $provider_user:ident| $user:block,
        verify |$verify_self:ident, $verify_input:ident| $verify:block,
        refresh |$refresh_self:ident, $refresh_token:ident| $refresh:block
    ) => {
        impl SocialOAuthProvider for $provider {
            fn id(&self) -> &str {
                <Self as crate::runtime::ProviderIdentity>::id(self)
            }

            fn name(&self) -> &str {
                <Self as crate::runtime::ProviderIdentity>::name(self)
            }

            fn provider_options(&self) -> ProviderOptions {
                let $options_self = self;
                $options
            }

            fn create_authorization_url(
                &self,
                input: SocialAuthorizationUrlRequest,
            ) -> Result<Url, OAuthError> {
                let $auth_self = self;
                let $auth_input = input;
                $authorization
            }

            fn validate_authorization_code(
                &self,
                input: SocialAuthorizationCodeRequest,
            ) -> SocialProviderFuture<'_, OAuth2Tokens> {
                let $code_self = self;
                let $code_input = input;
                Box::pin(async move { $code })
            }

            fn get_user_info(
                &self,
                tokens: OAuth2Tokens,
                provider_user: Option<Value>,
            ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>> {
                let $user_self = self;
                let $tokens = tokens;
                let $provider_user = provider_user;
                Box::pin(async move { $user })
            }

            fn verify_id_token(
                &self,
                input: SocialIdTokenRequest,
            ) -> SocialProviderFuture<'_, bool> {
                let $verify_self = self;
                let $verify_input = input;
                Box::pin(async move { $verify })
            }

            fn refresh_access_token(
                &self,
                refresh_token: String,
            ) -> SocialProviderFuture<'_, OAuth2Tokens> {
                let $refresh_self = self;
                let $refresh_token = refresh_token;
                Box::pin(async move { $refresh })
            }
        }
    };
}

fn unsupported_id_token(_input: SocialIdTokenRequest) -> Result<bool, OAuthError> {
    Ok(false)
}

fn parse_provider_user<T: DeserializeOwned>(value: Option<Value>) -> Result<Option<T>, OAuthError> {
    value
        .map(serde_json::from_value)
        .transpose()
        .map_err(|err| OAuthError::InvalidResponse(err.to_string()))
}

fn parse_url(value: String) -> Result<Url, OAuthError> {
    Url::parse(&value).map_err(OAuthError::InvalidUrl)
}

mod apple;
mod atlassian;
mod cognito;
mod discord;
mod dropbox;
mod facebook;
mod figma;
mod github;
mod gitlab;
mod google;
mod huggingface;
mod kakao;
mod kick;
mod line;
mod linear;
mod linkedin;
mod microsoft_entra_id;
mod naver;
mod notion;
mod paybin;
mod paypal;
mod polar;
mod railway;
mod reddit;
mod roblox;
mod salesforce;
mod slack;
mod spotify;
mod tiktok;
mod twitch;
mod twitter;
mod vercel;
mod vk;
mod wechat;
mod zoom;
