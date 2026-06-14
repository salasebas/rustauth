//! Twitch OpenID Connect social provider.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwk::JwkSet;
use rustauth_oauth::oauth2::{
    validate_token, verify_jws_with_jwks, OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError,
    OAuthFormRequest, ProviderOptions, TokenValidationOptions, ValidateTokenOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::runtime::ProviderIdentity;

const AUTHORIZATION_ENDPOINT: &str = "https://id.twitch.tv/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://id.twitch.tv/oauth2/token";
const JWKS_ENDPOINT: &str = "https://id.twitch.tv/oauth2/keys";
const ISSUER: &str = "https://id.twitch.tv/oauth2";
const DEFAULT_SCOPES: &[&str] = &["user:read:email", "openid"];
const DEFAULT_CLAIMS: &[&str] = &["email", "email_verified", "preferred_username", "picture"];

pub const TWITCH_ID: &str = "twitch";
pub const TWITCH_NAME: &str = "Twitch";
pub const TWITCH_AUTHORIZATION_ENDPOINT: &str = AUTHORIZATION_ENDPOINT;
pub const TWITCH_TOKEN_ENDPOINT: &str = TOKEN_ENDPOINT;
pub const TWITCH_JWKS_ENDPOINT: &str = JWKS_ENDPOINT;
pub const TWITCH_ISSUER: &str = ISSUER;
pub const TWITCH_DEFAULT_SCOPES: &[&str] = DEFAULT_SCOPES;
pub const TWITCH_DEFAULT_CLAIMS: &[&str] = DEFAULT_CLAIMS;

/// Twitch provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwitchOptions {
    pub oauth: ProviderOptions,
    pub claims: Vec<String>,
    pub jwks_endpoint: Option<String>,
}

/// Input used to create a Twitch authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwitchAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// Twitch ID token profile claims.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TwitchProfile {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub preferred_username: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub picture: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl TwitchProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.sub.clone(),
            name: Some(self.preferred_username.clone()),
            email: Some(self.email.clone()),
            image: Some(self.picture.clone()),
            email_verified: self.email_verified,
        }
    }
}

/// A normalized RustAuth user and the raw Twitch claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwitchUserInfo {
    pub user: OAuth2UserInfo,
    pub data: TwitchProfile,
}

/// Twitch OAuth/OIDC provider.
#[derive(Debug, Clone)]
pub struct TwitchProvider {
    client: OAuth2Client,
    options: TwitchOptions,
}

#[allow(deprecated)]
pub fn twitch(options: TwitchOptions) -> Result<TwitchProvider, OAuthError> {
    TwitchProvider::new(options)
}

impl TwitchProvider {
    #[deprecated(note = "use advanced::twitch::twitch() instead")]
    pub fn new(options: TwitchOptions) -> Result<Self, OAuthError> {
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder("twitch", options.oauth.clone())
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?;
        if !disable_default_scope {
            builder = builder.default_scopes(DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
            options,
        })
    }

    pub fn options(&self) -> &TwitchOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn create_authorization_url(
        &self,
        request: TwitchAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?
            .scopes(request.scopes);
        for claim in self.claims() {
            url = url.claim(claim);
        }
        url.build()
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .exchange_code(code, redirect_uri)?
            .into_form_request()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.exchange_code(code, redirect_uri)?.send().await
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .refresh_token(refresh_token)?
            .into_form_request()
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.refresh_token(refresh_token)?.send().await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<TwitchUserInfo>, OAuthError> {
        let Some(id_token) = token.id_token.as_deref() else {
            return Ok(None);
        };
        let profile = decode_jwt_payload::<TwitchProfile>(id_token)?;
        Ok(Some(TwitchUserInfo {
            user: profile.to_user_info(),
            data: profile,
        }))
    }

    pub async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<bool, OAuthError> {
        if self.options.oauth.disable_id_token_sign_in {
            return Ok(false);
        }
        let audiences = self.client_id_audiences();
        if audiences.is_empty() {
            return Ok(false);
        }
        let jwks_endpoint = self
            .options
            .jwks_endpoint
            .as_deref()
            .unwrap_or(JWKS_ENDPOINT);
        let payload = match validate_token(
            token,
            jwks_endpoint,
            ValidateTokenOptions::new(TokenValidationOptions {
                audience: audiences,
                issuer: vec![ISSUER.to_owned()],
                ..TokenValidationOptions::default().require_standard_claims()
            }),
        )
        .await
        {
            Ok(result) => result.payload,
            Err(_) => return Ok(false),
        };
        self.valid_verified_id_token_payload(payload, nonce)
    }

    pub fn verify_id_token_with_jwk_set(
        &self,
        token: &str,
        nonce: Option<&str>,
        jwk_set: &JwkSet,
    ) -> Result<bool, OAuthError> {
        if self.options.oauth.disable_id_token_sign_in {
            return Ok(false);
        }
        let audiences = self.client_id_audiences();
        if audiences.is_empty() {
            return Ok(false);
        }
        let result = match verify_jws_with_jwks(
            token,
            jwk_set,
            &TokenValidationOptions {
                audience: audiences,
                issuer: vec![ISSUER.to_owned()],
                ..TokenValidationOptions::default().require_standard_claims()
            },
        ) {
            Ok(result) => result,
            Err(_) => return Ok(false),
        };
        self.valid_verified_id_token_payload(result.payload, nonce)
    }

    fn valid_verified_id_token_payload(
        &self,
        payload: Value,
        nonce: Option<&str>,
    ) -> Result<bool, OAuthError> {
        if payload
            .get("sub")
            .and_then(Value::as_str)
            .map_or(true, str::is_empty)
        {
            return Ok(false);
        }
        if let Some(expected_nonce) = nonce {
            let actual_nonce = payload.get("nonce").and_then(Value::as_str);
            if actual_nonce != Some(expected_nonce) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn id(&self) -> &str {
        TWITCH_ID
    }

    pub fn name(&self) -> &str {
        TWITCH_NAME
    }

    fn claims(&self) -> Vec<String> {
        if self.options.claims.is_empty() {
            DEFAULT_CLAIMS
                .iter()
                .map(|claim| (*claim).to_owned())
                .collect()
        } else {
            self.options.claims.clone()
        }
    }

    fn client_id_audiences(&self) -> Vec<String> {
        match &self.client.options().client_id {
            Some(rustauth_oauth::oauth2::ClientId::Single(value)) if !value.is_empty() => {
                vec![value.clone()]
            }
            Some(rustauth_oauth::oauth2::ClientId::Multiple(values)) => values
                .iter()
                .filter(|value| !value.is_empty())
                .cloned()
                .collect(),
            _ => Vec::new(),
        }
    }
}

impl ProviderIdentity for TwitchProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}

fn decode_jwt_payload<T>(token: &str) -> Result<T, OAuthError>
where
    T: for<'de> Deserialize<'de>,
{
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| OAuthError::TokenVerification("missing jwt payload".to_owned()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| OAuthError::TokenVerification(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| OAuthError::InvalidResponse(error.to_string()))
}
