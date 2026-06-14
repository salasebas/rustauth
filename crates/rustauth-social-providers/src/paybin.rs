//! Paybin OpenID Connect social provider.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::runtime::ProviderIdentity;

pub const PAYBIN_ID: &str = "paybin";
pub const PAYBIN_NAME: &str = "Paybin";
pub const PAYBIN_AUTHORIZATION_ENDPOINT: &str = "https://idp.paybin.io/oauth2/authorize";
pub const PAYBIN_TOKEN_ENDPOINT: &str = "https://idp.paybin.io/oauth2/token";
pub const PAYBIN_DEFAULT_ISSUER: &str = "https://idp.paybin.io";
pub const PAYBIN_DEFAULT_SCOPES: &[&str] = &["openid", "email", "profile"];

/// Paybin ID token profile claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaybinProfile {
    pub sub: String,
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

impl PaybinProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.sub.clone(),
            name: Some(
                self.name
                    .clone()
                    .or_else(|| self.preferred_username.clone())
                    .unwrap_or_default(),
            ),
            email: Some(self.email.clone()),
            image: self.picture.clone(),
            email_verified: self.email_verified,
        }
    }
}

/// Paybin provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaybinOptions {
    pub oauth: ProviderOptions,
    pub issuer: Option<String>,
}

/// Input used to create a Paybin authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaybinAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
}

/// A normalized RustAuth user and the raw Paybin claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaybinUserInfo {
    pub user: OAuth2UserInfo,
    pub data: PaybinProfile,
}

/// Paybin OAuth/OIDC provider.
#[derive(Debug, Clone)]
pub struct PaybinProvider {
    client: OAuth2Client,
}

#[allow(deprecated)]
pub fn paybin(options: PaybinOptions) -> Result<PaybinProvider, OAuthError> {
    PaybinProvider::new(options)
}

impl PaybinProvider {
    #[deprecated(note = "use advanced::paybin::paybin() instead")]
    pub fn new(options: PaybinOptions) -> Result<Self, OAuthError> {
        let issuer = options
            .issuer
            .as_deref()
            .unwrap_or(PAYBIN_DEFAULT_ISSUER)
            .trim_end_matches('/');
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder(PAYBIN_ID, options.oauth)
            .authorization_endpoint(format!("{issuer}/oauth2/authorize"))?
            .token_endpoint(format!("{issuer}/oauth2/token"))?;
        if !disable_default_scope {
            builder = builder.default_scopes(PAYBIN_DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn authorization_endpoint(&self) -> &str {
        self.client.authorization_endpoint().as_str()
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn create_authorization_url(
        &self,
        request: PaybinAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        self.ensure_client_credentials()?;
        let code_verifier = request
            .code_verifier
            .ok_or(OAuthError::MissingOption("code_verifier"))?;
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?
            .code_verifier(code_verifier);
        if let Some(login_hint) = request.login_hint {
            url = url.login_hint(login_hint);
        }
        url.scopes(request.scopes).build()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let code_verifier = code_verifier
            .map(Into::into)
            .ok_or(OAuthError::MissingOption("code_verifier"))?;
        self.client
            .exchange_code(code, redirect_uri)?
            .code_verifier(code_verifier)
            .send()
            .await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.refresh_token(refresh_token_value)?.send().await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<PaybinUserInfo>, OAuthError> {
        let Some(id_token) = token.id_token.as_deref() else {
            return Ok(None);
        };
        let profile = decode_jwt_payload::<PaybinProfile>(id_token)?;
        Ok(Some(PaybinUserInfo {
            user: profile.to_user_info(),
            data: profile,
        }))
    }

    fn ensure_client_credentials(&self) -> Result<(), OAuthError> {
        if self.client.options().client_secret.is_none() {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }
}

impl ProviderIdentity for PaybinProvider {
    fn id(&self) -> &str {
        PAYBIN_ID
    }

    fn name(&self) -> &str {
        PAYBIN_NAME
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
