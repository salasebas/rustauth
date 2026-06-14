//! PayPal social OAuth provider.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use josekit::jwk::JwkSet;
use rustauth_oauth::oauth2::{
    validate_token, verify_jws_with_jwks, ClientAuthentication, ClientId, OAuth2Client,
    OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions, TokenValidationOptions,
    ValidateTokenOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::runtime::ProviderIdentity;

pub const PAYPAL_ID: &str = "paypal";
pub const PAYPAL_NAME: &str = "PayPal";
pub const PAYPAL_SANDBOX_AUTHORIZATION_ENDPOINT: &str =
    "https://www.sandbox.paypal.com/signin/authorize";
pub const PAYPAL_LIVE_AUTHORIZATION_ENDPOINT: &str = "https://www.paypal.com/signin/authorize";
pub const PAYPAL_SANDBOX_TOKEN_ENDPOINT: &str = "https://api-m.sandbox.paypal.com/v1/oauth2/token";
pub const PAYPAL_LIVE_TOKEN_ENDPOINT: &str = "https://api-m.paypal.com/v1/oauth2/token";
pub const PAYPAL_SANDBOX_USER_INFO_ENDPOINT: &str =
    "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo";
pub const PAYPAL_LIVE_USER_INFO_ENDPOINT: &str =
    "https://api-m.paypal.com/v1/identity/oauth2/userinfo";
pub const PAYPAL_ISSUER: &str = "https://www.paypal.com";
pub const PAYPAL_SANDBOX_JWKS_ENDPOINT: &str = "https://api-m.sandbox.paypal.com/v1/oauth2/certs";
pub const PAYPAL_LIVE_JWKS_ENDPOINT: &str = "https://api-m.paypal.com/v1/oauth2/certs";

type UserMapper = Arc<dyn Fn(&PayPalProfile) -> OAuth2UserInfo + Send + Sync>;
type VerifyIdTokenFuture = Pin<Box<dyn Future<Output = Result<bool, OAuthError>> + Send>>;
pub type PayPalVerifyIdToken =
    Arc<dyn Fn(String, Option<String>) -> VerifyIdTokenFuture + Send + Sync>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PayPalEnvironment {
    #[default]
    Sandbox,
    Live,
}

#[derive(Clone, Default)]
pub struct PayPalOptions {
    pub oauth: ProviderOptions,
    pub environment: PayPalEnvironment,
    pub request_shipping_address: bool,
    pub jwks_endpoint: Option<String>,
    pub map_profile_to_user: Option<UserMapper>,
    pub verify_id_token: Option<PayPalVerifyIdToken>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PayPalAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayPalAddress {
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayPalProfile {
    pub user_id: String,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
    pub middle_name: Option<String>,
    pub picture: Option<String>,
    pub email: String,
    pub email_verified: bool,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub phone_number: Option<String>,
    pub address: Option<PayPalAddress>,
    pub verified_account: Option<bool>,
    pub account_type: Option<String>,
    pub age_range: Option<String>,
    pub payer_id: Option<String>,
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

impl PayPalProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.user_id.clone(),
            name: Some(self.name.clone()),
            email: Some(self.email.clone()),
            image: self.picture.clone(),
            email_verified: self.email_verified,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayPalUserInfo {
    pub user: OAuth2UserInfo,
    pub data: PayPalProfile,
}

#[derive(Clone)]
pub struct PayPalProvider {
    client: OAuth2Client,
    environment: PayPalEnvironment,
    jwks_endpoint: Option<String>,
    map_profile_to_user: Option<UserMapper>,
    verify_id_token: Option<PayPalVerifyIdToken>,
    user_info_endpoint: &'static str,
    http_client: reqwest::Client,
}

#[allow(deprecated)]
pub fn paypal(options: PayPalOptions) -> Result<PayPalProvider, OAuthError> {
    PayPalProvider::new(options)
}

impl PayPalProvider {
    #[deprecated(note = "use advanced::paypal::paypal() instead")]
    pub fn new(options: PayPalOptions) -> Result<Self, OAuthError> {
        let (authorization_endpoint, token_endpoint, user_info_endpoint) = match options.environment
        {
            PayPalEnvironment::Sandbox => (
                PAYPAL_SANDBOX_AUTHORIZATION_ENDPOINT,
                PAYPAL_SANDBOX_TOKEN_ENDPOINT,
                PAYPAL_SANDBOX_USER_INFO_ENDPOINT,
            ),
            PayPalEnvironment::Live => (
                PAYPAL_LIVE_AUTHORIZATION_ENDPOINT,
                PAYPAL_LIVE_TOKEN_ENDPOINT,
                PAYPAL_LIVE_USER_INFO_ENDPOINT,
            ),
        };

        let PayPalOptions {
            oauth,
            environment,
            jwks_endpoint,
            map_profile_to_user,
            verify_id_token,
            ..
        } = options;

        Ok(Self {
            client: OAuth2Client::builder(PAYPAL_ID, oauth)
                .authorization_endpoint(authorization_endpoint)?
                .token_endpoint(token_endpoint)?
                .authentication(ClientAuthentication::Basic)
                .build()?,
            environment,
            jwks_endpoint,
            map_profile_to_user,
            verify_id_token,
            user_info_endpoint,
            http_client: crate::http::shared_client(),
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

    pub fn user_info_endpoint(&self) -> &str {
        self.user_info_endpoint
    }

    pub fn create_authorization_url(
        &self,
        request: PayPalAuthorizationUrlRequest,
    ) -> Result<url::Url, OAuthError> {
        self.ensure_client_credentials()?;
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?;
        if let Some(code_verifier) = request.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        if let Some(prompt) = self.client.options().prompt.clone() {
            url = url.prompt(prompt);
        }
        url.build()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client
            .exchange_code(code, redirect_uri)?
            .header("Accept-Language", "en_US")
            .send()
            .await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client
            .refresh_token(refresh_token_value)?
            .header("Accept-Language", "en_US")
            .send()
            .await
    }

    pub async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<bool, OAuthError> {
        if self.client.options().disable_id_token_sign_in {
            return Ok(false);
        }

        if let Some(verify_id_token) = &self.verify_id_token {
            return verify_id_token(token.to_owned(), nonce.map(str::to_owned)).await;
        }

        let audiences = self.client_id_audiences();
        if audiences.is_empty() {
            return Ok(false);
        }

        let payload = match validate_token(
            token,
            self.jwks_endpoint(),
            ValidateTokenOptions::new(self.id_token_validation_options(audiences)),
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
        if self.client.options().disable_id_token_sign_in {
            return Ok(false);
        }

        let audiences = self.client_id_audiences();
        if audiences.is_empty() {
            return Ok(false);
        }

        let result = match verify_jws_with_jwks(
            token,
            jwk_set,
            &self.id_token_validation_options(audiences),
        ) {
            Ok(result) => result,
            Err(_) => return Ok(false),
        };

        self.valid_verified_id_token_payload(result.payload, nonce)
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<PayPalUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let response = match self
            .http_client
            .get(self.user_info_url())
            .bearer_auth(access_token)
            .header("accept", "application/json")
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };

        if !response.status().is_success() {
            return Ok(None);
        }

        let profile = match response.json::<PayPalProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(self.map_profile(profile)))
    }

    pub fn map_profile(&self, profile: PayPalProfile) -> PayPalUserInfo {
        let user = self
            .map_profile_to_user
            .as_ref()
            .map(|mapper| mapper(&profile))
            .unwrap_or_else(|| profile.to_user_info());

        PayPalUserInfo {
            user,
            data: profile,
        }
    }

    fn ensure_client_credentials(&self) -> Result<(), OAuthError> {
        if self.client.options().client_secret.is_none() {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }

    fn user_info_url(&self) -> String {
        format!("{}?schema=paypalv1.1", self.user_info_endpoint)
    }

    fn jwks_endpoint(&self) -> &str {
        self.jwks_endpoint
            .as_deref()
            .unwrap_or(match self.environment {
                PayPalEnvironment::Sandbox => PAYPAL_SANDBOX_JWKS_ENDPOINT,
                PayPalEnvironment::Live => PAYPAL_LIVE_JWKS_ENDPOINT,
            })
    }

    fn id_token_validation_options(&self, audience: Vec<String>) -> TokenValidationOptions {
        TokenValidationOptions {
            audience,
            issuer: vec![PAYPAL_ISSUER.to_owned()],
            ..TokenValidationOptions::default().require_standard_claims()
        }
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

    fn client_id_audiences(&self) -> Vec<String> {
        match &self.client.options().client_id {
            Some(ClientId::Single(value)) if !value.is_empty() => vec![value.clone()],
            Some(ClientId::Multiple(values)) => values
                .iter()
                .filter(|value| !value.is_empty())
                .cloned()
                .collect(),
            _ => Vec::new(),
        }
    }
}

impl ProviderIdentity for PayPalProvider {
    fn id(&self) -> &str {
        PAYPAL_ID
    }

    fn name(&self) -> &str {
        PAYPAL_NAME
    }
}
