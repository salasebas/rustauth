//! PayPal social OAuth provider.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use josekit::jwk::JwkSet;
use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, get_oauth2_tokens,
    refresh_access_token_request, validate_authorization_code, validate_token,
    verify_jws_with_jwks, AuthorizationCodeRequest, AuthorizationUrlRequest, ClientAuthentication,
    ClientId, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest,
    OAuthProviderContract, ProviderOptions, RefreshAccessTokenRequest, TokenValidationOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

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
    pub extra: BTreeMap<String, Value>,
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
    options: PayPalOptions,
    authorization_endpoint: &'static str,
    token_endpoint: &'static str,
    user_info_endpoint: &'static str,
    http_client: reqwest::Client,
}

pub fn paypal(options: PayPalOptions) -> PayPalProvider {
    PayPalProvider::new(options)
}

impl PayPalProvider {
    pub fn new(options: PayPalOptions) -> Self {
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

        Self {
            options,
            authorization_endpoint,
            token_endpoint,
            user_info_endpoint,
            http_client: crate::http::shared_client(),
        }
    }

    pub fn options(&self) -> &PayPalOptions {
        &self.options
    }

    pub fn authorization_endpoint(&self) -> &str {
        self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &str {
        self.token_endpoint
    }

    pub fn user_info_endpoint(&self) -> &str {
        self.user_info_endpoint
    }

    pub fn create_authorization_url(
        &self,
        request: PayPalAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        self.ensure_client_credentials()?;

        create_authorization_url(AuthorizationUrlRequest {
            id: PAYPAL_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: self.authorization_endpoint.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_verifier: request.code_verifier,
            scopes: Vec::new(),
            prompt: self.options.oauth.prompt.clone(),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            options: self.options.oauth.clone(),
            authentication: ClientAuthentication::Basic,
            headers: paypal_token_headers(),
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: self.token_endpoint.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Basic,
                headers: paypal_token_headers(),
                ..AuthorizationCodeRequest::default()
            },
        })
        .await
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        refresh_access_token_request(RefreshAccessTokenRequest {
            refresh_token: refresh_token_value.into(),
            options: self.options.oauth.clone(),
            authentication: ClientAuthentication::Basic,
            ..RefreshAccessTokenRequest::default()
        })
        .map(with_paypal_token_headers)
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let request = self.refresh_access_token_request(refresh_token_value)?;
        let data = post_form(self.token_endpoint, request).await?;
        get_oauth2_tokens(data)
    }

    pub async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<bool, OAuthError> {
        if self.options.oauth.disable_id_token_sign_in {
            return Ok(false);
        }

        if let Some(verify_id_token) = &self.options.verify_id_token {
            return verify_id_token(token.to_owned(), nonce.map(str::to_owned)).await;
        }

        let audiences = self.client_id_audiences();
        if audiences.is_empty() {
            return Ok(false);
        }

        let payload = match validate_token(
            token,
            self.jwks_endpoint(),
            self.id_token_validation_options(audiences),
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
            .options
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
        if openauth_oauth::oauth2::get_primary_client_id(&self.options.oauth.client_id).is_none() {
            return Err(OAuthError::MissingOption("client_id"));
        }
        if self
            .options
            .oauth
            .client_secret
            .as_deref()
            .unwrap_or("")
            .is_empty()
        {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }

    fn user_info_url(&self) -> String {
        format!("{}?schema=paypalv1.1", self.user_info_endpoint)
    }

    fn jwks_endpoint(&self) -> &str {
        self.options
            .jwks_endpoint
            .as_deref()
            .unwrap_or(match self.options.environment {
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
        match &self.options.oauth.client_id {
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

impl OAuthProviderContract for PayPalProvider {
    fn id(&self) -> &str {
        PAYPAL_ID
    }

    fn name(&self) -> &str {
        PAYPAL_NAME
    }
}

fn paypal_token_headers() -> BTreeMap<String, String> {
    BTreeMap::from([("Accept-Language".to_owned(), "en_US".to_owned())])
}

fn with_paypal_token_headers(mut request: OAuthFormRequest) -> OAuthFormRequest {
    request.set_header("Accept-Language", "en_US");
    request
}

async fn post_form(
    token_endpoint: &str,
    request: OAuthFormRequest,
) -> Result<serde_json::Value, OAuthError> {
    let client = crate::http::shared_client();
    let mut builder = client.post(token_endpoint);
    for (key, value) in &request.headers {
        builder = builder.header(key, value);
    }
    let response = builder
        .body(request.to_form_urlencoded())
        .send()
        .await?
        .error_for_status()?;
    response
        .json::<serde_json::Value>()
        .await
        .map_err(Into::into)
}
