//! PayPal social OAuth provider.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, get_oauth2_tokens,
    refresh_access_token_request, validate_authorization_code, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest, OAuth2Tokens,
    OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract, ProviderOptions,
    RefreshAccessTokenRequest,
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
            http_client: reqwest::Client::new(),
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

        Ok(false)
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<PayPalUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let profile = self
            .http_client
            .get(self.user_info_url())
            .bearer_auth(access_token)
            .header("accept", "application/json")
            .send()
            .await?;

        if !profile.status().is_success() {
            return Ok(None);
        }

        let profile = profile.json::<PayPalProfile>().await?;
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
    let client = reqwest::Client::new();
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
