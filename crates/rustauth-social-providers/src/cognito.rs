//! Amazon Cognito social OAuth provider.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwk::JwkSet;
use rustauth_oauth::oauth2::{
    get_primary_client_id, validate_token, verify_jws_with_jwks, ClientId, ClientSecret,
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
    TokenValidationOptions, ValidateTokenOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use url::Url;

use crate::http::ProviderHttpClient;
use crate::runtime::ProviderIdentity;

const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];
const ID_TOKEN_MAX_AGE_SECONDS: i64 = 60 * 60;

type UserMapper = Arc<dyn Fn(&CognitoProfile) -> OAuth2UserInfo + Send + Sync>;

/// Amazon Cognito ID token and userinfo profile fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CognitoProfile {
    pub sub: String,
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub username: Option<String>,
    pub locale: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub aud: Option<Value>,
    pub iss: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl CognitoProfile {
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .or_else(|| self.given_name.clone())
            .or_else(|| self.username.clone())
            .unwrap_or_default()
    }
}

/// Configuration for Amazon Cognito as a Better Auth-compatible social provider.
#[derive(Clone)]
pub struct CognitoOptions {
    pub client_id: ClientId,
    pub client_secret: Option<String>,
    pub client_key: Option<String>,
    /// Cognito domain, with or without an `https://` prefix.
    pub domain: String,
    /// AWS region where the user pool is hosted, for example `us-east-1`.
    pub region: String,
    pub user_pool_id: String,
    pub require_client_secret: bool,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub redirect_uri: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub disable_id_token_sign_in: bool,
    pub prompt: Option<String>,
    pub response_mode: Option<String>,
    pub map_profile_to_user: Option<UserMapper>,
}

impl CognitoOptions {
    pub fn new(
        client_id: impl Into<ClientId>,
        domain: impl Into<String>,
        region: impl Into<String>,
        user_pool_id: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: None,
            client_key: None,
            domain: domain.into(),
            region: region.into(),
            user_pool_id: user_pool_id.into(),
            require_client_secret: false,
            scope: Vec::new(),
            disable_default_scope: false,
            redirect_uri: None,
            authorization_endpoint: None,
            disable_id_token_sign_in: false,
            prompt: None,
            response_mode: None,
            map_profile_to_user: None,
        }
    }

    fn provider_options(&self) -> Result<ProviderOptions, OAuthError> {
        let mut options = ProviderOptions {
            client_id: Some(self.client_id.clone()),
            client_key: self.client_key.clone(),
            scope: self.scope.clone(),
            disable_default_scope: self.disable_default_scope,
            redirect_uri: self.redirect_uri.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            disable_id_token_sign_in: self.disable_id_token_sign_in,
            prompt: self.prompt.clone(),
            response_mode: self.response_mode.clone(),
            ..ProviderOptions::default()
        };
        if let Some(secret) = &self.client_secret {
            options.client_secret = Some(ClientSecret::new(secret.clone())?);
        }
        Ok(options)
    }
}

/// Inputs required to build the Cognito authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CognitoAuthorizationUrlInput {
    pub state: String,
    pub scopes: Vec<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: String,
}

/// A Cognito user plus the original provider profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CognitoUserInfo {
    pub user: OAuth2UserInfo,
    pub data: CognitoProfile,
}

/// Amazon Cognito OAuth provider.
#[derive(Clone)]
pub struct CognitoProvider {
    client: OAuth2Client,
    options: CognitoOptions,
    user_info_endpoint: String,
    http_client: ProviderHttpClient,
}

impl CognitoProvider {
    #[deprecated(note = "use advanced::cognito::cognito() instead")]
    pub fn new(options: CognitoOptions) -> Result<Self, OAuthError> {
        if options.domain.is_empty() || options.region.is_empty() || options.user_pool_id.is_empty()
        {
            return Err(OAuthError::MissingOption("domain, region and user_pool_id"));
        }

        let clean_domain = clean_cognito_domain(&options.domain).to_owned();
        let authorization_endpoint = format!("https://{clean_domain}/oauth2/authorize");
        let token_endpoint = format!("https://{clean_domain}/oauth2/token");
        let user_info_endpoint = format!("https://{clean_domain}/oauth2/userinfo");
        let disable_default_scope = options.disable_default_scope;
        let provider_options = options.provider_options()?;
        let mut builder = OAuth2Client::builder("cognito", provider_options)
            .authorization_endpoint(authorization_endpoint)?
            .token_endpoint(token_endpoint)?;
        if !disable_default_scope {
            builder = builder.default_scopes(DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
            options,
            user_info_endpoint,
            http_client: ProviderHttpClient::shared(),
        })
    }

    pub fn provider_options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    /// Overrides the HTTP client used for userinfo requests. Use
    /// [`ProviderHttpClient::permissive`] in tests to reach local fixtures.
    pub fn with_http_client(mut self, http_client: ProviderHttpClient) -> Self {
        self.http_client = http_client;
        self
    }

    pub fn options(&self) -> &CognitoOptions {
        &self.options
    }

    pub fn authorization_endpoint(&self) -> &str {
        self.client.authorization_endpoint().as_str()
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn user_info_endpoint(&self) -> &str {
        &self.user_info_endpoint
    }

    pub fn jwks_endpoint(&self) -> String {
        cognito_jwks_uri(&self.options.region, &self.options.user_pool_id)
    }

    pub fn expected_issuer(&self) -> String {
        cognito_issuer(&self.options.region, &self.options.user_pool_id)
    }

    pub fn create_authorization_url(
        &self,
        input: CognitoAuthorizationUrlInput,
    ) -> Result<String, OAuthError> {
        if get_primary_client_id(&Some(self.options.client_id.clone())).is_none() {
            return Err(OAuthError::MissingOption("client_id"));
        }
        if self.options.require_client_secret && self.options.client_secret.is_none() {
            return Err(OAuthError::MissingOption("client_secret"));
        }

        let mut url = self
            .client
            .authorization_url(input.state, input.redirect_uri)?;
        if let Some(code_verifier) = input.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        if let Some(prompt) = self.options.prompt.clone() {
            url = url.prompt(prompt);
        }
        if let Some(response_mode) = self.options.response_mode.clone() {
            url = url.response_mode(response_mode);
        }
        let url = url.scopes(input.scopes).build()?;

        Ok(encode_scope_with_percent_twenty(url))
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let mut exchange = self.client.exchange_code(code, redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        exchange.send().await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.refresh_token(refresh_token_value)?.send().await
    }

    pub async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<bool, OAuthError> {
        let jwks_endpoint = self.jwks_endpoint();
        self.verify_id_token_with_jwks_url(token, nonce, &jwks_endpoint)
            .await
    }

    pub async fn verify_id_token_with_jwks_url(
        &self,
        token: &str,
        nonce: Option<&str>,
        jwks_url: &str,
    ) -> Result<bool, OAuthError> {
        if self.options.disable_id_token_sign_in {
            return Ok(false);
        }

        let audience = client_id_audiences(&self.options.client_id);
        let result = validate_token(
            token,
            jwks_url,
            ValidateTokenOptions::new(TokenValidationOptions {
                audience,
                issuer: vec![self.expected_issuer()],
                ..TokenValidationOptions::default().require_standard_claims()
            }),
        )
        .await?;

        Self::accept_id_token(&result.payload, nonce)
    }

    pub fn verify_id_token_with_jwk_set(
        &self,
        token: &str,
        nonce: Option<&str>,
        jwk_set: &JwkSet,
    ) -> Result<bool, OAuthError> {
        if self.options.disable_id_token_sign_in {
            return Ok(false);
        }

        let audience = client_id_audiences(&self.options.client_id);
        let result = verify_jws_with_jwks(
            token,
            jwk_set,
            &TokenValidationOptions {
                audience,
                issuer: vec![self.expected_issuer()],
                ..TokenValidationOptions::default().require_standard_claims()
            },
        )?;

        Self::accept_id_token(&result.payload, nonce)
    }

    fn accept_id_token(payload: &Value, nonce: Option<&str>) -> Result<bool, OAuthError> {
        if let Some(expected_nonce) = nonce {
            if payload.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
                return Ok(false);
            }
        }

        if !issued_within_max_age(payload, ID_TOKEN_MAX_AGE_SECONDS) {
            return Ok(false);
        }

        Ok(true)
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<CognitoUserInfo>, OAuthError> {
        if let Some(id_token) = &token.id_token {
            if let Ok(profile) = decode_jwt_payload::<CognitoProfile>(id_token) {
                return Ok(Some(self.map_user_info(profile)));
            }
        }

        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let response = match self
            .http_client
            .get(&self.user_info_endpoint)?
            .bearer_auth(access_token)
            .header("accept", "application/json")
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        let response = match response.error_for_status() {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        let profile = match response.json::<CognitoProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };

        Ok(Some(self.map_user_info(profile)))
    }

    fn map_user_info(&self, profile: CognitoProfile) -> CognitoUserInfo {
        let user = self
            .options
            .map_profile_to_user
            .as_ref()
            .map(|mapper| mapper(&profile))
            .unwrap_or_else(|| OAuth2UserInfo {
                id: profile.sub.clone(),
                name: Some(profile.display_name()),
                email: Some(profile.email.clone()),
                image: profile.picture.clone(),
                email_verified: profile.email_verified,
            });

        CognitoUserInfo {
            user,
            data: profile,
        }
    }
}

impl ProviderIdentity for CognitoProvider {
    fn id(&self) -> &str {
        "cognito"
    }

    fn name(&self) -> &str {
        "Cognito"
    }
}

#[allow(deprecated)]
pub fn cognito(options: CognitoOptions) -> Result<CognitoProvider, OAuthError> {
    CognitoProvider::new(options)
}

pub fn cognito_issuer(region: &str, user_pool_id: &str) -> String {
    format!("https://cognito-idp.{region}.amazonaws.com/{user_pool_id}")
}

pub fn cognito_jwks_uri(region: &str, user_pool_id: &str) -> String {
    format!(
        "{}/.well-known/jwks.json",
        cognito_issuer(region, user_pool_id)
    )
}

fn clean_cognito_domain(domain: &str) -> &str {
    domain
        .strip_prefix("https://")
        .or_else(|| domain.strip_prefix("http://"))
        .unwrap_or(domain)
}

fn client_id_audiences(client_id: &ClientId) -> Vec<String> {
    match client_id {
        ClientId::Single(value) if !value.is_empty() => vec![value.clone()],
        ClientId::Single(_) => Vec::new(),
        ClientId::Multiple(values) => values
            .iter()
            .filter(|value| !value.is_empty())
            .cloned()
            .collect(),
    }
}

fn issued_within_max_age(payload: &Value, max_age_seconds: i64) -> bool {
    let Some(issued_at) = payload.get("iat").and_then(Value::as_i64) else {
        return false;
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    issued_at >= now - max_age_seconds
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

fn encode_scope_with_percent_twenty(mut url: Url) -> String {
    let pairs = url.query_pairs().into_owned().collect::<Vec<_>>();
    if !pairs.iter().any(|(key, _)| key == "scope") {
        return url.to_string();
    }

    let query = pairs
        .into_iter()
        .map(|(key, value)| {
            if key == "scope" {
                format!(
                    "{}={}",
                    encode_query_component(&key),
                    encode_query_component(&value)
                )
            } else {
                let mut serializer = url::form_urlencoded::Serializer::new(String::new());
                serializer.append_pair(&key, &value);
                serializer.finish()
            }
        })
        .collect::<Vec<_>>()
        .join("&");

    url.set_query(None);
    let mut url_string = url.to_string();
    url_string.push('?');
    url_string.push_str(&query);
    url_string
}

fn encode_query_component(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => vec![char::from(byte)],
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}
