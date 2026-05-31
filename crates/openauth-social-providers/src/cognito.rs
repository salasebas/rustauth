//! Amazon Cognito social OAuth provider.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_oauth::oauth2::{
    create_authorization_url, get_primary_client_id, refresh_access_token,
    validate_authorization_code, validate_token, AuthorizationCodeRequest, AuthorizationUrlRequest,
    ClientAuthentication, ClientId, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError,
    OAuthProviderContract, ProviderOptions, RefreshAccessTokenRequest, TokenValidationOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use url::Url;

use crate::http::ProviderHttpClient;

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

    fn provider_options(&self) -> ProviderOptions {
        ProviderOptions {
            client_id: Some(self.client_id.clone()),
            client_secret: self.client_secret.clone(),
            client_key: self.client_key.clone(),
            scope: self.scope.clone(),
            disable_default_scope: self.disable_default_scope,
            redirect_uri: self.redirect_uri.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            disable_id_token_sign_in: self.disable_id_token_sign_in,
            prompt: self.prompt.clone(),
            response_mode: self.response_mode.clone(),
            ..ProviderOptions::default()
        }
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
    options: CognitoOptions,
    authorization_endpoint: String,
    token_endpoint: String,
    user_info_endpoint: String,
    http_client: ProviderHttpClient,
}

impl CognitoProvider {
    pub fn new(options: CognitoOptions) -> Result<Self, OAuthError> {
        if options.domain.is_empty() || options.region.is_empty() || options.user_pool_id.is_empty()
        {
            return Err(OAuthError::MissingOption("domain, region and user_pool_id"));
        }

        let clean_domain = clean_cognito_domain(&options.domain).to_owned();
        Ok(Self {
            options,
            authorization_endpoint: format!("https://{clean_domain}/oauth2/authorize"),
            token_endpoint: format!("https://{clean_domain}/oauth2/token"),
            user_info_endpoint: format!("https://{clean_domain}/oauth2/userinfo"),
            http_client: ProviderHttpClient::shared(),
        })
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
        &self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
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

        let mut scopes = Vec::new();
        if !self.options.disable_default_scope {
            scopes.extend(DEFAULT_SCOPES.iter().map(|scope| (*scope).to_owned()));
        }
        scopes.extend(self.options.scope.iter().cloned());
        scopes.extend(input.scopes);

        let url = create_authorization_url(AuthorizationUrlRequest {
            id: self.id().to_owned(),
            options: self.options.provider_options(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            redirect_uri: input.redirect_uri,
            state: input.state,
            code_verifier: input.code_verifier,
            scopes,
            prompt: self.options.prompt.clone(),
            response_mode: self.options.response_mode.clone(),
            ..AuthorizationUrlRequest::default()
        })?;

        Ok(encode_scope_with_percent_twenty(url))
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: self.token_endpoint.clone(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.provider_options(),
                code_verifier,
                authentication: ClientAuthentication::Post,
                ..AuthorizationCodeRequest::default()
            },
        })
        .await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: self.token_endpoint.clone(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token_value.into(),
                options: self.options.provider_options(),
                authentication: ClientAuthentication::Post,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<bool, OAuthError> {
        if self.options.disable_id_token_sign_in {
            return Ok(false);
        }

        let audience = client_id_audiences(&self.options.client_id);
        let result = validate_token(
            token,
            &self.jwks_endpoint(),
            TokenValidationOptions {
                audience,
                issuer: vec![self.expected_issuer()],
                ..TokenValidationOptions::default()
            },
        )
        .await?;

        if let Some(expected_nonce) = nonce {
            if result.payload.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
                return Ok(false);
            }
        }

        if !issued_within_max_age(&result.payload, ID_TOKEN_MAX_AGE_SECONDS) {
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

impl OAuthProviderContract for CognitoProvider {
    fn id(&self) -> &str {
        "cognito"
    }

    fn name(&self) -> &str {
        "Cognito"
    }
}

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
