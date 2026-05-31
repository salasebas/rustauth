//! Apple social OAuth provider.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_oauth::oauth2::{
    create_authorization_url, get_primary_client_id, refresh_access_token,
    validate_authorization_code, validate_token, AuthorizationCodeRequest, AuthorizationUrlRequest,
    ClientAuthentication, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError,
    OAuthProviderContract, ProviderOptions, RefreshAccessTokenRequest, TokenValidationOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use url::Url;

const APPLE_AUTHORIZATION_ENDPOINT: &str = "https://appleid.apple.com/auth/authorize";
const APPLE_TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";
const APPLE_JWKS_ENDPOINT: &str = "https://appleid.apple.com/auth/keys";
const APPLE_ISSUER: &str = "https://appleid.apple.com";
const ID_TOKEN_MAX_AGE_SECONDS: i64 = 60 * 60;

/// Apple profile claims decoded from an Apple `id_token`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppleProfile {
    pub sub: String,
    pub email: Option<String>,
    #[serde(default, deserialize_with = "deserialize_apple_bool")]
    pub email_verified: bool,
    #[serde(default, deserialize_with = "deserialize_optional_apple_bool")]
    pub is_private_email: Option<bool>,
    pub real_user_status: Option<i64>,
    pub name: Option<String>,
    pub picture: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum AppleBoolean {
    Bool(bool),
    String(String),
    #[default]
    Missing,
}

impl AppleBoolean {
    fn as_bool(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::String(value) => value == "true",
            Self::Missing => false,
        }
    }
}

/// User payload Apple sends outside the token on the first consent response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleNonConformUser {
    pub name: AppleName,
    pub email: String,
}

/// Name shape nested inside Apple's non-conformant `user` payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleName {
    #[serde(rename = "firstName")]
    pub first_name: String,
    #[serde(rename = "lastName")]
    pub last_name: String,
}

/// Apple provider options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleOptions {
    pub provider: ProviderOptions,
    pub app_bundle_identifier: Option<String>,
    pub audience: Vec<String>,
}

/// User info returned after mapping an Apple profile into OpenAuth's OAuth user shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppleUserInfo {
    pub user: OAuth2UserInfo,
    pub data: AppleProfile,
}

/// Apple OAuth provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleProvider {
    options: AppleOptions,
}

/// Create an Apple OAuth provider from typed options.
pub fn apple(options: AppleOptions) -> AppleProvider {
    AppleProvider { options }
}

impl AppleProvider {
    pub fn options(&self) -> &AppleOptions {
        &self.options
    }

    pub fn create_authorization_url<I, S>(
        &self,
        state: &str,
        scopes: I,
        redirect_uri: &str,
    ) -> Result<Url, OAuthError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.require_client_id_and_secret()?;

        let mut resolved_scopes = Vec::new();
        if !self.options.provider.disable_default_scope {
            resolved_scopes.push("email".to_owned());
            resolved_scopes.push("name".to_owned());
        }
        resolved_scopes.extend(self.options.provider.scope.iter().cloned());
        resolved_scopes.extend(scopes.into_iter().map(Into::into));

        create_authorization_url(AuthorizationUrlRequest {
            id: "apple".to_owned(),
            options: self.options.provider.clone(),
            authorization_endpoint: APPLE_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: redirect_uri.to_owned(),
            state: state.to_owned(),
            scopes: resolved_scopes,
            response_mode: Some("form_post".to_owned()),
            response_type: Some("code id_token".to_owned()),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.require_client_id_and_secret()?;
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: APPLE_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.provider.clone(),
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
        self.require_client_id_and_secret()?;
        refresh_access_token(ClientTokenRequest {
            token_endpoint: APPLE_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token_value.into(),
                options: self.options.provider.clone(),
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
        self.verify_id_token_with_jwks_url(token, nonce, APPLE_JWKS_ENDPOINT)
            .await
    }

    pub async fn verify_id_token_with_jwks_url(
        &self,
        token: &str,
        nonce: Option<&str>,
        jwks_url: &str,
    ) -> Result<bool, OAuthError> {
        if self.options.provider.disable_id_token_sign_in {
            return Ok(false);
        }

        let audience = self.audience()?;
        let verified = match validate_token(
            token,
            jwks_url,
            TokenValidationOptions {
                audience,
                issuer: vec![APPLE_ISSUER.to_owned()],
                ..TokenValidationOptions::default().require_standard_claims()
            },
        )
        .await
        {
            Ok(verified) => verified,
            Err(_) => return Ok(false),
        };

        if !validate_max_token_age(&verified.payload) {
            return Ok(false);
        }
        if let Some(expected_nonce) = nonce {
            let actual_nonce = verified.payload.get("nonce").and_then(Value::as_str);
            if actual_nonce != Some(expected_nonce) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn get_user_info(
        &self,
        tokens: &OAuth2Tokens,
        apple_user: Option<AppleNonConformUser>,
    ) -> Result<Option<AppleUserInfo>, OAuthError> {
        let Some(id_token) = tokens.id_token.as_deref() else {
            return Ok(None);
        };
        let mut profile = decode_jwt_payload::<AppleProfile>(id_token)?;
        let name = apple_user
            .as_ref()
            .map(|user| full_name(&user.name))
            .unwrap_or_else(|| profile.name.clone().unwrap_or_default());
        profile.name = Some(name.clone());

        Ok(Some(AppleUserInfo {
            user: OAuth2UserInfo {
                id: profile.sub.clone(),
                name: Some(name),
                email: profile.email.clone(),
                image: profile.picture.clone(),
                email_verified: profile.email_verified,
            },
            data: profile,
        }))
    }

    fn require_client_id_and_secret(&self) -> Result<(), OAuthError> {
        if get_primary_client_id(&self.options.provider.client_id).is_none() {
            return Err(OAuthError::MissingOption("client_id"));
        }
        if self.options.provider.client_secret.is_none() {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }

    fn audience(&self) -> Result<Vec<String>, OAuthError> {
        if !self.options.audience.is_empty() {
            return Ok(self.options.audience.clone());
        }
        if let Some(bundle_identifier) = &self.options.app_bundle_identifier {
            return Ok(vec![bundle_identifier.clone()]);
        }
        get_primary_client_id(&self.options.provider.client_id)
            .map(|client_id| vec![client_id.to_owned()])
            .ok_or(OAuthError::MissingOption("client_id"))
    }
}

impl OAuthProviderContract for AppleProvider {
    fn id(&self) -> &str {
        "apple"
    }

    fn name(&self) -> &str {
        "Apple"
    }
}

fn decode_jwt_payload<T>(token: &str) -> Result<T, OAuthError>
where
    T: for<'de> Deserialize<'de>,
{
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| OAuthError::InvalidResponse("id token is not a JWT".to_owned()))?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).map_err(|error| {
        OAuthError::InvalidResponse(format!("invalid id token payload: {error}"))
    })?;
    serde_json::from_slice(&decoded)
        .map_err(|error| OAuthError::InvalidResponse(format!("invalid id token claims: {error}")))
}

fn full_name(name: &AppleName) -> String {
    [name.first_name.as_str(), name.last_name.as_str()]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_max_token_age(payload: &Value) -> bool {
    let Some(issued_at) = payload.get("iat").and_then(Value::as_i64) else {
        return false;
    };
    issued_at >= OffsetDateTime::now_utc().unix_timestamp() - ID_TOKEN_MAX_AGE_SECONDS
}

fn deserialize_apple_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(AppleBoolean::deserialize(deserializer)?.as_bool())
}

fn deserialize_optional_apple_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<AppleBoolean>::deserialize(deserializer)?.map(|value| value.as_bool()))
}
