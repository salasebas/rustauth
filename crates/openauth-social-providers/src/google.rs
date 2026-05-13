//! Google social OAuth provider.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwk::JwkSet;
use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::{Es256, Es384, Es512};
use josekit::jws::alg::eddsa::EddsaJwsAlgorithm::Eddsa;
use josekit::jws::alg::hmac::HmacJwsAlgorithm::{Hs256, Hs384, Hs512};
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::{Rs256, Rs384, Rs512};
use josekit::jws::JwsHeader;
use josekit::jwt;
use openauth_oauth::oauth2::{
    create_authorization_url, get_jwks, get_primary_client_id, refresh_access_token,
    validate_authorization_code, AuthorizationCodeRequest, AuthorizationUrlRequest,
    ClientAuthentication, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError,
    OAuthProviderContract, ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const GOOGLE_ID: &str = "google";
pub const GOOGLE_NAME: &str = "Google";
pub const GOOGLE_AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
pub const GOOGLE_JWKS_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v3/certs";
pub const GOOGLE_ISSUER_HTTPS: &str = "https://accounts.google.com";
pub const GOOGLE_ISSUER_BARE: &str = "accounts.google.com";
const GOOGLE_ID_TOKEN_MAX_AGE_SECONDS: i64 = 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoogleAccessType {
    Offline,
    Online,
}

impl GoogleAccessType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Online => "online",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoogleDisplay {
    Page,
    Popup,
    Touch,
    Wap,
}

impl GoogleDisplay {
    fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Popup => "popup",
            Self::Touch => "touch",
            Self::Wap => "wap",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoogleOptions {
    pub oauth: ProviderOptions,
    pub access_type: Option<GoogleAccessType>,
    pub display: Option<GoogleDisplay>,
    pub hd: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoogleAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
    pub display: Option<GoogleDisplay>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoogleAuthorizationCodeRequest {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleProfile {
    pub aud: String,
    pub azp: String,
    pub email: String,
    pub email_verified: bool,
    pub exp: i64,
    pub family_name: String,
    pub given_name: String,
    pub hd: Option<String>,
    pub iat: i64,
    pub iss: String,
    pub jti: Option<String>,
    pub locale: Option<String>,
    pub name: String,
    pub nbf: Option<i64>,
    pub picture: String,
    pub sub: String,
    pub nonce: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GoogleUserInfo {
    pub user: OAuth2UserInfo,
    pub data: GoogleProfile,
}

#[derive(Debug, Clone)]
pub struct GoogleProvider {
    options: GoogleOptions,
}

pub fn google(options: GoogleOptions) -> GoogleProvider {
    GoogleProvider::new(options)
}

impl GoogleProvider {
    pub fn new(options: GoogleOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &GoogleOptions {
        &self.options
    }

    pub fn create_authorization_url(
        &self,
        request: GoogleAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        self.ensure_authorization_options(request.code_verifier.as_deref())?;

        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            ["email", "profile", "openid"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request.scopes);

        create_authorization_url(AuthorizationUrlRequest {
            id: GOOGLE_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: GOOGLE_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_verifier: request.code_verifier,
            scopes,
            prompt: self.options.oauth.prompt.clone(),
            access_type: self
                .options
                .access_type
                .map(|value| value.as_str().to_owned()),
            display: request
                .display
                .or(self.options.display)
                .map(|value| value.as_str().to_owned()),
            login_hint: request.login_hint,
            hd: self.options.hd.clone(),
            additional_params: BTreeMap::from([(
                "include_granted_scopes".to_owned(),
                "true".to_owned(),
            )]),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        request: GoogleAuthorizationCodeRequest,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: GOOGLE_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: request.code,
                redirect_uri: request.redirect_uri,
                code_verifier: request.code_verifier,
                device_id: request.device_id,
                options: self.options.oauth.clone(),
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
            token_endpoint: GOOGLE_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token_value.into(),
                options: ProviderOptions {
                    client_id: self.options.oauth.client_id.clone(),
                    client_key: self.options.oauth.client_key.clone(),
                    client_secret: self.options.oauth.client_secret.clone(),
                    ..ProviderOptions::default()
                },
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
        self.verify_id_token_with_jwks_url(token, nonce, GOOGLE_JWKS_ENDPOINT)
            .await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<GoogleUserInfo>, OAuthError> {
        let Some(id_token) = token.id_token.as_deref() else {
            return Ok(None);
        };
        let profile = decode_jwt_payload::<GoogleProfile>(id_token)?;
        Ok(Some(GoogleUserInfo {
            user: Self::map_profile_to_user_info(&profile),
            data: profile,
        }))
    }

    pub fn map_profile_to_user_info(profile: &GoogleProfile) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: profile.sub.clone(),
            name: Some(profile.name.clone()),
            email: Some(profile.email.clone()),
            image: Some(profile.picture.clone()),
            email_verified: profile.email_verified,
        }
    }

    async fn verify_id_token_with_jwks_url(
        &self,
        token: &str,
        nonce: Option<&str>,
        jwks_url: &str,
    ) -> Result<bool, OAuthError> {
        let jwks = match get_jwks(jwks_url).await {
            Ok(jwks) => jwks,
            Err(_) => return Ok(false),
        };
        self.verify_id_token_with_jwk_set(token, nonce, &jwks)
    }

    fn verify_id_token_with_jwk_set(
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

        let result = match verify_google_id_token_jws(token, jwk_set, &audiences) {
            Ok(result) => result,
            Err(_) => return Ok(false),
        };

        if let Some(expected_nonce) = nonce {
            let actual_nonce = result.get("nonce").and_then(Value::as_str);
            if actual_nonce != Some(expected_nonce) {
                return Ok(false);
            }
        }

        Ok(id_token_is_fresh(&result))
    }

    fn client_id_audiences(&self) -> Vec<String> {
        match &self.options.oauth.client_id {
            Some(openauth_oauth::oauth2::ClientId::Single(value)) if !value.is_empty() => {
                vec![value.clone()]
            }
            Some(openauth_oauth::oauth2::ClientId::Multiple(values)) => values
                .iter()
                .filter(|value| !value.is_empty())
                .cloned()
                .collect(),
            _ => Vec::new(),
        }
    }

    fn ensure_authorization_options(&self, code_verifier: Option<&str>) -> Result<(), OAuthError> {
        if get_primary_client_id(&self.options.oauth.client_id).is_none() {
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
        if code_verifier.unwrap_or("").is_empty() {
            return Err(OAuthError::MissingOption("code_verifier"));
        }
        Ok(())
    }
}

impl OAuthProviderContract for GoogleProvider {
    fn id(&self) -> &str {
        GOOGLE_ID
    }

    fn name(&self) -> &str {
        GOOGLE_NAME
    }
}

fn verify_google_id_token_jws(
    token: &str,
    jwk_set: &JwkSet,
    audiences: &[String],
) -> Result<Value, OAuthError> {
    let header = jwt::decode_header(token)?;
    let header = header
        .as_any()
        .downcast_ref::<JwsHeader>()
        .ok_or_else(|| OAuthError::TokenVerification("token is not a JWS".to_owned()))?;
    let kid = header
        .key_id()
        .ok_or_else(|| OAuthError::TokenVerification("missing jwt kid".to_owned()))?;
    let alg = header
        .algorithm()
        .ok_or_else(|| OAuthError::TokenVerification("missing jwt alg".to_owned()))?;
    let jwk = jwk_set
        .get(kid)
        .into_iter()
        .next()
        .ok_or_else(|| OAuthError::TokenVerification("no matching jwk".to_owned()))?;

    let (payload, _) = match alg {
        "HS256" => jwt::decode_with_verifier(token, &Hs256.verifier_from_jwk(jwk)?)?,
        "HS384" => jwt::decode_with_verifier(token, &Hs384.verifier_from_jwk(jwk)?)?,
        "HS512" => jwt::decode_with_verifier(token, &Hs512.verifier_from_jwk(jwk)?)?,
        "RS256" => jwt::decode_with_verifier(token, &Rs256.verifier_from_jwk(jwk)?)?,
        "RS384" => jwt::decode_with_verifier(token, &Rs384.verifier_from_jwk(jwk)?)?,
        "RS512" => jwt::decode_with_verifier(token, &Rs512.verifier_from_jwk(jwk)?)?,
        "ES256" => jwt::decode_with_verifier(token, &Es256.verifier_from_jwk(jwk)?)?,
        "ES384" => jwt::decode_with_verifier(token, &Es384.verifier_from_jwk(jwk)?)?,
        "ES512" => jwt::decode_with_verifier(token, &Es512.verifier_from_jwk(jwk)?)?,
        "EdDSA" => jwt::decode_with_verifier(token, &Eddsa.verifier_from_jwk(jwk)?)?,
        other => {
            return Err(OAuthError::TokenVerification(format!(
                "unsupported jwt alg `{other}`"
            )))
        }
    };

    let claims = payload.claims_set();
    if !audience_matches(claims.get("aud"), audiences) {
        return Err(OAuthError::TokenVerification(
            "audience mismatch".to_owned(),
        ));
    }
    let issuer = claims.get("iss").and_then(Value::as_str);
    if !matches!(issuer, Some(GOOGLE_ISSUER_HTTPS | GOOGLE_ISSUER_BARE)) {
        return Err(OAuthError::TokenVerification("issuer mismatch".to_owned()));
    }
    validate_temporal_claims(claims)?;
    Ok(Value::Object(claims.clone()))
}

fn audience_matches(value: Option<&Value>, expected: &[String]) -> bool {
    match value {
        Some(Value::String(audience)) => expected.iter().any(|expected| expected == audience),
        Some(Value::Array(audiences)) => audiences
            .iter()
            .filter_map(Value::as_str)
            .any(|audience| expected.iter().any(|expected| expected == audience)),
        _ => false,
    }
}

fn validate_temporal_claims(claims: &serde_json::Map<String, Value>) -> Result<(), OAuthError> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if let Some(expiration) = numeric_claim(claims.get("exp")) {
        if expiration <= now {
            return Err(OAuthError::TokenVerification("token expired".to_owned()));
        }
    }
    if let Some(not_before) = numeric_claim(claims.get("nbf")) {
        if not_before > now {
            return Err(OAuthError::TokenVerification("token not active".to_owned()));
        }
    }
    if let Some(issued_at) = numeric_claim(claims.get("iat")) {
        if issued_at > now + 60 {
            return Err(OAuthError::TokenVerification(
                "token issued in the future".to_owned(),
            ));
        }
    }
    Ok(())
}

fn numeric_claim(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok())),
        _ => None,
    }
}

fn id_token_is_fresh(payload: &Value) -> bool {
    let Some(issued_at) = payload.get("iat").and_then(Value::as_i64) else {
        return false;
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    issued_at >= now - GOOGLE_ID_TOKEN_MAX_AGE_SECONDS
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

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "Google provider tests intentionally fail fast with contextual setup errors"
)]
mod tests {
    use super::*;
    use josekit::jwk::Jwk;
    use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
    use josekit::jws::JwsHeader;
    use josekit::jwt::{self, JwtPayload};
    use serde_json::json;

    #[tokio::test]
    async fn verify_id_token_accepts_any_configured_audience() {
        let (token, jwk) = signed_google_id_token("ios-client", GOOGLE_ISSUER_HTTPS, Some("n"));
        let jwks = jwks_with_key(jwk);
        let provider = GoogleProvider::new(GoogleOptions {
            oauth: ProviderOptions {
                client_id: Some(openauth_oauth::oauth2::ClientId::Multiple(vec![
                    "web-client".to_owned(),
                    "ios-client".to_owned(),
                    "android-client".to_owned(),
                ])),
                client_secret: Some("secret".to_owned()),
                ..ProviderOptions::default()
            },
            ..GoogleOptions::default()
        });

        assert!(provider
            .verify_id_token_with_jwk_set(&token, Some("n"), &jwks)
            .expect("verification should complete"));
    }

    #[tokio::test]
    async fn verify_id_token_rejects_unknown_audience_wrong_issuer_nonce_and_disabled_sign_in() {
        let (token, jwk) = signed_google_id_token("unknown-client", GOOGLE_ISSUER_HTTPS, Some("n"));
        let jwks = jwks_with_key(jwk);
        let provider = test_provider(false);

        assert!(!provider
            .verify_id_token_with_jwk_set(&token, Some("n"), &jwks)
            .expect("verification should complete"));

        let (token, jwk) =
            signed_google_id_token("web-client", "https://issuer.example", Some("n"));
        let jwks = jwks_with_key(jwk);
        assert!(!provider
            .verify_id_token_with_jwk_set(&token, Some("n"), &jwks)
            .expect("verification should complete"));

        let (token, jwk) = signed_google_id_token("web-client", GOOGLE_ISSUER_HTTPS, Some("n"));
        let jwks = jwks_with_key(jwk);
        assert!(!provider
            .verify_id_token_with_jwk_set(&token, Some("different"), &jwks)
            .expect("verification should complete"));

        let disabled = test_provider(true);
        assert!(!disabled
            .verify_id_token_with_jwk_set(&token, Some("n"), &jwks)
            .expect("verification should complete"));
    }

    fn test_provider(disable_id_token_sign_in: bool) -> GoogleProvider {
        GoogleProvider::new(GoogleOptions {
            oauth: ProviderOptions {
                client_id: Some(openauth_oauth::oauth2::ClientId::from("web-client")),
                client_secret: Some("secret".to_owned()),
                disable_id_token_sign_in,
                ..ProviderOptions::default()
            },
            ..GoogleOptions::default()
        })
    }

    fn signed_google_id_token(audience: &str, issuer: &str, nonce: Option<&str>) -> (String, Jwk) {
        let kid = "google-test-key";
        let mut jwk = Jwk::generate_rsa_key(2048).expect("rsa key should generate");
        jwk.set_key_id(kid);
        jwk.set_algorithm("RS256");
        jwk.set_key_use("sig");

        let signer = Rs256
            .signer_from_jwk(&jwk)
            .expect("rsa signer should build");
        let mut payload = JwtPayload::new();
        payload
            .set_claim("aud", Some(json!(audience)))
            .expect("aud claim");
        payload
            .set_claim("iss", Some(json!(issuer)))
            .expect("iss claim");
        payload
            .set_claim("sub", Some(json!("google-subject")))
            .expect("sub claim");
        payload
            .set_claim("email", Some(json!("ada@example.com")))
            .expect("email claim");
        payload
            .set_claim("email_verified", Some(json!(true)))
            .expect("email_verified claim");
        if let Some(nonce) = nonce {
            payload
                .set_claim("nonce", Some(json!(nonce)))
                .expect("nonce claim");
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        payload
            .set_claim("iat", Some(json!(now)))
            .expect("iat claim");
        payload
            .set_claim("exp", Some(json!(now + 3600)))
            .expect("exp claim");

        let mut header = JwsHeader::new();
        header.set_algorithm("RS256");
        header.set_key_id(kid);
        let token =
            jwt::encode_with_signer(&payload, &header, &signer).expect("token should encode");
        let mut public_jwk = jwk.to_public_key().expect("public jwk should export");
        public_jwk.set_key_id(kid);
        public_jwk.set_algorithm("RS256");
        public_jwk.set_key_use("sig");
        (token, public_jwk)
    }

    fn jwks_with_key(jwk: Jwk) -> JwkSet {
        let bytes = json!({ "keys": [jwk] }).to_string();
        JwkSet::from_bytes(bytes.as_bytes()).expect("jwks should parse")
    }
}
