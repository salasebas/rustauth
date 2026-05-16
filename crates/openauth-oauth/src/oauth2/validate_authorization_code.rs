use std::collections::BTreeMap;

use josekit::jwk::JwkSet;
use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::{Es256, Es384, Es512};
use josekit::jws::alg::eddsa::EddsaJwsAlgorithm::Eddsa;
use josekit::jws::alg::hmac::HmacJwsAlgorithm::{Hs256, Hs384, Hs512};
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::{Rs256, Rs384, Rs512};
use josekit::jws::JwsHeader;
use josekit::jwt;
use serde_json::Value;
use time::OffsetDateTime;

use super::error::OAuthError;
use super::request::{
    apply_client_authentication, post_form, ClientAuthentication, OAuthFormRequest,
};
use super::tokens::{get_oauth2_tokens, OAuth2Tokens, ProviderOptions};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeRequest {
    pub code: String,
    pub redirect_uri: String,
    pub options: ProviderOptions,
    pub code_verifier: Option<String>,
    pub device_id: Option<String>,
    pub authentication: ClientAuthentication,
    pub headers: BTreeMap<String, String>,
    pub additional_params: BTreeMap<String, String>,
    pub resource: Vec<String>,
}

impl Default for AuthorizationCodeRequest {
    fn default() -> Self {
        Self {
            code: String::new(),
            redirect_uri: String::new(),
            options: ProviderOptions::default(),
            code_verifier: None,
            device_id: None,
            authentication: ClientAuthentication::Post,
            headers: BTreeMap::new(),
            additional_params: BTreeMap::new(),
            resource: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTokenRequest<T> {
    pub token_endpoint: String,
    pub request: T,
}

pub fn create_authorization_code_request(
    input: AuthorizationCodeRequest,
) -> Result<OAuthFormRequest, OAuthError> {
    let mut request = OAuthFormRequest::new();
    for (key, value) in input.headers {
        request.set_header(key, value);
    }
    request.set_body("grant_type", "authorization_code");
    request.set_body("code", input.code);
    if let Some(code_verifier) = input.code_verifier {
        request.set_body("code_verifier", code_verifier);
    }
    if let Some(client_key) = &input.options.client_key {
        request.set_body("client_key", client_key);
    }
    if let Some(device_id) = input.device_id {
        request.set_body("device_id", device_id);
    }
    request.set_body(
        "redirect_uri",
        input
            .options
            .redirect_uri
            .as_deref()
            .unwrap_or(&input.redirect_uri),
    );
    for resource in input.resource {
        request.push_body("resource", resource);
    }
    apply_client_authentication(&mut request, &input.options, input.authentication, false)?;
    for (key, value) in input.additional_params {
        request.set_body(key, value);
    }
    Ok(request)
}

pub fn authorization_code_request(
    input: AuthorizationCodeRequest,
) -> Result<OAuthFormRequest, OAuthError> {
    create_authorization_code_request(input)
}

pub async fn validate_authorization_code(
    input: ClientTokenRequest<AuthorizationCodeRequest>,
) -> Result<OAuth2Tokens, OAuthError> {
    let request = authorization_code_request(input.request)?;
    let data = post_form(&input.token_endpoint, request).await?;
    get_oauth2_tokens(data)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenValidationOptions {
    pub audience: Vec<String>,
    pub issuer: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenValidationResult {
    pub payload: Value,
    pub header_algorithm: Option<String>,
    pub key_id: Option<String>,
}

pub async fn validate_token(
    token: &str,
    jwks_endpoint: &str,
    options: TokenValidationOptions,
) -> Result<TokenValidationResult, OAuthError> {
    let jwks = reqwest::Client::new()
        .get(jwks_endpoint)
        .header("accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let jwk_set = JwkSet::from_bytes(&jwks)?;
    verify_jws_with_jwks(token, &jwk_set, &options)
}

pub fn verify_jws_with_jwks(
    token: &str,
    jwk_set: &JwkSet,
    options: &TokenValidationOptions,
) -> Result<TokenValidationResult, OAuthError> {
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
    validate_payload_claims(payload.claims_set(), options)?;
    Ok(TokenValidationResult {
        payload: Value::Object(payload.claims_set().clone()),
        header_algorithm: Some(alg.to_owned()),
        key_id: Some(kid.to_owned()),
    })
}

pub(crate) fn validate_payload_claims(
    claims: &serde_json::Map<String, Value>,
    options: &TokenValidationOptions,
) -> Result<(), OAuthError> {
    validate_temporal_claims(claims)?;
    if !options.audience.is_empty() && !audience_matches(claims.get("aud"), &options.audience) {
        return Err(OAuthError::TokenVerification(
            "audience mismatch".to_owned(),
        ));
    }
    if !options.issuer.is_empty() {
        let issuer = claims.get("iss").and_then(Value::as_str);
        if !issuer.is_some_and(|issuer| options.issuer.iter().any(|expected| expected == issuer)) {
            return Err(OAuthError::TokenVerification("issuer mismatch".to_owned()));
        }
    }
    Ok(())
}

pub(crate) fn validate_temporal_claims(
    claims: &serde_json::Map<String, Value>,
) -> Result<(), OAuthError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
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

pub(crate) fn audience_matches(value: Option<&Value>, expected: &[String]) -> bool {
    match value {
        Some(Value::String(audience)) => expected.iter().any(|expected| expected == audience),
        Some(Value::Array(audiences)) => audiences
            .iter()
            .filter_map(Value::as_str)
            .any(|audience| expected.iter().any(|expected| expected == audience)),
        _ => false,
    }
}

fn numeric_claim(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok())),
        _ => None,
    }
}
