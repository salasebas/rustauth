use josekit::jwk::JwkSet;
use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::{Es256, Es384, Es512};
use josekit::jws::alg::eddsa::EddsaJwsAlgorithm::Eddsa;
use josekit::jws::alg::hmac::HmacJwsAlgorithm::{Hs256, Hs384, Hs512};
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::{Rs256, Rs384, Rs512};
use josekit::jws::JwsHeader;
use josekit::jwt;
use serde_json::Value;

use super::claims::{validate_payload_claims, TokenValidationOptions};
use super::error::OAuthError;
use super::http::{default_http_client, OAuthHttpClient};

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
    validate_token_with_client(token, jwks_endpoint, options, &default_http_client()?).await
}

pub async fn validate_token_with_client(
    token: &str,
    jwks_endpoint: &str,
    options: TokenValidationOptions,
    client: &OAuthHttpClient,
) -> Result<TokenValidationResult, OAuthError> {
    let jwks = client.get_bytes(jwks_endpoint).await?;
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
    if !options
        .allowed_algorithms
        .iter()
        .any(|allowed| allowed == alg)
    {
        return Err(OAuthError::UnsupportedAlgorithm(alg.to_owned()));
    }
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
        other => return Err(OAuthError::UnsupportedAlgorithm(other.to_owned())),
    };
    validate_payload_claims(payload.claims_set(), options)?;
    Ok(TokenValidationResult {
        payload: Value::Object(payload.claims_set().clone()),
        header_algorithm: Some(alg.to_owned()),
        key_id: Some(kid.to_owned()),
    })
}
