use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::{Es256, Es512};
use josekit::jws::alg::eddsa::EddsaJwsAlgorithm::Eddsa;
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
use josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::Ps256;
use josekit::jwt;
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use serde_json::Value;

use super::claims::JwtClaims;
use super::{adapter, JwkAlgorithm, JwtOptions};

pub async fn verify_jwt(
    context: &AuthContext,
    token: &str,
    issuer_override: Option<&str>,
) -> Result<Option<JwtClaims>, OpenAuthError> {
    verify_jwt_with_options(context, token, &JwtOptions::default(), issuer_override).await
}

pub async fn verify_jwt_with_options(
    context: &AuthContext,
    token: &str,
    options: &JwtOptions,
    issuer_override: Option<&str>,
) -> Result<Option<JwtClaims>, OpenAuthError> {
    let Some(kid) = token_kid(token) else {
        return Ok(None);
    };
    let Some(key) = adapter::get_all_keys(context, options)
        .await?
        .into_iter()
        .find(|key| key.id == kid)
    else {
        return Ok(None);
    };
    let algorithm = key.alg.unwrap_or_else(|| options.algorithm());
    let Ok(public) = josekit::jwk::Jwk::from_bytes(&key.public_key) else {
        return Ok(None);
    };
    let decoded = match algorithm {
        JwkAlgorithm::EdDsa => {
            let Ok(verifier) = Eddsa.verifier_from_jwk(&public) else {
                return Ok(None);
            };
            jwt::decode_with_verifier(token, &verifier)
        }
        JwkAlgorithm::Es256 => {
            let Ok(verifier) = Es256.verifier_from_jwk(&public) else {
                return Ok(None);
            };
            jwt::decode_with_verifier(token, &verifier)
        }
        JwkAlgorithm::Es512 => {
            let Ok(verifier) = Es512.verifier_from_jwk(&public) else {
                return Ok(None);
            };
            jwt::decode_with_verifier(token, &verifier)
        }
        JwkAlgorithm::Rs256 => {
            let Ok(verifier) = Rs256.verifier_from_jwk(&public) else {
                return Ok(None);
            };
            jwt::decode_with_verifier(token, &verifier)
        }
        JwkAlgorithm::Ps256 => {
            let Ok(verifier) = Ps256.verifier_from_jwk(&public) else {
                return Ok(None);
            };
            jwt::decode_with_verifier(token, &verifier)
        }
    };
    let Ok((payload, _)) = decoded else {
        return Ok(None);
    };
    let claims = payload.claims_set().clone();
    if !valid_temporal_claims(&claims) || !valid_issuer(&claims, context, options, issuer_override)
    {
        return Ok(None);
    }
    if claims.get("sub").and_then(Value::as_str).is_none()
        || !valid_audience(&claims, context, options)
    {
        return Ok(None);
    }
    Ok(Some(claims))
}

fn token_kid(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    parts.next()?;
    parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let header = URL_SAFE_NO_PAD.decode(header).ok()?;
    let header: Value = serde_json::from_slice(&header).ok()?;
    header.get("kid").and_then(Value::as_str).map(str::to_owned)
}

fn valid_temporal_claims(claims: &JwtClaims) -> bool {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if claims
        .get("exp")
        .and_then(Value::as_i64)
        .is_some_and(|exp| exp <= now)
    {
        return false;
    }
    if claims
        .get("nbf")
        .and_then(Value::as_i64)
        .is_some_and(|nbf| nbf > now)
    {
        return false;
    }
    true
}

fn valid_issuer(
    claims: &JwtClaims,
    context: &AuthContext,
    options: &JwtOptions,
    issuer_override: Option<&str>,
) -> bool {
    let expected = issuer_override
        .map(str::to_owned)
        .or_else(|| options.jwt.issuer.clone())
        .unwrap_or_else(|| context.base_url.clone());
    claims.get("iss").and_then(Value::as_str) == Some(expected.as_str())
}

fn valid_audience(claims: &JwtClaims, context: &AuthContext, options: &JwtOptions) -> bool {
    let expected = options
        .jwt
        .audience
        .clone()
        .unwrap_or_else(|| vec![context.base_url.clone()]);
    match claims.get("aud") {
        Some(Value::String(audience)) => expected.iter().any(|item| item == audience),
        Some(Value::Array(audiences)) => audiences
            .iter()
            .filter_map(Value::as_str)
            .any(|audience| expected.iter().any(|item| item == audience)),
        _ => false,
    }
}
