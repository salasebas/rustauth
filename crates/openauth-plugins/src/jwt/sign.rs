use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::{Es256, Es512};
use josekit::jws::alg::eddsa::EddsaJwsAlgorithm::Eddsa;
use josekit::jws::alg::rsassa::RsassaJwsAlgorithm::Rs256;
use josekit::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::Ps256;
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;
use serde_json::Value;

use super::claims::{claims_with_defaults, JwtClaims};
use super::keys::{generate_jwk, JwkAlgorithm};
use super::{adapter, crypto, JwtOptions};

pub async fn sign_jwt(
    context: &AuthContext,
    claims: JwtClaims,
    override_options: Option<JwtOptions>,
) -> Result<String, OpenAuthError> {
    let options = override_options.unwrap_or_default();
    sign_jwt_with_options(context, claims, &options).await
}

pub(crate) async fn sign_jwt_with_options(
    context: &AuthContext,
    claims: JwtClaims,
    options: &JwtOptions,
) -> Result<String, OpenAuthError> {
    let claims = claims_with_defaults(claims, &context.base_url, options)?;
    if let Some(sign) = &options.jwt.sign {
        return sign(claims).await;
    }

    let mut key = adapter::get_latest_key(context, options).await?;
    if key
        .as_ref()
        .and_then(|key| key.expires_at)
        .is_some_and(|expires_at| expires_at <= time::OffsetDateTime::now_utc())
    {
        key = None;
    }
    let key = match key {
        Some(key) => key,
        None => {
            let key = crypto::encrypt_private_key(
                context,
                generate_jwk(options)?,
                options.jwks.disable_private_key_encryption,
            )?;
            adapter::create_jwk(context, options, key).await?
        }
    };
    let private_key = crypto::decrypt_private_key(
        context,
        &key.private_key,
        options.jwks.disable_private_key_encryption,
    )?;
    encode_with_key(
        &private_key,
        key.alg.unwrap_or_else(|| options.algorithm()),
        &key.id,
        claims,
    )
}

fn encode_with_key(
    private_key: &str,
    algorithm: JwkAlgorithm,
    key_id: &str,
    claims: JwtClaims,
) -> Result<String, OpenAuthError> {
    let jwk = josekit::jwk::Jwk::from_bytes(private_key)
        .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
    let payload = jwt_payload(claims)?;
    let mut header = JwsHeader::new();
    header.set_algorithm(algorithm.as_str());
    header.set_key_id(key_id);

    match algorithm {
        JwkAlgorithm::EdDsa => jwt::encode_with_signer(
            &payload,
            &header,
            &Eddsa
                .signer_from_jwk(&jwk)
                .map_err(|error| OpenAuthError::Crypto(error.to_string()))?,
        ),
        JwkAlgorithm::Es256 => jwt::encode_with_signer(
            &payload,
            &header,
            &Es256
                .signer_from_jwk(&jwk)
                .map_err(|error| OpenAuthError::Crypto(error.to_string()))?,
        ),
        JwkAlgorithm::Es512 => jwt::encode_with_signer(
            &payload,
            &header,
            &Es512
                .signer_from_jwk(&jwk)
                .map_err(|error| OpenAuthError::Crypto(error.to_string()))?,
        ),
        JwkAlgorithm::Rs256 => jwt::encode_with_signer(
            &payload,
            &header,
            &Rs256
                .signer_from_jwk(&jwk)
                .map_err(|error| OpenAuthError::Crypto(error.to_string()))?,
        ),
        JwkAlgorithm::Ps256 => jwt::encode_with_signer(
            &payload,
            &header,
            &Ps256
                .signer_from_jwk(&jwk)
                .map_err(|error| OpenAuthError::Crypto(error.to_string()))?,
        ),
    }
    .map_err(|error| OpenAuthError::Crypto(error.to_string()))
}

fn jwt_payload(claims: JwtClaims) -> Result<JwtPayload, OpenAuthError> {
    let mut payload = JwtPayload::new();
    for (key, value) in claims {
        payload
            .set_claim(&key, Some(value_to_jose(value)))
            .map_err(|error| OpenAuthError::Crypto(error.to_string()))?;
    }
    Ok(payload)
}

fn value_to_jose(value: Value) -> josekit::Value {
    serde_json::from_value(value).unwrap_or(josekit::Value::Null)
}
