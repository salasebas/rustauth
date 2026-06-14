//! SCIM bearer token helpers.

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBearerToken {
    pub base_token: String,
    pub provider_id: String,
    pub organization_id: Option<String>,
}

pub fn encode_bearer_token(
    base_token: &str,
    provider_id: &str,
    organization_id: Option<&str>,
) -> String {
    let raw = match organization_id {
        Some(organization_id) => format!("{base_token}:{provider_id}:{organization_id}"),
        None => format!("{base_token}:{provider_id}"),
    };
    URL_SAFE_NO_PAD.encode(raw)
}

pub fn decode_bearer_token(token: &str) -> Result<DecodedBearerToken, &'static str> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .or_else(|_| URL_SAFE.decode(token))
        .map_err(|_| "Invalid SCIM token")?;
    let raw = String::from_utf8(bytes).map_err(|_| "Invalid SCIM token")?;
    let mut parts = raw.split(':');
    let base_token = parts.next().filter(|value| !value.is_empty());
    let provider_id = parts.next().filter(|value| !value.is_empty());
    let (Some(base_token), Some(provider_id)) = (base_token, provider_id) else {
        return Err("Invalid SCIM token");
    };
    let rest = parts.collect::<Vec<_>>();
    let organization_id = (!rest.is_empty()).then(|| rest.join(":"));

    Ok(DecodedBearerToken {
        base_token: base_token.to_owned(),
        provider_id: provider_id.to_owned(),
        organization_id,
    })
}

pub fn hash_base_token(base_token: &str) -> String {
    let digest = Sha256::digest(base_token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}
