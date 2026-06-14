use serde_json::Value;

use super::claims::{
    audience_matches, validate_required_claims, validate_temporal_claims_with_leeway,
    TokenValidationOptions,
};
use super::error::OAuthError;
use super::http::{default_http_client, OAuthHttpClient};
use super::jwks::{verify_jws_access_token, JwksVerifyOptions, OAuthJwksCacheConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyAccessTokenRemote {
    pub introspect_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub force: bool,
}

#[derive(Debug, Clone, Default)]
pub struct VerifyAccessTokenOptions {
    pub verify_options: TokenValidationOptions,
    pub scopes: Vec<String>,
    pub jwks_url: Option<String>,
    pub remote_verify: Option<VerifyAccessTokenRemote>,
    pub jwks_cache: OAuthJwksCacheConfig,
    pub http: Option<OAuthHttpClient>,
}

impl VerifyAccessTokenOptions {
    pub fn jwks(
        jwks_url: impl Into<String>,
        audience: impl IntoIterator<Item = impl Into<String>>,
        issuer: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, OAuthError> {
        let jwks_url = jwks_url.into();
        url::Url::parse(&jwks_url)?;
        Ok(Self {
            verify_options: TokenValidationOptions {
                audience: audience.into_iter().map(Into::into).collect(),
                issuer: issuer.into_iter().map(Into::into).collect(),
                ..TokenValidationOptions::default()
            },
            jwks_url: Some(jwks_url),
            ..Self::default()
        })
    }

    pub fn remote(remote_verify: VerifyAccessTokenRemote) -> Result<Self, OAuthError> {
        url::Url::parse(&remote_verify.introspect_url)?;
        if remote_verify.client_id.is_empty() {
            return Err(OAuthError::MissingOption("client_id"));
        }
        if remote_verify.client_secret.is_empty() {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(Self {
            remote_verify: Some(remote_verify),
            ..Self::default()
        })
    }
}

pub async fn verify_access_token(
    token: &str,
    options: VerifyAccessTokenOptions,
) -> Result<Value, OAuthError> {
    let client = match options.http.as_ref() {
        Some(client) => client,
        None => &default_http_client()?,
    };
    let mut payload = None;
    if let Some(jwks_url) = &options.jwks_url {
        if !options
            .remote_verify
            .as_ref()
            .is_some_and(|remote| remote.force)
        {
            if options.remote_verify.is_some() && !looks_like_parseable_jws(token) {
                payload = None;
            } else {
                match verify_jws_access_token(
                    token,
                    jwks_url,
                    JwksVerifyOptions {
                        verify_options: options.verify_options.clone(),
                        cache: options.jwks_cache,
                        http: Some(client.clone()),
                    },
                )
                .await
                {
                    Ok(result) => payload = Some(result.payload),
                    Err(error)
                        if options.remote_verify.is_some()
                            && local_jws_failure_allows_remote_fallback(&error) =>
                    {
                        payload = None;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }

    if let Some(remote) = options.remote_verify {
        let mut request = super::request::OAuthFormRequest::new();
        request.set_body("client_id", remote.client_id);
        request.set_body("client_secret", remote.client_secret);
        request.set_body("token", token);
        request.set_body("token_type_hint", "access_token");
        let introspect = client.post_form(&remote.introspect_url, request).await?;
        let active = introspect
            .get("active")
            .and_then(Value::as_bool)
            .ok_or(OAuthError::MissingTokenField("active"))?;
        if !active {
            return Err(OAuthError::TokenVerification("token inactive".to_owned()));
        }
        validate_introspection_claims(&introspect, &options.verify_options)?;
        payload = Some(introspect);
    }

    let payload =
        payload.ok_or_else(|| OAuthError::TokenVerification("no token payload".to_owned()))?;
    validate_scopes(&payload, &options.scopes)?;
    Ok(payload)
}

fn validate_introspection_claims(
    payload: &Value,
    options: &TokenValidationOptions,
) -> Result<(), OAuthError> {
    let Some(claims) = payload.as_object() else {
        return Err(OAuthError::TokenVerification(
            "introspection payload must be an object".to_owned(),
        ));
    };
    validate_temporal_claims_with_leeway(claims, options.leeway_seconds)?;
    validate_required_claims(claims, options)?;
    // Match Better Auth: only validate audience when the introspection response includes
    // a truthy `aud` claim (RFC 7662 responses may omit it).
    if !options.audience.is_empty()
        && introspection_includes_audience(claims)
        && !audience_matches(claims.get("aud"), &options.audience)
    {
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

/// Returns true when the introspection JSON includes a non-empty `aud` claim.
fn introspection_includes_audience(claims: &serde_json::Map<String, Value>) -> bool {
    match claims.get("aud") {
        None | Some(Value::Null) => false,
        Some(Value::String(audience)) => !audience.is_empty(),
        Some(Value::Array(audiences)) => audiences
            .iter()
            .any(|value| value.as_str().is_some_and(|audience| !audience.is_empty())),
        Some(_) => true,
    }
}

/// Mirrors Better Auth `verifyAccessToken`: swallow local JWS parse errors when remote
/// introspection is configured so opaque or malformed tokens can fall back.
fn local_jws_failure_allows_remote_fallback(error: &OAuthError) -> bool {
    match error {
        OAuthError::TokenVerification(message) => {
            message == "token is not a JWS"
                || message == "missing jwt kid"
                || message.starts_with("JOSE operation failed:")
        }
        OAuthError::Jose(message) => message.contains("InvalidJws"),
        _ => false,
    }
}

fn looks_like_parseable_jws(token: &str) -> bool {
    if token.split('.').count() != 3 {
        return false;
    }
    josekit::jwt::decode_header(token).is_ok()
}

fn validate_scopes(payload: &Value, required_scopes: &[String]) -> Result<(), OAuthError> {
    if required_scopes.is_empty() {
        return Ok(());
    }
    let scopes = payload
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("")
        .split_whitespace()
        .collect::<std::collections::HashSet<_>>();
    for scope in required_scopes {
        if !scopes.contains(scope.as_str()) {
            return Err(OAuthError::TokenVerification(format!(
                "invalid scope {scope}"
            )));
        }
    }
    Ok(())
}
