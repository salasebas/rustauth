use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::MemoryAdapter;
use openauth_plugins::jwt::{
    jwt, jwt_with_options, sign_jwt, verify_jwt, verify_jwt_with_options, JwtClaims,
    JwtJwksOptions, JwtOptions, JwtSignHandler, JwtSigningOptions,
};
use serde_json::{json, Value};

use super::helpers::*;

#[tokio::test]
async fn custom_signer_receives_defaulted_claims() -> Result<(), Box<dyn std::error::Error>> {
    let captured = Arc::new(Mutex::new(None::<JwtClaims>));
    let signer: JwtSignHandler = Arc::new({
        let captured = Arc::clone(&captured);
        move |claims| {
            let captured = Arc::clone(&captured);
            Box::pin(async move {
                *captured.lock().map_err(|error| {
                    openauth_core::error::OpenAuthError::Api(error.to_string())
                })? = Some(claims);
                Ok("remote.jwt.signature".to_owned())
            })
        }
    });
    let options = JwtOptions {
        jwks: JwtJwksOptions {
            remote_url: Some("https://example.com/jwks?tenant=one".to_owned()),
            ..JwtJwksOptions::default()
        },
        jwt: JwtSigningOptions {
            sign: Some(signer),
            ..JwtSigningOptions::default()
        },
        ..JwtOptions::default()
    };
    let context = create_auth_context_with_adapter(
        options_with_plugin(jwt_with_options(options.clone())?),
        Arc::new(MemoryAdapter::new()),
    )?;
    let mut claims = JwtClaims::new();
    claims.insert("sub".to_owned(), json!("user_1"));

    let token = sign_jwt(&context, claims, Some(options)).await?;
    let claims = captured
        .lock()
        .map_err(|error| error.to_string())?
        .clone()
        .ok_or("missing captured claims")?;

    assert_eq!(token, "remote.jwt.signature");
    assert_eq!(claims["sub"], "user_1");
    assert_eq!(claims["iss"], TEST_BASE_URL);
    assert_eq!(claims["aud"], TEST_BASE_URL);
    assert!(claims.get("iat").and_then(Value::as_i64).is_some());
    assert!(claims.get("exp").and_then(Value::as_i64).is_some());
    Ok(())
}

#[tokio::test]
async fn verify_returns_none_for_invalid_claim_or_key_cases(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(options_with_plugin(jwt()?), adapter)?;

    let mut valid_claims = JwtClaims::new();
    valid_claims.insert("sub".to_owned(), json!("user_1"));
    let valid = sign_jwt(&context, valid_claims, None).await?;
    assert!(verify_jwt(&context, &valid, None).await?.is_some());

    let mut no_sub = JwtClaims::new();
    no_sub.insert("custom".to_owned(), json!("value"));
    let no_sub_token = sign_jwt(&context, no_sub, None).await?;
    assert!(verify_jwt(&context, &no_sub_token, None).await?.is_none());

    let mut wrong_aud = JwtClaims::new();
    wrong_aud.insert("sub".to_owned(), json!("user_1"));
    wrong_aud.insert("aud".to_owned(), json!("https://wrong.example"));
    let wrong_aud_token = sign_jwt(&context, wrong_aud, None).await?;
    assert!(verify_jwt(&context, &wrong_aud_token, None)
        .await?
        .is_none());

    let mut expired = JwtClaims::new();
    expired.insert("sub".to_owned(), json!("user_1"));
    expired.insert("exp".to_owned(), json!(1));
    let expired_token = sign_jwt(&context, expired, None).await?;
    assert!(verify_jwt(&context, &expired_token, None).await?.is_none());

    assert!(verify_jwt(&context, "malformed", None).await?.is_none());
    assert!(verify_jwt(&context, &remove_kid(&valid)?, None)
        .await?
        .is_none());
    assert!(verify_jwt(&context, &replace_kid(&valid, "unknown")?, None)
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn verify_with_options_accepts_custom_audience() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(options_with_plugin(jwt()?), adapter)?;
    let options = JwtOptions {
        jwt: JwtSigningOptions {
            audience: Some(vec!["https://api.example".to_owned()]),
            ..JwtSigningOptions::default()
        },
        ..JwtOptions::default()
    };
    let mut claims = JwtClaims::new();
    claims.insert("sub".to_owned(), json!("user_1"));

    let token = sign_jwt(&context, claims, Some(options.clone())).await?;

    assert!(verify_jwt(&context, &token, None).await?.is_none());
    assert!(verify_jwt_with_options(&context, &token, &options, None)
        .await?
        .is_some());
    Ok(())
}

fn replace_kid(token: &str, kid: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parts = token.split('.').collect::<Vec<_>>();
    let mut header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    header["kid"] = json!(kid);
    Ok(format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        parts.get(1).ok_or("missing payload")?,
        parts.get(2).ok_or("missing signature")?
    ))
}

fn remove_kid(token: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parts = token.split('.').collect::<Vec<_>>();
    let mut header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    header
        .as_object_mut()
        .ok_or("header must be object")?
        .remove("kid");
    Ok(format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        parts.get(1).ok_or("missing payload")?,
        parts.get(2).ok_or("missing signature")?
    ))
}
