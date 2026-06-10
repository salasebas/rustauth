use std::sync::{Arc, Mutex};

use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbAdapter, DbValue, FindMany, MemoryAdapter, Update, Where};
use openauth_core::error::OpenAuthError;
use openauth_plugins::jwt::{
    jwt, sign_jwt, verify_jwt, Jwk, JwtAdapterOptions, JwtClaims, JwtJwksOptions, JwtOptions,
};
use serde_json::json;

use super::helpers::*;

#[tokio::test]
async fn private_keys_are_encrypted_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(options_with_plugin(jwt()?), adapter.clone())?;
    let mut claims = JwtClaims::new();
    claims.insert("sub".to_owned(), json!("user_1"));

    sign_jwt(&context, claims, None).await?;
    let records = adapter.find_many(FindMany::new("jwks")).await?;
    let private_key = records[0]
        .get("private_key")
        .and_then(|value| match value {
            DbValue::String(value) => Some(value.as_str()),
            _ => None,
        })
        .ok_or("missing private key")?;

    assert!(!private_key.trim_start().starts_with('{'));
    Ok(())
}

#[tokio::test]
async fn private_key_encryption_can_be_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let options = JwtOptions {
        jwks: JwtJwksOptions {
            disable_private_key_encryption: true,
            ..JwtJwksOptions::default()
        },
        ..JwtOptions::default()
    };
    let context = create_auth_context_with_adapter(
        options_with_plugin(openauth_plugins::jwt::jwt_with(options.clone())?),
        adapter.clone(),
    )?;
    let mut claims = JwtClaims::new();
    claims.insert("sub".to_owned(), json!("user_1"));

    sign_jwt(&context, claims, Some(options)).await?;
    let records = adapter.find_many(FindMany::new("jwks")).await?;
    let private_key = records[0]
        .get("private_key")
        .and_then(|value| match value {
            DbValue::String(value) => Some(value.as_str()),
            _ => None,
        })
        .ok_or("missing private key")?;

    assert!(private_key.trim_start().starts_with('{'));
    assert!(serde_json::from_str::<serde_json::Value>(private_key)?
        .get("d")
        .is_some());
    Ok(())
}

#[tokio::test]
async fn custom_adapter_callbacks_are_used() -> Result<(), Box<dyn std::error::Error>> {
    let stored = Arc::new(Mutex::new(Vec::<Jwk>::new()));
    let read_count = Arc::new(Mutex::new(0_u32));
    let create_count = Arc::new(Mutex::new(0_u32));

    let adapter_options = JwtAdapterOptions {
        get_jwks: Some(Arc::new({
            let stored = Arc::clone(&stored);
            let read_count = Arc::clone(&read_count);
            move |_context| {
                let stored = Arc::clone(&stored);
                let read_count = Arc::clone(&read_count);
                Box::pin(async move {
                    *read_count.lock().map_err(|error| {
                        openauth_core::error::OpenAuthError::Api(error.to_string())
                    })? += 1;
                    Ok(stored
                        .lock()
                        .map_err(|error| {
                            openauth_core::error::OpenAuthError::Api(error.to_string())
                        })?
                        .clone())
                })
            }
        })),
        create_jwk: Some(Arc::new({
            let stored = Arc::clone(&stored);
            let create_count = Arc::clone(&create_count);
            move |_context, jwk| {
                let stored = Arc::clone(&stored);
                let create_count = Arc::clone(&create_count);
                Box::pin(async move {
                    *create_count.lock().map_err(|error| {
                        openauth_core::error::OpenAuthError::Api(error.to_string())
                    })? += 1;
                    stored
                        .lock()
                        .map_err(|error| {
                            openauth_core::error::OpenAuthError::Api(error.to_string())
                        })?
                        .push(jwk.clone());
                    Ok(jwk)
                })
            }
        })),
    };
    let options = JwtOptions {
        adapter: adapter_options,
        ..JwtOptions::default()
    };
    let context = create_auth_context_with_adapter(
        options_with_plugin(openauth_plugins::jwt::jwt_with(options.clone())?),
        Arc::new(MemoryAdapter::new()),
    )?;
    let mut claims = JwtClaims::new();
    claims.insert("sub".to_owned(), json!("user_1"));

    sign_jwt(&context, claims, Some(options)).await?;

    assert_eq!(*read_count.lock().map_err(|error| error.to_string())?, 1);
    assert_eq!(*create_count.lock().map_err(|error| error.to_string())?, 1);
    assert_eq!(stored.lock().map_err(|error| error.to_string())?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn custom_adapter_is_used_by_jwks_endpoint_when_empty(
) -> Result<(), Box<dyn std::error::Error>> {
    let stored = Arc::new(Mutex::new(Vec::<Jwk>::new()));
    let options = JwtOptions {
        adapter: JwtAdapterOptions {
            get_jwks: Some(Arc::new({
                let stored = Arc::clone(&stored);
                move |_context| {
                    let stored = Arc::clone(&stored);
                    Box::pin(async move {
                        Ok(stored
                            .lock()
                            .map_err(|error| OpenAuthError::Api(error.to_string()))?
                            .clone())
                    })
                }
            })),
            create_jwk: Some(Arc::new({
                let stored = Arc::clone(&stored);
                move |_context, jwk| {
                    let stored = Arc::clone(&stored);
                    Box::pin(async move {
                        stored
                            .lock()
                            .map_err(|error| OpenAuthError::Api(error.to_string()))?
                            .push(jwk.clone());
                        Ok(jwk)
                    })
                }
            })),
        },
        ..JwtOptions::default()
    };
    let router = router_with_plugin(
        Arc::new(MemoryAdapter::new()),
        openauth_plugins::jwt::jwt_with(options)?,
    )?;

    let response = router
        .handle_async(request(http::Method::GET, "/api/auth/jwks", "", None)?)
        .await?;

    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(stored.lock().map_err(|error| error.to_string())?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn invalid_public_jwk_returns_none() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(options_with_plugin(jwt()?), adapter.clone())?;
    let mut claims = JwtClaims::new();
    claims.insert("sub".to_owned(), json!("user_1"));
    let token = sign_jwt(&context, claims, None).await?;

    let kid = jwt_kid(&token)?;
    adapter
        .update(
            Update::new("jwks")
                .where_clause(Where::new("id", DbValue::String(kid)))
                .data("public_key", DbValue::String("not-json".to_owned())),
        )
        .await?;

    assert!(verify_jwt(&context, &token, None).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn decrypting_key_with_wrong_secret_fails() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(options_with_plugin(jwt()?), adapter.clone())?;
    let mut claims = JwtClaims::new();
    claims.insert("sub".to_owned(), json!("user_1"));
    sign_jwt(&context, claims.clone(), None).await?;

    let wrong_context = create_auth_context_with_adapter(
        openauth_core::options::OpenAuthOptions {
            base_url: Some(TEST_BASE_URL.to_owned()),
            secret: Some("different-secret-12345678901234567890".to_owned()),
            plugins: vec![jwt()?],
            advanced: openauth_core::options::AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..openauth_core::options::AdvancedOptions::default()
            },
            ..openauth_core::options::OpenAuthOptions::default()
        },
        adapter,
    )?;

    assert!(sign_jwt(&wrong_context, claims, None).await.is_err());
    Ok(())
}
