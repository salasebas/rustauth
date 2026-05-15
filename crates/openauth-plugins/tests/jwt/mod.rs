mod claims;
mod crypto_adapter;
mod endpoints;
mod helpers;
mod sign_verify;

use std::sync::Arc;

use http::{header, Method, StatusCode};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::MemoryAdapter;
use openauth_core::error::OpenAuthError;
use openauth_plugins::jwt::{
    jwt, jwt_with_options, sign_jwt, to_exp_jwt, verify_jwt, JwkAlgorithm, JwtClaims,
    JwtJwksOptions, JwtOptions, JwtSigningOptions, TimeInput, UPSTREAM_PLUGIN_ID,
};
use serde_json::{json, Value};

use helpers::*;

#[test]
fn exposes_jwt_plugin_id() {
    assert_eq!(UPSTREAM_PLUGIN_ID, "jwt");
}

#[test]
fn jwt_plugin_contributes_jwks_schema() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context_with_adapter(
        options_with_plugin(jwt()?),
        Arc::new(MemoryAdapter::new()),
    )?;

    let table = context
        .db_schema
        .table("jwks")
        .ok_or("missing jwks table")?;
    assert_eq!(table.name, "jwks");
    assert_eq!(
        table.field("public_key").ok_or("missing public_key")?.name,
        "public_key"
    );
    assert_eq!(
        table
            .field("private_key")
            .ok_or("missing private_key")?
            .name,
        "private_key"
    );
    assert_eq!(
        table.field("created_at").ok_or("missing created_at")?.name,
        "created_at"
    );
    assert!(
        !table
            .field("expires_at")
            .ok_or("missing expires_at")?
            .required
    );
    Ok(())
}

#[test]
fn jwt_plugin_rejects_invalid_jwks_path() {
    for jwks_path in ["", "jwks", "/../jwks", "/jwks/../keys"] {
        let result = jwt_with_options(JwtOptions {
            jwks: JwtJwksOptions {
                jwks_path: jwks_path.to_owned(),
                ..JwtJwksOptions::default()
            },
            ..JwtOptions::default()
        });
        assert!(matches!(result, Err(OpenAuthError::InvalidConfig(_))));
    }
}

#[test]
fn jwt_plugin_validates_remote_signing_options() {
    let custom_sign = Arc::new(|claims: JwtClaims| {
        Box::pin(async move { Ok(format!("remote.{}.sig", claims.len())) }) as _
    });
    let result = jwt_with_options(JwtOptions {
        jwt: JwtSigningOptions {
            sign: Some(custom_sign.clone()),
            ..JwtSigningOptions::default()
        },
        ..JwtOptions::default()
    });
    assert!(matches!(result, Err(OpenAuthError::InvalidConfig(_))));

    let result = jwt_with_options(JwtOptions {
        jwks: JwtJwksOptions {
            remote_url: Some("https://example.com/jwks".to_owned()),
            key_pair_algorithm: None,
            ..JwtJwksOptions::default()
        },
        ..JwtOptions::default()
    });
    assert!(matches!(result, Err(OpenAuthError::InvalidConfig(_))));

    let result = jwt_with_options(JwtOptions {
        jwks: JwtJwksOptions {
            remote_url: Some("https://example.com/jwks".to_owned()),
            key_pair_algorithm: Some(JwkAlgorithm::Es256),
            ..JwtJwksOptions::default()
        },
        jwt: JwtSigningOptions {
            sign: Some(custom_sign),
            ..JwtSigningOptions::default()
        },
        ..JwtOptions::default()
    });
    assert!(result.is_ok());
}

#[test]
fn to_exp_jwt_supports_numbers_timestamps_and_duration_strings(
) -> Result<(), Box<dyn std::error::Error>> {
    let iat = 1_000;
    assert_eq!(to_exp_jwt(TimeInput::Seconds(3_600), iat)?, 3_600);
    assert_eq!(
        to_exp_jwt(TimeInput::UnixTimestamp(1_704_067_200), iat)?,
        1_704_067_200
    );
    assert_eq!(to_exp_jwt(TimeInput::Duration("1h".into()), iat)?, 4_600);
    assert_eq!(
        to_exp_jwt(TimeInput::Duration("7 days".into()), iat)?,
        605_800
    );
    assert_eq!(
        to_exp_jwt(TimeInput::Duration("1h ago".into()), iat)?,
        -2_600
    );
    assert_eq!(
        to_exp_jwt(TimeInput::Duration("1h from now".into()), iat)?,
        4_600
    );
    assert!(to_exp_jwt(TimeInput::Duration("invalid".into()), iat).is_err());
    Ok(())
}

#[tokio::test]
async fn jwks_endpoint_creates_public_key_set() -> Result<(), Box<dyn std::error::Error>> {
    for algorithm in [
        JwkAlgorithm::EdDsa,
        JwkAlgorithm::Es256,
        JwkAlgorithm::Es512,
        JwkAlgorithm::Rs256,
        JwkAlgorithm::Ps256,
    ] {
        let adapter = Arc::new(MemoryAdapter::new());
        let router = router_with_plugin(
            adapter,
            jwt_with_options(JwtOptions {
                jwks: JwtJwksOptions {
                    key_pair_algorithm: Some(algorithm),
                    ..JwtJwksOptions::default()
                },
                ..JwtOptions::default()
            })?,
        )?;

        let response = router
            .handle_async(request(Method::GET, "/api/auth/jwks", "", None)?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(response.body())?;
        let key = &body["keys"][0];
        assert_eq!(key["alg"], algorithm.as_str());
        assert!(key["kid"].as_str().is_some());
        assert!(
            key.get("d").is_none(),
            "JWKS must not expose private key material"
        );
    }
    Ok(())
}

#[tokio::test]
async fn sign_and_verify_jwt_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(options_with_plugin(jwt()?), adapter.clone())?;
    let mut claims = JwtClaims::new();
    claims.insert("sub".to_owned(), json!("user_1"));
    claims.insert("custom".to_owned(), json!("value"));

    let token = sign_jwt(&context, claims, None).await?;
    assert_eq!(token.split('.').count(), 3);

    let payload = verify_jwt(&context, &token, None)
        .await?
        .ok_or("missing valid payload")?;
    assert_eq!(payload["sub"], "user_1");
    assert_eq!(payload["custom"], "value");
    assert_eq!(payload["iss"], TEST_BASE_URL);
    assert_eq!(payload["aud"], TEST_BASE_URL);

    assert!(verify_jwt(&context, "not-a-jwt", None).await?.is_none());
    assert!(verify_jwt(&context, &token, Some("https://wrong.example"))
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn token_endpoint_requires_session_and_returns_jwt() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_session(adapter.as_ref()).await?;
    let router = router_with_plugin(adapter, jwt()?)?;
    let cookie = signed_session_cookie("token_1")?;

    let unauthorized = router
        .handle_async(request(Method::GET, "/api/auth/token", "", None)?)
        .await?;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .handle_async(request(Method::GET, "/api/auth/token", "", Some(&cookie))?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(
        body["token"]
            .as_str()
            .ok_or("missing token")?
            .split('.')
            .count(),
        3
    );
    Ok(())
}

#[tokio::test]
async fn get_session_sets_auth_jwt_header() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_session(adapter.as_ref()).await?;
    let router = router_with_plugin(adapter, jwt()?)?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-auth-jwt").is_some());
    assert!(response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("set-auth-jwt")));
    Ok(())
}

#[tokio::test]
async fn get_session_respects_disable_setting_jwt_header() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_session(adapter.as_ref()).await?;
    let router = router_with_plugin(
        adapter,
        jwt_with_options(JwtOptions {
            disable_setting_jwt_header: true,
            ..JwtOptions::default()
        })?,
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-auth-jwt").is_none());
    Ok(())
}

#[tokio::test]
async fn custom_jwks_path_replaces_default_jwks_endpoint() -> Result<(), Box<dyn std::error::Error>>
{
    let router = router_with_plugin(
        Arc::new(MemoryAdapter::new()),
        jwt_with_options(JwtOptions {
            jwks: JwtJwksOptions {
                jwks_path: "/.well-known/jwks.json".to_owned(),
                ..JwtJwksOptions::default()
            },
            ..JwtOptions::default()
        })?,
    )?;

    let response = router
        .handle_async(request(
            Method::GET,
            "/api/auth/.well-known/jwks.json",
            "",
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let old = router
        .handle_async(request(Method::GET, "/api/auth/jwks", "", None)?)
        .await?;
    assert_eq!(old.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn jwks_rotation_keeps_keys_during_grace_period() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(
        options_with_plugin(jwt_with_options(JwtOptions {
            jwks: JwtJwksOptions {
                rotation_interval: Some(-1),
                grace_period: 60,
                ..JwtJwksOptions::default()
            },
            ..JwtOptions::default()
        })?),
        adapter.clone(),
    )?;

    let mut claims = JwtClaims::new();
    claims.insert("sub".to_owned(), json!("user_1"));
    let rotation_options = JwtOptions {
        jwks: JwtJwksOptions {
            rotation_interval: Some(-1),
            grace_period: 60,
            ..JwtJwksOptions::default()
        },
        ..JwtOptions::default()
    };
    let first = sign_jwt(&context, claims.clone(), Some(rotation_options.clone())).await?;
    let second = sign_jwt(&context, claims, Some(rotation_options)).await?;
    assert_ne!(jwt_kid(&first)?, jwt_kid(&second)?);

    let router = router_with_plugin(
        adapter,
        jwt_with_options(JwtOptions {
            jwks: JwtJwksOptions {
                rotation_interval: Some(-1),
                grace_period: 60,
                ..JwtJwksOptions::default()
            },
            ..JwtOptions::default()
        })?,
    )?;
    let response = router
        .handle_async(request(Method::GET, "/api/auth/jwks", "", None)?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["keys"].as_array().ok_or("missing keys")?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn remote_url_disables_local_jwks_but_allows_custom_signer(
) -> Result<(), Box<dyn std::error::Error>> {
    let signer = Arc::new(|claims: JwtClaims| {
        Box::pin(async move {
            let sub = claims
                .get("sub")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            Ok(format!("remote.{sub}.signature"))
        }) as _
    });
    let plugin = jwt_with_options(JwtOptions {
        jwks: JwtJwksOptions {
            remote_url: Some("https://example.com/.well-known/jwks.json".to_owned()),
            key_pair_algorithm: Some(JwkAlgorithm::Es256),
            ..JwtJwksOptions::default()
        },
        jwt: JwtSigningOptions {
            sign: Some(signer),
            ..JwtSigningOptions::default()
        },
        ..JwtOptions::default()
    })?;
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_session(adapter.as_ref()).await?;
    let router = router_with_plugin(adapter, plugin)?;
    let cookie = signed_session_cookie("token_1")?;

    let jwks = router
        .handle_async(request(Method::GET, "/api/auth/jwks", "", None)?)
        .await?;
    assert_eq!(jwks.status(), StatusCode::NOT_FOUND);

    let token = router
        .handle_async(request(Method::GET, "/api/auth/token", "", Some(&cookie))?)
        .await?;
    let body: Value = serde_json::from_slice(token.body())?;
    assert_eq!(body["token"], "remote.user_1.signature");
    Ok(())
}
