use std::sync::Arc;

use http::{header, Method, Response, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_core::plugin::{AuthPlugin, PluginAfterHookAction};
use openauth_plugins::jwt::{
    jwt, jwt_with, verify_jwt, verify_jwt_with_options, JwkAlgorithm, JwtJwksOptions, JwtOptions,
    JwtSigningOptions,
};
use serde_json::Value;

use super::helpers::*;

#[tokio::test]
async fn sign_and_verify_endpoints_are_server_only() -> Result<(), Box<dyn std::error::Error>> {
    let router = router_with_plugin(Arc::new(MemoryAdapter::new()), jwt()?)?;

    let sign = router
        .handle_async(request(
            Method::POST,
            "/api/auth/sign-jwt",
            r#"{"payload":{"sub":"user_1"}}"#,
            None,
        )?)
        .await?;
    let verify = router
        .handle_async(request(
            Method::POST,
            "/api/auth/verify-jwt",
            r#"{"token":"malformed"}"#,
            None,
        )?)
        .await?;

    assert_eq!(sign.status(), StatusCode::NOT_FOUND);
    assert_eq!(verify.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn sign_and_verify_endpoints_are_reachable_through_handle_async_server(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router_with_plugin(Arc::new(MemoryAdapter::new()), jwt()?)?;

    let sign = router
        .handle_async_server(request(
            Method::POST,
            "/api/auth/sign-jwt",
            r#"{"payload":{"sub":"user_1"}}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign.status(), StatusCode::OK);
    let token = serde_json::from_slice::<Value>(sign.body())?["token"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();

    let verify = router
        .handle_async_server(request(
            Method::POST,
            "/api/auth/verify-jwt",
            &format!(r#"{{"token":"{token}"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(verify.status(), StatusCode::OK);
    let payload = serde_json::from_slice::<Value>(verify.body())?;
    assert_eq!(payload["payload"]["sub"], "user_1");
    Ok(())
}

#[tokio::test]
async fn sign_jwt_endpoint_accepts_serializable_override_options(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let plugin = jwt()?;
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/sign-jwt")
        .ok_or("missing sign-jwt endpoint")?
        .clone();
    let context = openauth_core::context::create_auth_context_with_adapter(
        options_with_plugin(plugin),
        adapter,
    )?;

    let response = (endpoint.handler)(
        &context,
        request(
            Method::POST,
            "/api/auth/sign-jwt",
            r#"{"payload":{"sub":"user_1"},"overrideOptions":{"jwt":{"issuer":"https://issuer.example","audience":["https://api.example"],"expirationTime":"1h"}}}"#,
            None,
        )?,
    )
    .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    let token = body["token"].as_str().ok_or("missing token")?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(verify_jwt(&context, token, None).await?.is_none());
    let claims = verify_jwt_with_options(
        &context,
        token,
        &JwtOptions {
            jwt: JwtSigningOptions {
                audience: Some(vec!["https://api.example".to_owned()]),
                ..JwtSigningOptions::default()
            },
            ..JwtOptions::default()
        },
        Some("https://issuer.example"),
    )
    .await?
    .ok_or("missing verified claims")?;
    assert_eq!(claims["sub"], "user_1");
    assert_eq!(claims["iss"], "https://issuer.example");
    assert_eq!(claims["aud"], "https://api.example");
    Ok(())
}

#[tokio::test]
async fn get_session_merges_exposed_headers() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_session(adapter.as_ref()).await?;
    let preexisting = AuthPlugin::new("preexisting-expose-header").with_after_hook(
        "/get-session",
        |_context, _request, response| {
            let (mut parts, body) = response.into_parts();
            parts.headers.insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                header::HeaderValue::from_static("x-existing"),
            );
            Ok(PluginAfterHookAction::Continue(Response::from_parts(
                parts, body,
            )))
        },
    );
    let context = openauth_core::context::create_auth_context_with_adapter(
        openauth_core::options::OpenAuthOptions {
            base_url: Some(TEST_BASE_URL.to_owned()),
            secret: Some("test-secret-123456789012345678901234".to_owned()),
            plugins: vec![preexisting, jwt()?],
            advanced: openauth_core::options::AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..openauth_core::options::AdvancedOptions::default()
            },
            ..openauth_core::options::OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let router = openauth_core::api::AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        openauth_core::api::core_auth_async_endpoints(adapter),
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
    let expose = response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .and_then(|value| value.to_str().ok())
        .ok_or("missing expose header")?;

    assert!(expose.contains("x-existing"));
    assert!(expose.contains("set-auth-jwt"));
    Ok(())
}

#[tokio::test]
async fn jwks_drops_keys_expired_beyond_grace() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let options = JwtOptions {
        jwks: JwtJwksOptions {
            rotation_interval: Some(-120),
            grace_period: 1,
            disable_private_key_encryption: true,
            ..JwtJwksOptions::default()
        },
        ..JwtOptions::default()
    };
    let context = openauth_core::context::create_auth_context_with_adapter(
        options_with_plugin(jwt_with(options.clone())?),
        adapter.clone(),
    )?;
    let mut claims = openauth_plugins::jwt::JwtClaims::new();
    claims.insert("sub".to_owned(), serde_json::json!("user_1"));
    openauth_plugins::jwt::sign_jwt(&context, claims, Some(options.clone())).await?;
    let router = router_with_plugin(adapter, jwt_with(options)?)?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/jwks", "", None)?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["keys"].as_array().ok_or("missing keys")?.len(), 0);
    Ok(())
}

#[test]
fn remote_url_accepts_plain_strings_and_query_params() {
    let result = jwt_with(JwtOptions {
        jwks: JwtJwksOptions {
            remote_url: Some("not a url ?x=1".to_owned()),
            ..JwtJwksOptions::default()
        },
        jwt: JwtSigningOptions {
            sign: Some(Arc::new(|_claims| {
                Box::pin(async move { Ok("remote.jwt.signature".to_owned()) })
            })),
            ..JwtSigningOptions::default()
        },
        ..JwtOptions::default()
    });

    assert!(result.is_ok());
}

#[tokio::test]
async fn token_from_http_validates_against_jwks_kid_and_claims(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_session(adapter.as_ref()).await?;
    let context = openauth_core::context::create_auth_context_with_adapter(
        options_with_plugin(jwt()?),
        adapter.clone(),
    )?;
    let router = router_with_plugin(adapter, jwt()?)?;
    let cookie = signed_session_cookie("token_1")?;

    let token_response = router
        .handle_async(request(Method::GET, "/api/auth/token", "", Some(&cookie))?)
        .await?;
    assert_eq!(token_response.status(), StatusCode::OK);
    let token = serde_json::from_slice::<Value>(token_response.body())?["token"]
        .as_str()
        .ok_or("missing token")?
        .to_owned();

    let jwks_response = router
        .handle_async(request(Method::GET, "/api/auth/jwks", "", None)?)
        .await?;
    assert_eq!(jwks_response.status(), StatusCode::OK);
    let jwks: Value = serde_json::from_slice(jwks_response.body())?;
    let kid = jwt_kid(&token)?;
    let keys = jwks["keys"].as_array().ok_or("missing keys")?;
    assert!(keys.iter().any(|key| key["kid"] == kid));

    let claims = verify_jwt(&context, &token, None)
        .await?
        .ok_or("token should verify against stored JWKS")?;
    assert_eq!(claims["sub"], "user_1");
    Ok(())
}

#[tokio::test]
async fn remote_url_still_allows_local_signing_without_custom_signer_for_supported_algorithms(
) -> Result<(), Box<dyn std::error::Error>> {
    for algorithm in [
        JwkAlgorithm::EdDsa,
        JwkAlgorithm::Es256,
        JwkAlgorithm::Es512,
        JwkAlgorithm::Rs256,
        JwkAlgorithm::Ps256,
    ] {
        let adapter = Arc::new(MemoryAdapter::new());
        seed_user_session(adapter.as_ref()).await?;
        let options = JwtOptions {
            jwks: JwtJwksOptions {
                remote_url: Some("https://example.com/.well-known/jwks.json".to_owned()),
                key_pair_algorithm: Some(algorithm),
                disable_private_key_encryption: true,
                ..JwtJwksOptions::default()
            },
            ..JwtOptions::default()
        };
        let context = openauth_core::context::create_auth_context_with_adapter(
            options_with_plugin(jwt_with(options.clone())?),
            adapter.clone(),
        )?;
        let router = router_with_plugin(adapter, jwt_with(options)?)?;
        let cookie = signed_session_cookie("token_1")?;

        let response = router
            .handle_async(request(Method::GET, "/api/auth/token", "", Some(&cookie))?)
            .await?;
        let body: Value = serde_json::from_slice(response.body())?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(verify_jwt(
            &context,
            body["token"].as_str().ok_or("missing token")?,
            None
        )
        .await?
        .is_some());
    }
    Ok(())
}

#[test]
fn rsa_modulus_length_must_be_at_least_2048() {
    let result = jwt_with(JwtOptions {
        jwks: JwtJwksOptions {
            key_pair_algorithm: Some(JwkAlgorithm::Rs256),
            rsa_modulus_length: Some(1024),
            ..JwtJwksOptions::default()
        },
        ..JwtOptions::default()
    });

    assert!(result.is_err());
}

#[tokio::test]
async fn rsa_modulus_length_can_be_configured() -> Result<(), Box<dyn std::error::Error>> {
    let router = router_with_plugin(
        Arc::new(MemoryAdapter::new()),
        jwt_with(JwtOptions {
            jwks: JwtJwksOptions {
                key_pair_algorithm: Some(JwkAlgorithm::Rs256),
                rsa_modulus_length: Some(2048),
                ..JwtJwksOptions::default()
            },
            ..JwtOptions::default()
        })?,
    )?;

    let response = router
        .handle_async(request(Method::GET, "/api/auth/jwks", "", None)?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(body["keys"][0]["alg"], "RS256");
    assert!(body["keys"][0]["n"].as_str().is_some());
    Ok(())
}
