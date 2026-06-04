use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use http::{HeaderValue, Method, StatusCode};
use openauth_core::db::{DbAdapter, DbValue, Delete, FindMany, Where};
use openauth_core::options::{AdvancedOptions, IpAddressOptions};
use openauth_passkey::{
    PasskeyAuthenticationOptions, PasskeyOptions, PasskeyWebAuthnBackend,
    RealPasskeyWebAuthnBackend, WebAuthnConfig,
};
use serde_json::{json, Value};

use crate::support::{
    cookie_header_from_response, empty_request, join_cookies, json_request,
    json_request_with_origin, passkey_challenge_cookie_name, seed_passkey, seed_user_two,
    seeded_router, seeded_router_with_advanced, set_cookie_values, sign_in_cookie,
    signed_passkey_challenge_cookie, single_verification_expires_at,
};

#[tokio::test]
async fn generate_authenticate_options_without_session_returns_discoverable_options(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["challenge"], "authentication-challenge");
    assert_eq!(body["rpId"], "localhost");
    assert!(body.get("allowCredentials").is_none());
    Ok(())
}

#[tokio::test]
async fn generate_authenticate_options_includes_legacy_credential_ids_in_allow_list(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let session_cookie = sign_in_cookie(&router).await?;
    adapter
        .create(
            openauth_core::db::Create::new("passkey")
                .data("id", DbValue::String("legacy-passkey".to_owned()))
                .data("name", DbValue::String("Legacy".to_owned()))
                .data("public_key", DbValue::String("public-key".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .data(
                    "credential_id",
                    DbValue::String("legacy-credential-id".to_owned()),
                )
                .data("counter", DbValue::Number(0))
                .data("device_type", DbValue::String("singleDevice".to_owned()))
                .data("backed_up", DbValue::Boolean(false))
                .data("transports", DbValue::Null)
                .data(
                    "created_at",
                    DbValue::Timestamp(time::OffsetDateTime::now_utc()),
                )
                .data("aaguid", DbValue::Null)
                .data("webauthn_credential", DbValue::Null)
                .force_allow_id(),
        )
        .await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            Some(&session_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    let Some(allowed) = body
        .get("allowCredentials")
        .and_then(|value| value.as_array())
    else {
        return Err(format!("allowCredentials missing: {body:?}").into());
    };
    assert!(
        allowed
            .iter()
            .any(|entry| entry["id"].as_str() == Some("legacy-credential-id")),
        "legacy credential id must be allowed: {allowed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn generate_authenticate_options_with_session_includes_user_credentials(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
    let session_cookie = sign_in_cookie(&router).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            Some(&session_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["allowCredentials"][0]["id"], "credential-id");
    Ok(())
}

#[tokio::test]
async fn generate_authenticate_options_computes_challenge_expiration_per_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let before_request = time::OffsetDateTime::now_utc();

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let expires_at = single_verification_expires_at(adapter.as_ref()).await?;
    assert!(expires_at > before_request);
    assert!(expires_at <= time::OffsetDateTime::now_utc() + time::Duration::minutes(5));
    Ok(())
}

#[tokio::test]
async fn generate_authenticate_options_includes_user_verification_and_extensions(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = PasskeyOptions::default().authentication(
        PasskeyAuthenticationOptions::new()
            .extensions(json!({ "appid": "https://legacy.example.com" })),
    );
    let (_adapter, router, _backend) = seeded_router(options).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["userVerification"], "preferred");
    assert_eq!(body["extensions"]["appid"], "https://legacy.example.com");
    Ok(())
}

#[tokio::test]
async fn generate_authenticate_options_uses_async_extension_resolver(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = PasskeyOptions::default().authentication(
        PasskeyAuthenticationOptions::new().extensions_resolver(|_| {
            Box::pin(async { Some(json!({ "appid": "https://async.example.com" })) })
        }),
    );
    let (_adapter, router, _backend) = seeded_router(options).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["extensions"]["appid"], "https://async.example.com");
    Ok(())
}

#[test]
fn real_webauthn_backend_rejects_invalid_authentication_payload() {
    let backend = RealPasskeyWebAuthnBackend;
    let result = backend.finish_authentication(
        WebAuthnConfig {
            rp_id: "localhost".to_owned(),
            rp_name: "OpenAuth".to_owned(),
            origins: vec!["http://localhost:3000".to_owned()],
        },
        json!({}),
        json!({}),
        None,
    );

    assert!(result.is_err());
}

/// Authentication must advertise the same user-verification policy it later
/// enforces. The ceremony is now generated with `preferred`, matching the
/// advertised option for both the discoverable and credential flows (OPE-48).
#[test]
fn real_webauthn_backend_authentication_advertised_policy_matches_verified_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let backend = RealPasskeyWebAuthnBackend;
    let config = WebAuthnConfig {
        rp_id: "localhost".to_owned(),
        rp_name: "OpenAuth".to_owned(),
        origins: vec!["http://localhost:3000".to_owned()],
    };

    let discoverable = backend.start_authentication(config.clone(), Vec::new(), None)?;
    assert_eq!(
        discoverable.options["userVerification"].as_str(),
        Some("preferred")
    );
    assert_eq!(
        discoverable.state["Discoverable"]["policy"].as_str(),
        Some("preferred")
    );

    let credential = json!({
        "cred": {
            "cred_id": "AQID",
            "cred": { "type_": "ES256", "key": { "EC_EC2": {
                "curve": "SECP256R1",
                "x": vec![1u8; 32],
                "y": vec![2u8; 32]
            } } },
            "counter": 0,
            "transports": null,
            "user_verified": false,
            "backup_eligible": false,
            "backup_state": false,
            "registration_policy": "preferred",
            "extensions": { "cred_protect": "NotRequested", "hmac_create_secret": "NotRequested" },
            "attestation": { "data": "None", "metadata": "None" },
            "attestation_format": "none"
        }
    });
    let credential_flow = backend.start_authentication(config, vec![credential], None)?;
    assert_eq!(
        credential_flow.options["userVerification"].as_str(),
        Some("preferred")
    );
    assert_eq!(
        credential_flow.state["Passkey"]["policy"].as_str(),
        Some("preferred")
    );
    Ok(())
}

#[tokio::test]
async fn verify_authentication_creates_session_and_returns_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);

    let response = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&passkey_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["id"], "user_1");
    assert!(body["session"]["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.contains("session_token")));
    Ok(())
}

#[tokio::test]
async fn verify_authentication_rejects_missing_origin_when_origin_is_not_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&passkey_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "origin missing");
    Ok(())
}

#[tokio::test]
async fn verify_authentication_runs_async_after_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let callback_seen = Arc::clone(&seen);
    let options = PasskeyOptions::default().authentication(
        PasskeyAuthenticationOptions::new().after_verification_async(move |input| {
            let callback_seen = Arc::clone(&callback_seen);
            Box::pin(async move {
                if let Ok(mut seen) = callback_seen.lock() {
                    seen.push(input.credential_id);
                }
            })
        }),
    );
    let (adapter, router, _backend) = seeded_router(options).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);

    let response = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&passkey_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let seen = seen.lock().map_err(|_| "callback mutex poisoned")?;
    assert_eq!(seen.as_slice(), &["credential-id"]);
    Ok(())
}

#[tokio::test]
async fn verify_authentication_rejects_deleted_user_with_json_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
    adapter
        .delete(
            Delete::new("user")
                .where_clause(Where::new("id", DbValue::String("user_1".to_owned()))),
        )
        .await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);

    let response = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&passkey_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "User not found");
    Ok(())
}

#[tokio::test]
async fn verify_authentication_rejects_credential_outside_session_challenge(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    seed_user_two(adapter.as_ref()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_2",
        "user_2",
        "Other Laptop",
        "credential-user-2",
    )
    .await?;
    let session_cookie = sign_in_cookie(&router).await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            Some(&session_cookie),
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);
    let cookie = join_cookies(&[session_cookie.as_str(), passkey_cookie.as_str()]);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-user-2"}}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "AUTHENTICATION_FAILED");
    Ok(())
}

/// Unknown credential IDs and invalid proofs must not be distinguishable by
/// status code or error code (credential ID enumeration, OPE-32).
#[tokio::test]
async fn verify_authentication_unknown_and_invalid_proof_return_same_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, backend) = seeded_router(PasskeyOptions::default()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
    let unknown_options = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let unknown_cookie = cookie_header_from_response(&unknown_options);

    let unknown = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"unknown-credential-id"}}"#,
            Some(&unknown_cookie),
        )?)
        .await?;
    let unknown_body: Value = serde_json::from_slice(unknown.body())?;

    let invalid_proof_options = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let invalid_proof_cookie = cookie_header_from_response(&invalid_proof_options);

    backend
        .fail_finish_authentication
        .store(true, Ordering::Relaxed);
    let invalid_proof = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&invalid_proof_cookie),
        )?)
        .await?;
    let invalid_proof_body: Value = serde_json::from_slice(invalid_proof.body())?;

    assert_eq!(unknown.status(), invalid_proof.status());
    assert_eq!(unknown_body["code"], invalid_proof_body["code"]);
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    assert_eq!(unknown_body["code"], "AUTHENTICATION_FAILED");
    Ok(())
}

#[tokio::test]
async fn verify_authentication_rejects_missing_response_id_with_json_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{}}"#,
            Some(&passkey_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "AUTHENTICATION_FAILED");
    Ok(())
}

#[tokio::test]
async fn verify_authentication_rejects_invalid_signed_challenge_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let invalid_cookie = format!("{}=invalid.signature", passkey_challenge_cookie_name()?);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(invalid_cookie.as_str()),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "CHALLENGE_NOT_FOUND");
    Ok(())
}

#[tokio::test]
async fn verify_authentication_rejects_unknown_challenge_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let cookie = signed_passkey_challenge_cookie("missing-token")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "CHALLENGE_NOT_FOUND");
    Ok(())
}

#[tokio::test]
async fn verify_authentication_rejects_registration_challenge(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let session_cookie = sign_in_cookie(&router).await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options",
            Some(&session_cookie),
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);
    let cookie = join_cookies(&[session_cookie.as_str(), passkey_cookie.as_str()]);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "CHALLENGE_NOT_FOUND");
    Ok(())
}

#[tokio::test]
async fn verify_authentication_rejects_reused_challenge() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);

    let first = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&passkey_cookie),
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&passkey_cookie),
        )?)
        .await?;
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(second.body())?;
    assert_eq!(body["code"], "CHALLENGE_NOT_FOUND");
    Ok(())
}

/// Concurrent verify requests must not both mint sessions from one challenge
/// (OPE-29).
#[tokio::test]
async fn verify_authentication_rejects_concurrent_challenge_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);
    let first_request = json_request_with_origin(
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&passkey_cookie),
    )?;
    let second_request = json_request_with_origin(
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&passkey_cookie),
    )?;

    let (first, second) = tokio::join!(
        router.handle_async(first_request),
        router.handle_async(second_request),
    );

    let first = first?;
    let second = second?;
    let successes = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();
    assert_eq!(
        successes,
        1,
        "exactly one concurrent verify may succeed: {:?} {:?}",
        first.status(),
        second.status()
    );
    let failures = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::BAD_REQUEST)
        .count();
    assert_eq!(failures, 1);
    let failed_body: Value = if first.status() == StatusCode::BAD_REQUEST {
        serde_json::from_slice(first.body())?
    } else {
        serde_json::from_slice(second.body())?
    };
    assert_eq!(failed_body["code"], "CHALLENGE_NOT_FOUND");

    let sessions = adapter.find_many(FindMany::new("session")).await?;
    assert_eq!(
        sessions.len(),
        1,
        "concurrent replay must not create multiple sessions"
    );
    Ok(())
}

/// Passkey login must persist the client IP resolved by the configured
/// `advanced.ip_address` allow-list, not the raw `x-forwarded-for` an attacker
/// can prepend during `/passkey/verify-authentication` (OPE-79).
#[tokio::test]
async fn verify_authentication_session_ip_uses_resolver_not_spoofed_forwarded_for(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router_with_advanced(
        PasskeyOptions::default(),
        AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        }
        .ip_address(IpAddressOptions::new().header("x-real-ip")),
    )
    .await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);

    let mut request = json_request_with_origin(
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&passkey_cookie),
    )?;
    request
        .headers_mut()
        .insert("x-real-ip", HeaderValue::from_static("198.51.100.4"));
    request
        .headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.99"));

    let response = router.handle_async(request).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let sessions = adapter.find_many(FindMany::new("session")).await?;
    let session = sessions.first().ok_or("session not stored")?;
    assert_eq!(
        session.get("ip_address"),
        Some(&DbValue::String("198.51.100.4".to_owned())),
        "session IP must come from the configured resolver, not the spoofed x-forwarded-for"
    );
    Ok(())
}
