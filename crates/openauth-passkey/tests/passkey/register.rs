use std::sync::Arc;

use http::{header, Method, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbAdapter, DbValue, FindOne, MemoryAdapter, Where};
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_passkey::{
    passkey, AuthenticatorAttachment, AuthenticatorSelection, PasskeyOptions,
    PasskeyRegistrationOptions, PasskeyRegistrationUser, PasskeyWebAuthnBackend,
    RealPasskeyWebAuthnBackend, RegistrationWebAuthnOptions, ResidentKeyRequirement,
    UserVerificationRequirement, WebAuthnConfig,
};
use serde_json::{json, Value};

use crate::support::{
    cookie_header_from_response, empty_request, expired_registration_challenge_cookie,
    join_cookies, json_request, json_request_with_origin, router_with_adapter, seed_user,
    seeded_router, session_cookie_for_created_at, set_cookie_values, sign_in_cookie,
    single_verification_expires_at, RaceDuplicateAdapter,
};

#[tokio::test]
async fn generate_register_options_requires_session_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "SESSION_REQUIRED");
    Ok(())
}

#[tokio::test]
async fn generate_register_options_uses_resolve_user_without_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = PasskeyOptions::default().registration(
        PasskeyRegistrationOptions::new()
            .require_session(false)
            .resolve_user(|input| {
                Some(
                    PasskeyRegistrationUser::new(
                        format!("user-{}", input.context.as_deref().unwrap_or("missing")),
                        input
                            .context
                            .unwrap_or_else(|| "missing@example.com".to_owned()),
                    )
                    .display_name("Pre-auth User"),
                )
            }),
    );
    let (_adapter, router, backend) = seeded_router(options).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options?context=preauth@example.com",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["challenge"], "registration-challenge");
    assert_eq!(body["user"]["name"], "preauth@example.com");
    assert_eq!(body["user"]["displayName"], "Pre-auth User");
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.contains("better-auth-passkey")));
    let users = backend
        .registration_users
        .lock()
        .map_err(|_| "registration user mutex poisoned")?;
    assert_eq!(users.as_slice(), &["user-preauth@example.com"]);
    Ok(())
}

#[tokio::test]
async fn generate_register_options_computes_challenge_expiration_per_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let session_cookie = sign_in_cookie(&router).await?;
    let before_request = time::OffsetDateTime::now_utc();

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options",
            Some(&session_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let expires_at = single_verification_expires_at(adapter.as_ref()).await?;
    assert!(expires_at > before_request);
    assert!(expires_at <= time::OffsetDateTime::now_utc() + time::Duration::minutes(5));
    Ok(())
}

#[tokio::test]
async fn generate_register_options_requires_resolve_user_in_preauth_mode(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = PasskeyOptions::default()
        .registration(PasskeyRegistrationOptions::new().require_session(false));
    let (_adapter, router, _backend) = seeded_router(options).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "RESOLVE_USER_REQUIRED");
    Ok(())
}

#[tokio::test]
async fn generate_register_options_rejects_invalid_resolved_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = PasskeyOptions::default().registration(
        PasskeyRegistrationOptions::new()
            .require_session(false)
            .resolve_user(|_| None),
    );
    let (_adapter, router, _backend) = seeded_router(options).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "RESOLVED_USER_INVALID");
    Ok(())
}

#[tokio::test]
async fn generate_register_options_uses_query_name_for_webauthn_user_name(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = PasskeyOptions::default().registration(
        PasskeyRegistrationOptions::new()
            .require_session(false)
            .resolve_user(|_| {
                Some(PasskeyRegistrationUser::new(
                    "preauth-user",
                    "preauth@example.com",
                ))
            }),
    );
    let (_adapter, router, _backend) = seeded_router(options).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options?name=Work%20Laptop",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["name"], "Work Laptop");
    assert_eq!(body["user"]["displayName"], "preauth@example.com");
    Ok(())
}

#[tokio::test]
async fn generate_register_options_includes_selection_attachment_and_extensions(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = PasskeyOptions::default()
        .authenticator_selection(
            AuthenticatorSelection::new()
                .resident_key(ResidentKeyRequirement::Required)
                .user_verification(UserVerificationRequirement::Discouraged)
                .authenticator_attachment(AuthenticatorAttachment::CrossPlatform),
        )
        .registration(
            PasskeyRegistrationOptions::new()
                .require_session(false)
                .resolve_user(|_| {
                    Some(PasskeyRegistrationUser::new(
                        "preauth-user",
                        "preauth@example.com",
                    ))
                })
                .extensions(json!({ "credProps": true, "hmacCreateSecret": true })),
        );
    let (_adapter, router, _backend) = seeded_router(options).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options?authenticatorAttachment=platform",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(
        body["authenticatorSelection"]["authenticatorAttachment"],
        "platform"
    );
    assert_eq!(body["authenticatorSelection"]["residentKey"], "required");
    assert_eq!(
        body["authenticatorSelection"]["userVerification"],
        "discouraged"
    );
    assert_eq!(body["extensions"]["credProps"], true);
    assert_eq!(body["extensions"]["hmacCreateSecret"], true);
    Ok(())
}

#[tokio::test]
async fn generate_register_options_rejects_invalid_authenticator_attachment(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = PasskeyOptions::default().registration(
        PasskeyRegistrationOptions::new()
            .require_session(false)
            .resolve_user(|_| {
                Some(PasskeyRegistrationUser::new(
                    "preauth-user",
                    "preauth@example.com",
                ))
            }),
    );
    let (_adapter, router, _backend) = seeded_router(options).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options?authenticatorAttachment=roaming",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn generate_register_options_uses_async_resolvers() -> Result<(), Box<dyn std::error::Error>>
{
    let options = PasskeyOptions::default().registration(
        PasskeyRegistrationOptions::new()
            .require_session(false)
            .resolve_user_async(|input| {
                Box::pin(async move {
                    Some(PasskeyRegistrationUser::new(
                        input.context.unwrap_or_else(|| "async-user".to_owned()),
                        "async@example.com",
                    ))
                })
            })
            .extensions_resolver(|input| {
                Box::pin(async move {
                    Some(json!({
                        "credProps": true,
                        "context": input.context,
                    }))
                })
            }),
    );
    let (_adapter, router, _backend) = seeded_router(options).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options?context=ctx-1",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["id"], "ctx-1");
    assert_eq!(body["extensions"]["credProps"], true);
    assert_eq!(body["extensions"]["context"], "ctx-1");
    Ok(())
}

#[tokio::test]
async fn real_webauthn_backend_generates_registration_option_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![passkey(
                PasskeyOptions::default().registration(
                    PasskeyRegistrationOptions::new()
                        .require_session(false)
                        .resolve_user(|_| {
                            Some(PasskeyRegistrationUser::new(
                                "real-user",
                                "real@example.com",
                            ))
                        }),
                ),
            )],
            ..OpenAuthOptions::default()
        },
        adapter,
    )?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(Arc::new(MemoryAdapter::new())),
    )?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["challenge"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(body["rp"]["id"], "localhost");
    assert_eq!(body["user"]["name"], "real@example.com");
    assert_eq!(body["authenticatorSelection"]["residentKey"], "preferred");
    assert_eq!(
        body["authenticatorSelection"]["userVerification"],
        "preferred"
    );
    assert!(body["pubKeyCredParams"]
        .as_array()
        .is_some_and(|values| !values.is_empty()));
    Ok(())
}

#[test]
fn real_webauthn_backend_rejects_invalid_registration_payload() {
    let backend = RealPasskeyWebAuthnBackend;
    let result = backend.finish_registration(
        WebAuthnConfig {
            rp_id: "localhost".to_owned(),
            rp_name: "OpenAuth".to_owned(),
            origins: vec!["http://localhost:3000".to_owned()],
        },
        json!({}),
        json!({}),
    );

    assert!(result.is_err());
}

#[test]
fn real_webauthn_backend_uses_random_registration_user_handle(
) -> Result<(), Box<dyn std::error::Error>> {
    let backend = RealPasskeyWebAuthnBackend;
    let config = WebAuthnConfig {
        rp_id: "localhost".to_owned(),
        rp_name: "OpenAuth".to_owned(),
        origins: vec!["http://localhost:3000".to_owned()],
    };
    let user = PasskeyRegistrationUser::new("real-user", "real@example.com");
    let request_options = RegistrationWebAuthnOptions {
        authenticator_selection: AuthenticatorSelection::default(),
        extensions: None,
    };

    let first =
        backend.start_registration(config.clone(), &user, Vec::new(), request_options.clone())?;
    let second = backend.start_registration(config, &user, Vec::new(), request_options)?;

    assert_ne!(first.options["user"]["id"], second.options["user"]["id"]);
    Ok(())
}

#[test]
fn real_webauthn_backend_rejects_invalid_origin_config() {
    let backend = RealPasskeyWebAuthnBackend;
    let result = backend.start_registration(
        WebAuthnConfig {
            rp_id: "localhost".to_owned(),
            rp_name: "OpenAuth".to_owned(),
            origins: vec!["not a url".to_owned()],
        },
        &PasskeyRegistrationUser::new("real-user", "real@example.com"),
        Vec::new(),
        RegistrationWebAuthnOptions {
            authenticator_selection: AuthenticatorSelection::default(),
            extensions: None,
        },
    );

    assert!(result.is_err());
}

#[tokio::test]
async fn verify_registration_creates_passkey_and_deletes_challenge(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
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
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"credential-id"},"name":"Laptop"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["name"], "Laptop");
    assert_eq!(body["credentialID"], "credential-id");
    assert_eq!(adapter.len("verification").await, 0);
    Ok(())
}

#[tokio::test]
async fn verify_registration_rejects_missing_origin_when_origin_is_not_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
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
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"credential-id"},"name":"Laptop"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "FAILED_TO_VERIFY_REGISTRATION");
    assert_eq!(adapter.len("passkey").await, 0);
    Ok(())
}

#[tokio::test]
async fn verify_registration_requires_session_by_default() -> Result<(), Box<dyn std::error::Error>>
{
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

    let response = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"credential-id"},"name":"Laptop"}"#,
            Some(&passkey_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "SESSION_REQUIRED");
    Ok(())
}

#[tokio::test]
async fn verify_registration_rejects_reused_challenge() -> Result<(), Box<dyn std::error::Error>> {
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

    let first = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"credential-id"},"name":"Laptop"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"credential-id"},"name":"Laptop"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(second.body())?;
    assert_eq!(body["code"], "CHALLENGE_NOT_FOUND");
    Ok(())
}

#[tokio::test]
async fn verify_registration_rejects_authentication_challenge(
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
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"credential-id"},"name":"Laptop"}"#,
            Some(&passkey_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "CHALLENGE_NOT_FOUND");
    Ok(())
}

#[tokio::test]
async fn verify_registration_rejects_expired_challenge() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let session_cookie = sign_in_cookie(&router).await?;
    let expired_cookie = expired_registration_challenge_cookie(adapter.as_ref()).await?;
    let cookie = join_cookies(&[session_cookie.as_str(), expired_cookie.as_str()]);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"credential-id"},"name":"Laptop"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "CHALLENGE_NOT_FOUND");
    Ok(())
}

#[tokio::test]
async fn verify_registration_rejects_invalid_signed_challenge_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let session_cookie = sign_in_cookie(&router).await?;
    let invalid_cookie = "better-auth-passkey=invalid.signature";
    let cookie = join_cookies(&[session_cookie.as_str(), invalid_cookie]);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"credential-id"},"name":"Laptop"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "CHALLENGE_NOT_FOUND");
    Ok(())
}

#[tokio::test]
async fn verify_registration_rejects_duplicate_credential_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let session_cookie = sign_in_cookie(&router).await?;
    crate::support::seed_passkey(
        adapter.as_ref(),
        "passkey_existing",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
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
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"credential-id"},"name":"Duplicate"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "PREVIOUSLY_REGISTERED");
    assert_eq!(adapter.len("passkey").await, 1);
    Ok(())
}

#[tokio::test]
async fn verify_registration_maps_duplicate_insert_race_to_previous_registered(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RaceDuplicateAdapter::new("race-credential"));
    seed_user(adapter.inner()).await?;
    let (router, _backend) =
        router_with_adapter(adapter.clone(), PasskeyOptions::default()).await?;
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
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"race-credential"},"name":"Race"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "PREVIOUSLY_REGISTERED");
    assert_eq!(adapter.inner().len("passkey").await, 1);
    Ok(())
}

#[tokio::test]
async fn verify_registration_rejects_stale_session() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let fresh_cookie = sign_in_cookie(&router).await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options",
            Some(&fresh_cookie),
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);
    let stale_cookie = session_cookie_for_created_at(
        adapter.as_ref(),
        "user_1",
        "stale-verify-token",
        time::OffsetDateTime::now_utc() - time::Duration::days(2),
    )
    .await?;
    let cookie = join_cookies(&[stale_cookie.as_str(), passkey_cookie.as_str()]);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"credential-id"},"name":"Laptop"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "SESSION_NOT_FRESH");
    Ok(())
}

#[tokio::test]
async fn generate_register_options_accepts_fresh_session() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let fresh_cookie = session_cookie_for_created_at(
        adapter.as_ref(),
        "user_1",
        "fresh-token",
        time::OffsetDateTime::now_utc(),
    )
    .await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options",
            Some(&fresh_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn generate_register_options_rejects_stale_session() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let stale_cookie = session_cookie_for_created_at(
        adapter.as_ref(),
        "user_1",
        "stale-token",
        time::OffsetDateTime::now_utc() - time::Duration::days(2),
    )
    .await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options",
            Some(&stale_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "SESSION_NOT_FRESH");
    Ok(())
}

#[tokio::test]
async fn passkey_error_responses_use_core_camel_case_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body.get("original_message").is_none());
    assert!(body.get("originalMessage").is_none());
    Ok(())
}

#[tokio::test]
async fn after_registration_verification_can_override_preauth_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = PasskeyOptions::default().registration(
        PasskeyRegistrationOptions::new()
            .require_session(false)
            .resolve_user(|_| {
                Some(PasskeyRegistrationUser::new(
                    "preauth-user",
                    "preauth@example.com",
                ))
            })
            .after_verification(|_| Some("user_1".to_owned())),
    );
    let (adapter, router, _backend) = seeded_router(options).await?;
    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-register-options?context=link-token",
            None,
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);

    let response = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"override-credential"}}"#,
            Some(&passkey_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["userId"], "user_1");
    let record = adapter
        .find_one(FindOne::new("passkey").where_clause(Where::new(
            "credential_id",
            DbValue::String("override-credential".to_owned()),
        )))
        .await?
        .ok_or("missing passkey")?;
    assert_eq!(
        record.get("user_id"),
        Some(&DbValue::String("user_1".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn after_registration_verification_cannot_override_session_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = PasskeyOptions::default().registration(
        PasskeyRegistrationOptions::new().after_verification(|_| Some("user_2".to_owned())),
    );
    let (adapter, router, _backend) = seeded_router(options).await?;
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
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-registration",
            r#"{"response":{"id":"mismatch-credential"}}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(adapter.len("passkey").await, 0);
    Ok(())
}
