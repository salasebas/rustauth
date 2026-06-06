use http::{Method, StatusCode};
use openauth_core::options::{AdvancedOptions, EmailPasswordOptions, OpenAuthOptions};
use openauth_passkey::{PasskeyOptions, PasskeyRegistrationOptions, PasskeyRegistrationUser};
use serde_json::Value;

use crate::support::{get_request_with_origin, seeded_router_with_auth_options};

const ORIGIN_REQUIRED: &str =
    "passkey requires an explicit origin, a request Origin header, or a configured base_url";
const RP_ID_REQUIRED: &str =
    "passkey requires an explicit rp_id or a host derivable from base_url or origin";

fn test_auth_options(base_url: Option<&str>) -> OpenAuthOptions {
    OpenAuthOptions {
        base_url: base_url.map(str::to_owned),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        email_password: EmailPasswordOptions::new().enabled(true),
        development: true,
        ..OpenAuthOptions::default()
    }
}

fn preauth_passkey_options() -> PasskeyOptions {
    PasskeyOptions::default().registration(
        PasskeyRegistrationOptions::new()
            .require_session(false)
            .resolve_user(|input| {
                Some(PasskeyRegistrationUser::new(
                    "user-pre",
                    input
                        .context
                        .unwrap_or_else(|| "preauth@example.com".to_owned()),
                ))
            }),
    )
}

#[tokio::test]
async fn generate_register_options_rejects_missing_origin_and_base_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) =
        seeded_router_with_auth_options(test_auth_options(None), preauth_passkey_options()).await?;

    let response = router
        .handle_async(get_request_with_origin(
            Method::GET,
            "example.test",
            "/api/auth/passkey/generate-register-options?context=preauth@example.com",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["message"]
        .as_str()
        .is_some_and(|message| message.contains(ORIGIN_REQUIRED)));
    Ok(())
}

#[tokio::test]
async fn generate_register_options_rejects_missing_rp_id_derivation(
) -> Result<(), Box<dyn std::error::Error>> {
    let passkey = preauth_passkey_options().origin("not-a-valid-url");
    let (_adapter, router, _backend) =
        seeded_router_with_auth_options(test_auth_options(None), passkey).await?;

    let response = router
        .handle_async(get_request_with_origin(
            Method::GET,
            "example.test",
            "/api/auth/passkey/generate-register-options?context=preauth@example.com",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["message"]
        .as_str()
        .is_some_and(|message| message.contains(RP_ID_REQUIRED)));
    Ok(())
}

#[tokio::test]
async fn generate_authenticate_options_honors_explicit_origin_and_rp_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let passkey = PasskeyOptions::default()
        .origin("https://auth.example.com")
        .rp_id("example.com")
        .rp_name("Example");
    let (_adapter, router, _backend) =
        seeded_router_with_auth_options(test_auth_options(None), passkey).await?;

    let response = router
        .handle_async(get_request_with_origin(
            Method::GET,
            "example.test",
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["rpId"], "example.com");
    Ok(())
}

#[tokio::test]
async fn generate_authenticate_options_derives_origin_and_rp_id_from_base_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) = seeded_router_with_auth_options(
        test_auth_options(Some("http://localhost:3000")),
        PasskeyOptions::default(),
    )
    .await?;

    let response = router
        .handle_async(get_request_with_origin(
            Method::GET,
            "localhost:3000",
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["rpId"], "localhost");
    Ok(())
}

#[tokio::test]
async fn generate_authenticate_options_prefers_request_origin_header(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router, _backend) =
        seeded_router_with_auth_options(test_auth_options(None), PasskeyOptions::default()).await?;

    let response = router
        .handle_async(get_request_with_origin(
            Method::GET,
            "example.test",
            "/api/auth/passkey/generate-authenticate-options",
            Some("https://auth.example.com/"),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["rpId"], "auth.example.com");
    Ok(())
}
