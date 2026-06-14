use super::*;
use http::Request;
use opensaml::constants::Binding;

#[path = "../../fixtures/saml_crypto.rs"]
mod saml_crypto_helpers;

use saml_crypto_helpers::{
    encrypted_saml_login_response, google_shaped_user, inject_wrapped_assertion, okta_shaped_user,
    register_saml_crypto_provider_body, signed_idp_logout_request_redirect_url,
    signed_logout_request_post, signed_saml_login_response, test_sp, verify_signed_login_response,
    ACS_URL, IDP_SSO_URL,
};

#[tokio::test]
async fn saml_signed_authn_request_redirect_contains_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(true, true, true, false),
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(url.as_str().split('?').next(), Some(IDP_SSO_URL));
    let query: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
    assert!(query.contains_key("Signature"));
    assert!(query.contains_key("SigAlg"));
    Ok(())
}

#[tokio::test]
async fn saml_acs_accepts_signed_response_happy_path() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(false, true, false, false),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = signed_saml_login_response(&relay_state, &okta_shaped_user())?;
    verify_signed_login_response(&saml_response, &relay_state)?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;
    assert_eq!(
        response.status(),
        StatusCode::FOUND,
        "ACS body: {}",
        String::from_utf8_lossy(response.body())
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        !location.contains("login-error"),
        "unexpected ACS redirect: {location}"
    );
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("account_id") == Some(&DbValue::String("saml-user@example.com".to_owned()))
    }));
    Ok(())
}

#[tokio::test]
async fn saml_acs_accepts_encrypted_assertion_happy_path() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(false, false, false, true),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = encrypted_saml_login_response(&relay_state, &okta_shaped_user())?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        !location.contains("login-error"),
        "unexpected ACS redirect: {location}"
    );
    assert!(!adapter.records("account").await.is_empty());
    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_signed_response_with_wrong_idp_cert(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let mut body = serde_json::from_str::<serde_json::Value>(&register_saml_crypto_provider_body(
        false, true, false, false,
    ))?;
    body["samlConfig"]["cert"] = serde_json::Value::String("WRONG-CERTIFICATE".to_owned());
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &body.to_string(),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = signed_saml_login_response(&relay_state, &okta_shaped_user())?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=saml_signature_invalid"
        ))
    );
    assert!(adapter.records("account").await.is_empty());
    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_tampered_signed_response() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(false, true, false, false),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = tamper_base64_xml(
        &signed_saml_login_response(&relay_state, &okta_shaped_user())?,
        "saml-user@example.com",
        "attacker@evil.example.com",
    )?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=saml_signature_invalid"
        ))
    );
    assert!(adapter.records("account").await.is_empty());
    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_xsw_with_multiple_assertions() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(false, true, false, false),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = inject_wrapped_assertion(&signed_saml_login_response(
        &relay_state,
        &okta_shaped_user(),
    )?)?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=invalid_saml_response"
        ))
    );
    assert!(adapter.records("account").await.is_empty());
    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_expired_assertion() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(false, false, false, false),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = expired_saml_response(&relay_state, "assertion-expired")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static(
            "/login-error?error=saml_timestamp_invalid"
        ))
    );
    assert!(adapter.records("account").await.is_empty());
    Ok(())
}

#[tokio::test]
async fn saml_acs_maps_okta_shaped_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(false, true, false, false),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let response = post_saml_acs(
        &router,
        &signed_saml_login_response(&relay_state, &okta_shaped_user())?,
        &relay_state,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("saml-user@example.com".to_owned()))
            && record.get("name") == Some(&DbValue::String("Saml User".to_owned()))
    }));
    Ok(())
}

#[tokio::test]
async fn saml_acs_maps_azure_shaped_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let body = serde_json::json!({
        "providerId": "saml-okta",
        "issuer": "https://idp.example.com",
        "domain": "example.com",
        "samlConfig": {
            "issuer": "https://app.example.com/sso/saml2/sp/metadata",
            "entryPoint": IDP_SSO_URL,
            "cert": saml_crypto_helpers::idp_signing_cert_pem(),
            "callbackUrl": ACS_URL,
            "spMetadata": {"entityId": "https://app.example.com/saml/sp"},
            "wantAssertionsSigned": true,
            "authnRequestsSigned": false,
            "mapping": {
                "id": "http://schemas.microsoft.com/identity/claims/objectidentifier",
                "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
            }
        }
    });
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &body.to_string(),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let response = post_saml_acs(
        &router,
        &signed_saml_login_response(&relay_state, &saml_crypto_helpers::azure_shaped_user())?,
        &relay_state,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("account_id") == Some(&DbValue::String("azure-object-id".to_owned()))
    }));
    Ok(())
}

#[tokio::test]
async fn saml_acs_maps_google_shaped_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(false, true, false, false),
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let response = post_saml_acs(
        &router,
        &signed_saml_login_response(&relay_state, &google_shaped_user())?,
        &relay_state,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("account_id") == Some(&DbValue::String("saml-user@example.com".to_owned()))
    }));
    Ok(())
}

#[tokio::test]
async fn saml_slo_accepts_signed_logout_request_post() -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    options.saml.want_logout_request_signed = true;
    let (_adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&_adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(false, false, false, false),
            Some(&cookie),
        )?)
        .await?;
    let logout_request = signed_logout_request_post("signed-idp-logout", "saml-user@example.com")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/slo/saml-okta",
            &format!(
                r#"{{"SAMLRequest":{}}}"#,
                serde_json::to_string(&logout_request)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    Ok(())
}

#[tokio::test]
async fn saml_slo_accepts_signed_logout_request_redirect() -> Result<(), Box<dyn std::error::Error>>
{
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    options.saml.want_logout_request_signed = true;
    let (_adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&_adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_saml_crypto_provider_body(false, false, false, false),
            Some(&cookie),
        )?)
        .await?;
    let redirect_url =
        signed_idp_logout_request_redirect_url("signed-redirect-logout", "saml-user@example.com")?;

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri(redirect_url.as_str())
                .header(header::ACCEPT, "*/*")
                .body(Vec::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(redirect_url.contains("Signature="));
    assert!(redirect_url.contains("SigAlg="));
    Ok(())
}

#[tokio::test]
async fn saml_sp_logout_request_preserves_caller_request_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = test_sp(false, false)?;
    let idp = saml_crypto_helpers::test_idp()?;
    let ctx = opensaml::logout::create_logout_request_with_id(
        &sp.setting,
        &sp.metadata,
        &idp.metadata,
        Binding::Redirect,
        &opensaml::entity::User::new("user@example.com"),
        None,
        true,
        Some("caller-logout-id"),
    )?;
    assert_eq!(ctx.id, "caller-logout-id");
    Ok(())
}
