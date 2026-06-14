use super::*;
use http::Request;

#[path = "../../fixtures/saml_crypto.rs"]
mod saml_crypto_helpers;

use saml_crypto_helpers::idp_fixtures::{
    encrypted_login_response_for_fixture, register_idp_fixture_body,
    register_idp_fixture_body_with_options, signed_login_response_for_fixture, IdpFixtureKind,
    IdpFixtureRegistrationOptions,
};

async fn register_idp_fixture(
    router: &rustauth_core::api::AuthRouter,
    cookie: &str,
    kind: IdpFixtureKind,
) -> Result<(), Box<dyn std::error::Error>> {
    register_idp_fixture_with_options(
        router,
        cookie,
        kind,
        IdpFixtureRegistrationOptions::default(),
    )
    .await
}

async fn register_idp_fixture_with_options(
    router: &rustauth_core::api::AuthRouter,
    cookie: &str,
    kind: IdpFixtureKind,
    options: IdpFixtureRegistrationOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &register_idp_fixture_body_with_options(kind, options),
            Some(cookie),
        )?)
        .await?;
    Ok(())
}

async fn saml_sign_in_relay_state_for_provider(
    router: &rustauth_core::api::AuthRouter,
    provider_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            &format!(
                r#"{{"providerId":"{provider_id}","providerType":"saml","callbackURL":"/dashboard"}}"#
            ),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing sign-in URL")?)?;
    let relay_state = url
        .query_pairs()
        .find(|(key, _)| key == "RelayState")
        .map(|(_, value)| value.into_owned())
        .ok_or("missing RelayState")?;
    Ok(relay_state)
}

async fn post_saml_acs_for_provider(
    router: &rustauth_core::api::AuthRouter,
    provider_id: &str,
    saml_response: &str,
    relay_state: &str,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(router
        .handle_async(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "https://app.example.com/sso/saml2/sp/acs/{provider_id}"
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&serde_json::json!({
                    "SAMLResponse": saml_response,
                    "RelayState": relay_state,
                }))?)?,
        )
        .await?)
}

#[tokio::test]
async fn saml_acs_accepts_okta_production_shaped_signed_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let kind = IdpFixtureKind::Okta;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_idp_fixture(&router, &cookie, kind).await?;
    let relay_state = saml_sign_in_relay_state_for_provider(&router, kind.provider_id()).await?;
    let saml_response = signed_login_response_for_fixture(kind, &relay_state)?;

    let response =
        post_saml_acs_for_provider(&router, kind.provider_id(), &saml_response, &relay_state)
            .await?;
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
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("okta.user@example.com".to_owned()))
            && record.get("name") == Some(&DbValue::String("Okta User".to_owned()))
    }));
    Ok(())
}

#[tokio::test]
async fn saml_acs_accepts_azure_production_shaped_signed_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let kind = IdpFixtureKind::Azure;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_idp_fixture(&router, &cookie, kind).await?;
    let relay_state = saml_sign_in_relay_state_for_provider(&router, kind.provider_id()).await?;
    let saml_response = signed_login_response_for_fixture(kind, &relay_state)?;

    let response =
        post_saml_acs_for_provider(&router, kind.provider_id(), &saml_response, &relay_state)
            .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("account_id") == Some(&DbValue::String("azure-oid-prod-456".to_owned()))
    }));
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("ada@contoso.com".to_owned()))
    }));
    Ok(())
}

#[tokio::test]
async fn saml_acs_accepts_google_production_shaped_signed_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let kind = IdpFixtureKind::Google;
    let raw_attributes = std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_raw = std::sync::Arc::clone(&raw_attributes);
    let (adapter, router) =
        router_with_options(SsoOptions::default().provision_user(move |input| {
            let captured_raw = std::sync::Arc::clone(&captured_raw);
            async move {
                if let Ok(mut guard) = captured_raw.lock() {
                    *guard = input.profile.raw_attributes.clone();
                }
                Ok(())
            }
        }))?;
    let cookie = seed_session(&adapter).await?;
    register_idp_fixture(&router, &cookie, kind).await?;
    let relay_state = saml_sign_in_relay_state_for_provider(&router, kind.provider_id()).await?;
    let saml_response = signed_login_response_for_fixture(kind, &relay_state)?;

    let response =
        post_saml_acs_for_provider(&router, kind.provider_id(), &saml_response, &relay_state)
            .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("account_id") == Some(&DbValue::String("google.user@example.com".to_owned()))
    }));
    let raw = raw_attributes
        .lock()
        .map_err(|_| "raw attributes lock poisoned")?
        .clone()
        .ok_or("missing raw attributes")?;
    assert_eq!(raw["hostedDomain"], json!("example.com"));
    Ok(())
}

#[tokio::test]
async fn saml_acs_accepts_okta_production_shaped_encrypted_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let kind = IdpFixtureKind::Okta;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_idp_fixture_with_options(
        &router,
        &cookie,
        kind,
        IdpFixtureRegistrationOptions {
            decryption_key: true,
            ..Default::default()
        },
    )
    .await?;
    let relay_state = saml_sign_in_relay_state_for_provider(&router, kind.provider_id()).await?;
    let saml_response = encrypted_login_response_for_fixture(kind, &relay_state)?;

    let response =
        post_saml_acs_for_provider(&router, kind.provider_id(), &saml_response, &relay_state)
            .await?;
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
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("okta.user@example.com".to_owned()))
    }));
    Ok(())
}

#[tokio::test]
async fn saml_acs_accepts_azure_production_shaped_encrypted_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let kind = IdpFixtureKind::Azure;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_idp_fixture_with_options(
        &router,
        &cookie,
        kind,
        IdpFixtureRegistrationOptions {
            decryption_key: true,
            ..Default::default()
        },
    )
    .await?;
    let relay_state = saml_sign_in_relay_state_for_provider(&router, kind.provider_id()).await?;
    let saml_response = encrypted_login_response_for_fixture(kind, &relay_state)?;

    let response =
        post_saml_acs_for_provider(&router, kind.provider_id(), &saml_response, &relay_state)
            .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("account_id") == Some(&DbValue::String("azure-oid-prod-456".to_owned()))
    }));
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("ada@contoso.com".to_owned()))
    }));
    Ok(())
}

#[tokio::test]
async fn saml_azure_production_fixture_sign_in_with_signed_authn_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let kind = IdpFixtureKind::Azure;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_idp_fixture_with_options(
        &router,
        &cookie,
        kind,
        IdpFixtureRegistrationOptions {
            authn_signed: true,
            ..Default::default()
        },
    )
    .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            &format!(
                r#"{{"providerId":"{}","providerType":"saml","callbackURL":"/dashboard"}}"#,
                kind.provider_id()
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(url.as_str().split('?').next(), Some(kind.entry_point()));
    let query: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
    assert!(query.contains_key("Signature"));
    assert!(query.contains_key("SigAlg"));
    Ok(())
}

#[tokio::test]
async fn saml_okta_production_fixture_sign_in_uses_okta_entry_point(
) -> Result<(), Box<dyn std::error::Error>> {
    let kind = IdpFixtureKind::Okta;
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_idp_fixture(&router, &cookie, kind).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            &format!(
                r#"{{"providerId":"{}","providerType":"saml","callbackURL":"/dashboard"}}"#,
                kind.provider_id()
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    assert_eq!(url.as_str().split('?').next(), Some(kind.entry_point()));
    Ok(())
}
