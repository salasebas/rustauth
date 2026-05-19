use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn saml_acs_uses_idp_metadata_entity_id_for_issuer_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"saml-okta",
                "issuer":"https://fallback-issuer.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "idpMetadata":{
                        "entityID":"https://idp-entity.example.com",
                        "singleSignOnService":[{
                            "Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                            "Location":"https://idp.example.com/saml/sso"
                        }]
                    },
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let response = valid_saml_response(&relay_state, "assertion-idp-entity")?;
    let xml = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(response)?)?
        .replace("https://idp.example.com", "https://idp-entity.example.com");
    let response = base64::engine::general_purpose::STANDARD.encode(xml.as_bytes());

    let callback = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":{}}}"#,
                serde_json::to_string(&response)?,
                serde_json::to_string(&relay_state)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(callback.status(), StatusCode::FOUND);
    assert!(adapter.records("user").await.iter().any(|record| {
        record.get("email") == Some(&DbValue::String("saml-user@example.com".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn saml_acs_assigns_user_to_provider_organization() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router) = router_with_options_and_extra_plugins(
        SsoOptions::default(),
        vec![AuthPlugin::new("organization")],
    )?;
    let cookie = seed_session(&adapter).await?;
    seed_org_member(&adapter, "member_register", "org_1", "user_1", "admin").await?;
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"saml-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "organizationId":"org_1",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-org-assignment")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let members = adapter.records("member").await;
    assert!(members.iter().any(|record| {
        record.get("organization_id") == Some(&DbValue::String("org_1".to_owned()))
            && record.get("role") == Some(&DbValue::String("member".to_owned()))
            && record.get("user_id") != Some(&DbValue::String("user_1".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn saml_acs_calls_provision_user_for_new_user() -> Result<(), Box<dyn std::error::Error>> {
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let callback_calls = std::sync::Arc::clone(&calls);
    let (adapter, router) =
        router_with_options(SsoOptions::default().provision_user(move |input| {
            let callback_calls = std::sync::Arc::clone(&callback_calls);
            async move {
                assert_eq!(input.profile.provider_type, "saml");
                assert_eq!(input.profile.provider_id, "saml-okta");
                assert_eq!(input.profile.email, "saml-user@example.com");
                callback_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }))?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-provision-user")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    Ok(())
}

#[tokio::test]
async fn saml_acs_exposes_mapped_extra_fields_to_provision_user(
) -> Result<(), Box<dyn std::error::Error>> {
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
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"saml-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":"CERTIFICATE",
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false,
                    "mapping":{
                        "extraFields":{
                            "firstName":"givenName",
                            "lastName":"surname"
                        }
                    }
                }
            }"#,
            Some(&cookie),
        )?)
        .await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-extra-fields")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let raw = raw_attributes
        .lock()
        .map_err(|_| "raw attributes lock poisoned")?
        .clone()
        .ok_or("missing raw attributes")?;
    assert_eq!(raw["firstName"], json!("Saml"));
    assert_eq!(raw["lastName"], json!("User"));

    Ok(())
}

#[tokio::test]
async fn saml_acs_redirects_new_user_to_new_user_callback_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard","newUserCallbackURL":"/welcome"}"#,
            None,
        )?)
        .await?;
    let body = json_body(sign_in)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let relay_state = url
        .query_pairs()
        .find_map(|(key, value)| (key == "RelayState").then(|| value.into_owned()))
        .ok_or("missing RelayState")?;
    let saml_response = valid_saml_response(&relay_state, "assertion-new-user-callback")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/welcome"))
    );

    Ok(())
}

#[tokio::test]
async fn saml_acs_rejects_new_user_when_implicit_sign_up_is_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions {
        disable_implicit_sign_up: true,
        ..SsoOptions::default()
    })?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-disabled-signup")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "SAML_SIGN_IN_FAILED");

    Ok(())
}

#[tokio::test]
async fn saml_acs_allows_explicit_request_sign_up_when_implicit_sign_up_is_disabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions {
        disable_implicit_sign_up: true,
        ..SsoOptions::default()
    })?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard","errorCallbackURL":"/login-error","requestSignUp":true}"#,
            None,
        )?)
        .await?;
    let body = json_body(sign_in)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let relay_state = url
        .query_pairs()
        .find_map(|(key, value)| (key == "RelayState").then(|| value.into_owned()))
        .ok_or("missing RelayState")?;
    let saml_response = valid_saml_response(&relay_state, "assertion-request-signup")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );

    Ok(())
}

#[tokio::test]
async fn saml_acs_normalizes_mixed_case_email_to_single_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;

    for assertion_id in ["assertion-mixed-email-1", "assertion-mixed-email-2"] {
        let relay_state = saml_sign_in_relay_state(&router).await?;
        let saml_response = valid_saml_response(&relay_state, assertion_id)?;
        let saml_response = tamper_base64_xml(
            &saml_response,
            "saml-user@example.com",
            "SAML-User@Example.Com",
        )?;
        let response = post_saml_acs(&router, &saml_response, &relay_state).await?;
        assert_eq!(response.status(), StatusCode::FOUND, "{assertion_id}");
    }

    let users = adapter.records("user").await;
    let normalized_users = users
        .iter()
        .filter(|record| {
            record.get("email") == Some(&DbValue::String("saml-user@example.com".to_owned()))
        })
        .count();
    assert_eq!(normalized_users, 1);
    assert!(users.iter().all(|record| {
        record.get("email") != Some(&DbValue::String("SAML-User@Example.Com".to_owned()))
    }));

    Ok(())
}

#[tokio::test]
async fn saml_acs_uses_default_sso_saml_provider() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(default_saml_sso_options())?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"default-saml","providerType":"saml","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let body = json_body(sign_in)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    let relay_state = url
        .query_pairs()
        .find_map(|(key, value)| (key == "RelayState").then(|| value.into_owned()))
        .ok_or("missing RelayState")?;
    let saml_response = valid_saml_response(&relay_state, "assertion-default-saml")?;
    let saml_response = tamper_base64_xml(
        &saml_response,
        "/sso/saml2/sp/acs/saml-okta",
        "/sso/saml2/sp/acs/default-saml",
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/default-saml",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":{}}}"#,
                serde_json::to_string(&saml_response)?,
                serde_json::to_string(&relay_state)?
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION),
        Some(&http::HeaderValue::from_static("/dashboard"))
    );
    assert!(adapter.records("account").await.iter().any(|record| {
        record.get("provider_id") == Some(&DbValue::String("default-saml".to_owned()))
    }));

    Ok(())
}
