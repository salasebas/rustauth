use super::*;

#[tokio::test]
async fn saml_acs_records_slo_session_lookup_when_single_logout_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.enable_single_logout = true;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    register_saml_provider_allowing_unsigned_assertions(&router, &cookie).await?;
    let relay_state = saml_sign_in_relay_state(&router).await?;
    let saml_response = valid_saml_response(&relay_state, "assertion-slo-session")?;

    let response = post_saml_acs(&router, &saml_response, &relay_state).await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    let verifications = adapter.records("verification").await;
    assert!(verifications.iter().any(|record| {
        record.get("identifier")
            == Some(&DbValue::String(
                "saml-session:saml-okta:saml-subject-123".to_owned(),
            ))
    }));
    assert!(verifications.iter().any(|record| {
        record
            .get("identifier")
            .is_some_and(|value| matches!(value, DbValue::String(identifier) if identifier.starts_with("saml-session-by-id:")))
    }));

    Ok(())
}
