use super::*;

#[tokio::test]
async fn register_saml_config_accepts_idp_metadata_single_sign_on_service(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let body = json!({
        "providerId": "metadata-saml",
        "issuer": "https://idp.example.com",
        "domain": "example.com",
        "samlConfig": {
            "issuer": "https://app.example.com/sso/saml2/sp/metadata",
            "cert": "CERTIFICATE",
            "callbackUrl": "https://app.example.com/sso/saml2/sp/acs/metadata-saml",
            "spMetadata": {},
            "wantAssertionsSigned": false,
            "authnRequestsSigned": false,
            "idpMetadata": {
                "singleSignOnService": [{
                    "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "Location": "https://idp.example.com/saml/from-service"
                }]
            }
        }
    });

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &serde_json::to_string(&body)?,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["providerType"], "saml");
    assert_eq!(body["type"], "saml");
    assert!(body.get("redirectURI").is_none());
    let records = adapter.records("sso_provider").await;
    let Some(DbValue::String(config)) = records[0].get("saml_config") else {
        return Err("missing stored SAML config".into());
    };
    assert!(config.contains(r#""entryPoint":"https://idp.example.com/saml/from-service""#));
    assert!(config.contains(r#""singleSignOnService""#));

    Ok(())
}

#[tokio::test]
async fn register_saml_config_extracts_entry_point_from_idp_metadata_xml(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = router_with_options(SsoOptions::default())?;
    let cookie = seed_session(&adapter).await?;
    let metadata = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><md:IDPSSODescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/from-metadata"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml/post"/></md:IDPSSODescriptor></md:EntityDescriptor>"#;
    let body = json!({
        "providerId": "metadata-saml",
        "issuer": "https://idp.example.com",
        "domain": "example.com",
        "samlConfig": {
            "issuer": "https://app.example.com/sso/saml2/sp/metadata",
            "cert": "CERTIFICATE",
            "callbackUrl": "https://app.example.com/sso/saml2/sp/acs/metadata-saml",
            "spMetadata": {},
            "wantAssertionsSigned": false,
            "authnRequestsSigned": false,
            "idpMetadata": {
                "metadata": metadata
            }
        }
    });

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &serde_json::to_string(&body)?,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let records = adapter.records("sso_provider").await;
    let Some(DbValue::String(config)) = records[0].get("saml_config") else {
        return Err("missing stored SAML config".into());
    };
    assert!(config.contains(r#""entryPoint":"https://idp.example.com/saml/from-metadata""#));
    assert!(config.contains(r#""metadata":"#));

    Ok(())
}

#[tokio::test]
async fn register_saml_config_rejects_oversized_idp_metadata_xml(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = SsoOptions::default();
    options.saml.max_metadata_size = 16;
    let (adapter, router) = router_with_options(options)?;
    let cookie = seed_session(&adapter).await?;
    let body = json!({
        "providerId": "metadata-saml",
        "issuer": "https://idp.example.com",
        "domain": "example.com",
        "samlConfig": {
            "issuer": "https://app.example.com/sso/saml2/sp/metadata",
            "cert": "CERTIFICATE",
            "callbackUrl": "https://app.example.com/sso/saml2/sp/acs/metadata-saml",
            "spMetadata": {},
            "wantAssertionsSigned": false,
            "authnRequestsSigned": false,
            "idpMetadata": {
                "metadata": "<EntityDescriptor><IDPSSODescriptor /></EntityDescriptor>"
            }
        }
    });

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &serde_json::to_string(&body)?,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)?["code"], "SAML_METADATA_TOO_LARGE");
    assert!(adapter.records("sso_provider").await.is_empty());

    Ok(())
}
