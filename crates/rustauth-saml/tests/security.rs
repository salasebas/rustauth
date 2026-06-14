#[cfg(feature = "saml-signed")]
use opensaml::{
    constants::{signature_algorithm::RSA_SHA256, Binding},
    crypto::encrypt_assertion,
    entity::{EntitySetting, User},
    idp::{IdentityProvider, LoginResponseOptions},
    metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig},
    ServiceProvider,
};
use rustauth_saml::{
    assertions::{count_assertions, parse_saml_response, validate_single_assertion},
    collect_saml_runtime_algorithms,
    metadata::service_provider_metadata,
    validate_saml_config_algorithms, validate_saml_config_algorithms_with_policy,
    validate_saml_runtime_algorithms, validate_saml_timestamp, validate_saml_timestamp_at,
    xml::validate_saml_xml,
    DeprecatedAlgorithmBehavior, DigestAlgorithm, SamlConditions, SamlConfig, SamlIdpMetadata,
    SamlRuntimeAlgorithmPolicy, SamlSecurityError, SignatureAlgorithm, TimestampValidationOptions,
};
#[cfg(feature = "saml-signed")]
use rustauth_saml::{
    encryption::decrypt_encrypted_assertion_response,
    signature::{verify_signed_saml_response, SamlSignatureInfo, SamlSignatureValidationError},
};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

fn encode_saml_xml(xml: &str) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, xml)
}

#[cfg(feature = "saml-signed")]
fn sp_private_key_pem() -> &'static str {
    include_str!("../../rustauth-sso/tests/fixtures/saml/key/sp_privkey.pem")
}

#[cfg(feature = "saml-signed")]
fn sp_signing_cert_pem() -> &'static str {
    include_str!("../../rustauth-sso/tests/fixtures/saml/key/sp_signing_cert.cer")
}

#[cfg(feature = "saml-signed")]
fn signed_login_response(in_response_to: &str) -> Result<String, Box<dyn std::error::Error>> {
    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com".to_owned(),
            signing_certs: vec![sp_signing_cert_pem().to_owned()],
            want_authn_requests_signed: false,
            single_sign_on_service: vec![Endpoint::new(
                Binding::Redirect,
                "https://idp.example.com/sso".to_owned(),
            )],
            ..Default::default()
        },
        EntitySetting {
            private_key: Some(sp_private_key_pem().to_owned()),
            signing_cert: Some(sp_signing_cert_pem().to_owned()),
            request_signature_algorithm: RSA_SHA256.to_owned(),
            ..Default::default()
        },
    )?;
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/entity".to_owned(),
            signing_certs: vec![sp_signing_cert_pem().to_owned()],
            authn_requests_signed: false,
            want_assertions_signed: true,
            assertion_consumer_service: vec![Endpoint::new(
                Binding::Post,
                "https://sp.example.com/acs".to_owned(),
            )],
            ..Default::default()
        },
        EntitySetting {
            entity_id: Some("https://sp.example.com/entity".to_owned()),
            private_key: Some(sp_private_key_pem().to_owned()),
            signing_cert: Some(sp_signing_cert_pem().to_owned()),
            request_signature_algorithm: RSA_SHA256.to_owned(),
            ..Default::default()
        },
    )?;
    let response = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("saml-user@example.com"),
        &LoginResponseOptions {
            in_response_to: Some(in_response_to),
            ..Default::default()
        },
    )?;
    Ok(response.context)
}

#[test]
fn assertion_count_uses_xml_local_names() -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
            <saml:Assertion ID="plain"></saml:Assertion>
            <custom:EncryptedAssertion xmlns:custom="urn:oasis:names:tc:SAML:2.0:assertion"></custom:EncryptedAssertion>
            <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" />
        </samlp:Response>
    "#;

    let counts = count_assertions(xml)?;

    assert_eq!(counts.assertions, 1);
    assert_eq!(counts.encrypted_assertions, 1);
    assert_eq!(counts.total, 2);
    Ok(())
}

#[test]
fn assertion_count_ignores_assertion_consumer_service_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <EntityDescriptor>
            <SPSSODescriptor>
                <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" />
            </SPSSODescriptor>
        </EntityDescriptor>
    "#;

    let counts = count_assertions(xml)?;

    assert_eq!(counts.assertions, 0);
    assert_eq!(counts.encrypted_assertions, 0);
    assert_eq!(counts.total, 0);
    Ok(())
}

#[test]
fn validate_single_assertion_accepts_namespaced_assertion() -> Result<(), Box<dyn std::error::Error>>
{
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:Assertion ID="assertion-1"></saml2:Assertion>
        </samlp:Response>
    "#;

    validate_single_assertion(&encode_saml_xml(xml))?;
    Ok(())
}

#[test]
fn validate_single_assertion_accepts_single_encrypted_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
            <saml:EncryptedAssertion>
                <xenc:EncryptedData>encrypted</xenc:EncryptedData>
            </saml:EncryptedAssertion>
        </samlp:Response>
    "#;

    validate_single_assertion(&encode_saml_xml(xml))?;
    Ok(())
}

#[test]
fn validate_single_assertion_rejects_nested_xsw_assertions(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <samlp:Extensions>
                <Wrapper>
                    <saml:Assertion ID="injected"></saml:Assertion>
                </Wrapper>
            </samlp:Extensions>
            <saml:Assertion ID="legitimate"></saml:Assertion>
        </samlp:Response>
    "#;

    let error = match validate_single_assertion(&encode_saml_xml(xml)) {
        Ok(_) => return Err("nested injected assertion should fail".into()),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("SAML response contains 2 assertions"));
    Ok(())
}

#[test]
fn validate_single_assertion_rejects_single_wrapped_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <samlp:Extensions>
                <Wrapper>
                    <saml:Assertion ID="wrapped"></saml:Assertion>
                </Wrapper>
            </samlp:Extensions>
        </samlp:Response>
    "#;

    let error = match validate_single_assertion(&encode_saml_xml(xml)) {
        Ok(_) => return Err("single wrapped assertion should fail".into()),
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("SAML assertion must be a direct Response child"));
    Ok(())
}

#[test]
fn validate_single_assertion_rejects_invalid_xml() -> Result<(), Box<dyn std::error::Error>> {
    let error = match validate_single_assertion(&encode_saml_xml("<Response><Assertion>")) {
        Ok(_) => return Err("invalid XML should fail".into()),
        Err(error) => error,
    };

    assert!(error.to_string().contains("Invalid SAML XML"));
    Ok(())
}

#[test]
fn encrypted_assertion_without_decryption_support_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
            <saml:EncryptedAssertion>
                <xenc:EncryptedData>encrypted</xenc:EncryptedData>
            </saml:EncryptedAssertion>
        </samlp:Response>
    "#;

    let error = match parse_saml_response(&encode_saml_xml(xml)) {
        Ok(_) => {
            return Err("encrypted assertion should fail until decryption is implemented".into())
        }
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("Encrypted SAML assertions are not supported"));
    Ok(())
}

#[cfg(feature = "saml-signed")]
#[test]
fn decrypt_encrypted_assertion_response_replaces_encrypted_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion ID="encrypted-fixture">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
            </saml:Assertion>
        </samlp:Response>
    "#;
    let encrypted = encrypt_assertion(
        xml,
        sp_signing_cert_pem(),
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
        "saml",
    )?;

    let decrypted = decrypt_encrypted_assertion_response(&encrypted, sp_private_key_pem())?;

    assert!(decrypted.contains(r#"<saml:Assertion ID="encrypted-fixture">"#));
    assert!(!decrypted.contains("EncryptedAssertion"));
    Ok(())
}

#[cfg(feature = "saml-signed")]
#[tokio::test]
async fn verify_signed_saml_response_accepts_matching_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = signed_login_response("request-1")?;
    let signature = SamlSignatureInfo {
        count: 1,
        response: true,
        assertion: false,
        logout_request: false,
        logout_response: false,
    };

    let verified = verify_signed_saml_response(&encoded, signature, sp_signing_cert_pem())
        .await
        .map_err(|error| format!("signature verification failed: {error:?}"))?;

    assert_eq!(
        verified.element,
        rustauth_saml::signature::SamlSignedElement::Response
    );
    Ok(())
}

#[cfg(feature = "saml-signed")]
#[tokio::test]
async fn verify_signed_saml_response_rejects_wrong_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = signed_login_response("request-1")?;
    let signature = SamlSignatureInfo {
        count: 1,
        response: true,
        assertion: false,
        logout_request: false,
        logout_response: false,
    };

    let error = match verify_signed_saml_response(&encoded, signature, "WRONG-CERT").await {
        Ok(_) => return Err("wrong certificate should fail".into()),
        Err(error) => error,
    };

    assert_eq!(error, SamlSignatureValidationError::Invalid);
    Ok(())
}

#[test]
fn parse_saml_response_extracts_audience_restrictions() -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion ID="assertion-1">
                <saml:Conditions>
                    <saml:AudienceRestriction>
                        <saml:Audience>https://sp.example.com/entity</saml:Audience>
                        <saml:Audience>https://sp.example.com/secondary</saml:Audience>
                    </saml:AudienceRestriction>
                </saml:Conditions>
            </saml:Assertion>
        </samlp:Response>
    "#;

    let parsed = parse_saml_response(&encode_saml_xml(xml))?;

    assert_eq!(
        parsed.assertion.audiences,
        vec![
            "https://sp.example.com/entity".to_owned(),
            "https://sp.example.com/secondary".to_owned()
        ]
    );
    Ok(())
}

#[test]
fn saml_config_defaults_want_assertions_signed_to_true() -> Result<(), Box<dyn std::error::Error>> {
    let config: SamlConfig = serde_json::from_value(serde_json::json!({
        "issuer": "https://sp.example.com/metadata",
        "entryPoint": "https://idp.example.com/sso",
        "cert": "CERTIFICATE",
        "callbackUrl": "https://sp.example.com/acs",
        "spMetadata": { "entityID": "https://sp.example.com/entity" },
        "authnRequestsSigned": false
    }))?;

    assert!(config.want_assertions_signed);
    Ok(())
}

#[test]
fn saml_config_uses_upstream_acronym_wire_names_and_accepts_legacy_aliases(
) -> Result<(), Box<dyn std::error::Error>> {
    let config = serde_json::json!({
        "issuer": "https://sp.example.com/metadata",
        "entryPoint": "https://idp.example.com/sso",
        "cert": "CERTIFICATE",
        "callbackUrl": "https://sp.example.com/acs",
        "spMetadata": {
            "entityID": "https://sp.example.com/entity"
        },
        "idpMetadata": {
            "entityID": "https://idp.example.com/entity",
            "entityURL": "https://idp.example.com/metadata",
            "redirectURL": "https://idp.example.com/redirect"
        },
        "wantAssertionsSigned": false,
        "authnRequestsSigned": false
    });
    let parsed: SamlConfig = serde_json::from_value(config)?;

    let serialized = serde_json::to_value(&parsed)?;

    assert_eq!(
        serialized["spMetadata"]["entityID"],
        "https://sp.example.com/entity"
    );
    assert_eq!(
        serialized["idpMetadata"]["entityID"],
        "https://idp.example.com/entity"
    );
    assert_eq!(
        serialized["idpMetadata"]["entityURL"],
        "https://idp.example.com/metadata"
    );
    assert_eq!(
        serialized["idpMetadata"]["redirectURL"],
        "https://idp.example.com/redirect"
    );

    let legacy: SamlConfig = serde_json::from_value(serde_json::json!({
        "issuer": "https://sp.example.com/metadata",
        "entryPoint": "https://idp.example.com/sso",
        "cert": "CERTIFICATE",
        "callbackUrl": "https://sp.example.com/acs",
        "spMetadata": {
            "entityId": "https://sp.example.com/legacy"
        },
        "idpMetadata": {
            "entityId": "https://idp.example.com/legacy",
            "entityUrl": "https://idp.example.com/legacy-metadata",
            "redirectUrl": "https://idp.example.com/legacy-redirect"
        },
        "wantAssertionsSigned": false,
        "authnRequestsSigned": false
    }))?;

    assert_eq!(
        legacy.sp_metadata.entity_id.as_deref(),
        Some("https://sp.example.com/legacy")
    );
    assert_eq!(
        legacy
            .idp_metadata
            .as_ref()
            .and_then(|metadata| metadata.entity_id.as_deref()),
        Some("https://idp.example.com/legacy")
    );
    assert_eq!(
        legacy
            .idp_metadata
            .as_ref()
            .and_then(|metadata| metadata.entity_url.as_deref()),
        Some("https://idp.example.com/legacy-metadata")
    );
    assert_eq!(
        legacy
            .idp_metadata
            .as_ref()
            .and_then(|metadata| metadata.redirect_url.as_deref()),
        Some("https://idp.example.com/legacy-redirect")
    );
    Ok(())
}

#[test]
fn service_provider_metadata_orders_slo_post_before_redirect(
) -> Result<(), Box<dyn std::error::Error>> {
    let config = SamlConfig {
        issuer: "https://sp.example.com/metadata".to_owned(),
        entry_point: "https://idp.example.com/sso".to_owned(),
        cert: "CERTIFICATE".to_owned(),
        callback_url: "https://sp.example.com/acs".to_owned(),
        acs_url: None,
        audience: None,
        idp_metadata: Some(SamlIdpMetadata::default()),
        sp_metadata: Default::default(),
        mapping: None,
        want_assertions_signed: false,
        authn_requests_signed: false,
        signature_algorithm: None,
        digest_algorithm: None,
        identifier_format: None,
        private_key: None,
        decryption_pvk: None,
        additional_params: None,
    };

    let metadata = service_provider_metadata("provider", "https://app.example.com", &config, true);
    let post_index = metadata
        .find(r#"SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""#)
        .ok_or("missing POST SLO binding")?;
    let redirect_index = metadata
        .find(r#"SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""#)
        .ok_or("missing Redirect SLO binding")?;

    assert!(post_index < redirect_index);
    Ok(())
}

#[test]
fn saml_xml_validator_accepts_namespaced_saml_xml() -> Result<(), Box<dyn std::error::Error>> {
    validate_saml_xml(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1"/></samlp:Response>"#,
    )?;

    Ok(())
}

#[test]
fn saml_xml_validator_rejects_mismatched_closing_elements() -> Result<(), Box<dyn std::error::Error>>
{
    let result = validate_saml_xml("<Response><Assertion></Response>");
    let error = match result {
        Ok(()) => return Err("mismatched XML should fail".into()),
        Err(error) => error,
    };

    assert!(error.to_string().contains("Invalid SAML XML"));
    Ok(())
}

#[test]
fn saml_xml_validator_rejects_doctype() -> Result<(), Box<dyn std::error::Error>> {
    let result = validate_saml_xml(
        r#"<!DOCTYPE Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Response/>"#,
    );
    let error = match result {
        Ok(()) => return Err("DOCTYPE should fail".into()),
        Err(error) => error,
    };

    assert!(error.to_string().contains("DOCTYPE"));
    Ok(())
}

#[test]
fn timestamp_validation_accepts_current_window() -> Result<(), Box<dyn std::error::Error>> {
    validate_saml_timestamp(
        Some(&SamlConditions {
            not_before: Some((OffsetDateTime::now_utc() - Duration::minutes(1)).format(&Rfc3339)?),
            not_on_or_after: Some(
                (OffsetDateTime::now_utc() + Duration::minutes(1)).format(&Rfc3339)?,
            ),
        }),
        TimestampValidationOptions::default(),
    )?;

    Ok(())
}

#[test]
fn timestamp_validation_rejects_expired_assertion() -> Result<(), Box<dyn std::error::Error>> {
    let result = validate_saml_timestamp(
        Some(&SamlConditions {
            not_before: None,
            not_on_or_after: Some(
                (OffsetDateTime::now_utc() - Duration::minutes(10)).format(&Rfc3339)?,
            ),
        }),
        TimestampValidationOptions {
            clock_skew: Duration::seconds(0),
            require_timestamps: false,
        },
    );

    assert!(matches!(result, Err(SamlSecurityError::Expired)));
    Ok(())
}

#[test]
fn timestamp_validation_can_require_conditions() {
    let result = validate_saml_timestamp(
        None,
        TimestampValidationOptions {
            clock_skew: Duration::minutes(5),
            require_timestamps: true,
        },
    );

    assert!(matches!(
        result,
        Err(SamlSecurityError::MissingTimestampConditions)
    ));
}

#[test]
fn timestamp_validation_accepts_not_before_at_now_with_zero_skew(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    let options = TimestampValidationOptions {
        clock_skew: Duration::ZERO,
        require_timestamps: false,
    };
    validate_saml_timestamp_at(
        Some(&SamlConditions {
            not_before: Some(now.format(&Rfc3339)?),
            not_on_or_after: None,
        }),
        options,
        now,
    )?;
    Ok(())
}

#[test]
fn timestamp_validation_rejects_not_before_one_millisecond_after_now_with_zero_skew(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    let not_before = (now + Duration::milliseconds(1)).format(&Rfc3339)?;
    let result = validate_saml_timestamp_at(
        Some(&SamlConditions {
            not_before: Some(not_before),
            not_on_or_after: None,
        }),
        TimestampValidationOptions {
            clock_skew: Duration::ZERO,
            require_timestamps: false,
        },
        now,
    );
    assert!(matches!(result, Err(SamlSecurityError::NotYetValid)));
    Ok(())
}

#[test]
fn timestamp_validation_accepts_not_on_or_after_at_now_with_zero_skew(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    validate_saml_timestamp_at(
        Some(&SamlConditions {
            not_before: None,
            not_on_or_after: Some(now.format(&Rfc3339)?),
        }),
        TimestampValidationOptions {
            clock_skew: Duration::ZERO,
            require_timestamps: false,
        },
        now,
    )?;
    Ok(())
}

#[test]
fn timestamp_validation_rejects_not_on_or_after_one_millisecond_before_now_with_zero_skew(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    let not_on_or_after = (now - Duration::milliseconds(1)).format(&Rfc3339)?;
    let result = validate_saml_timestamp_at(
        Some(&SamlConditions {
            not_before: None,
            not_on_or_after: Some(not_on_or_after),
        }),
        TimestampValidationOptions {
            clock_skew: Duration::ZERO,
            require_timestamps: false,
        },
        now,
    );
    assert!(matches!(result, Err(SamlSecurityError::Expired)));
    Ok(())
}

#[test]
fn saml_algorithm_constants_match_upstream_uris() {
    assert_eq!(
        SignatureAlgorithm::RsaSha256.as_uri(),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    );
    assert_eq!(
        DigestAlgorithm::Sha256.as_uri(),
        "http://www.w3.org/2001/04/xmlenc#sha256"
    );
}

#[test]
fn config_algorithm_validation_accepts_secure_uri_and_short_forms(
) -> Result<(), Box<dyn std::error::Error>> {
    validate_saml_config_algorithms(
        Some(SignatureAlgorithm::RsaSha256.as_uri()),
        Some(DigestAlgorithm::Sha256.as_uri()),
    )?;
    validate_saml_config_algorithms(Some("rsa-sha256"), Some("sha256"))?;
    validate_saml_config_algorithms(Some("sha256"), None)?;
    Ok(())
}

#[test]
fn config_algorithm_validation_rejects_unknown_algorithms() {
    let result = validate_saml_config_algorithms(Some("rsa-sha257"), None);
    assert!(matches!(
        result,
        Err(SamlSecurityError::UnknownSignatureAlgorithm(_))
    ));

    let result = validate_saml_config_algorithms(None, Some("sha257"));
    assert!(matches!(
        result,
        Err(SamlSecurityError::UnknownDigestAlgorithm(_))
    ));
}

#[test]
fn config_algorithm_validation_can_reject_deprecated_and_enforce_allow_lists() {
    let result = validate_saml_config_algorithms_with_policy(
        Some("rsa-sha1"),
        None,
        DeprecatedAlgorithmBehavior::Reject,
        None,
        None,
    );
    assert!(matches!(
        result,
        Err(SamlSecurityError::DeprecatedSignatureAlgorithm(_))
    ));

    let allowed = vec!["rsa-sha512".to_owned()];
    let result = validate_saml_config_algorithms_with_policy(
        Some("rsa-sha256"),
        None,
        DeprecatedAlgorithmBehavior::Warn,
        Some(&allowed),
        None,
    );
    assert!(matches!(
        result,
        Err(SamlSecurityError::SignatureAlgorithmNotAllowed(_))
    ));
}

#[test]
fn runtime_algorithm_validation_rejects_deprecated_signature_method(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                    <ds:Reference>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    </ds:Reference>
                </ds:SignedInfo>
            </ds:Signature>
            <saml:Assertion ID="a1"></saml:Assertion>
        </samlp:Response>
    "#;
    let parsed = parse_saml_response(&encode_saml_xml(xml))?;
    let result = validate_saml_runtime_algorithms(
        &parsed.algorithms,
        SamlRuntimeAlgorithmPolicy {
            on_deprecated: DeprecatedAlgorithmBehavior::Reject,
            ..SamlRuntimeAlgorithmPolicy::default()
        },
    );

    assert!(matches!(
        result,
        Err(SamlSecurityError::DeprecatedSignatureAlgorithm(_))
    ));
    Ok(())
}

#[test]
fn runtime_algorithm_validation_enforces_signature_allow_list(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:Signature>
                <ds:SignedInfo>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    </ds:Reference>
                </ds:SignedInfo>
            </ds:Signature>
            <saml:Assertion ID="a1"></saml:Assertion>
        </samlp:Response>
    "#;
    let parsed = parse_saml_response(&encode_saml_xml(xml))?;
    let allowed = vec![SignatureAlgorithm::RsaSha512.as_uri().to_owned()];
    let result = validate_saml_runtime_algorithms(
        &parsed.algorithms,
        SamlRuntimeAlgorithmPolicy {
            allowed_signature_algorithms: Some(&allowed),
            ..SamlRuntimeAlgorithmPolicy::default()
        },
    );

    assert!(matches!(
        result,
        Err(SamlSecurityError::SignatureAlgorithmNotAllowed(_))
    ));
    Ok(())
}

#[test]
fn runtime_algorithm_validation_rejects_deprecated_encryption_methods(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = r#"
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
            <saml:EncryptedAssertion>
                <xenc:EncryptedData>
                    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
                    <xenc:EncryptedKey>
                        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
                    </xenc:EncryptedKey>
                </xenc:EncryptedData>
            </saml:EncryptedAssertion>
        </samlp:Response>
    "#;
    let algorithms = collect_saml_runtime_algorithms(xml)?;
    let result = validate_saml_runtime_algorithms(
        &algorithms,
        SamlRuntimeAlgorithmPolicy {
            on_deprecated: DeprecatedAlgorithmBehavior::Reject,
            ..SamlRuntimeAlgorithmPolicy::default()
        },
    );

    assert!(matches!(
        result,
        Err(SamlSecurityError::DeprecatedDataEncryptionAlgorithm(_))
            | Err(SamlSecurityError::DeprecatedKeyEncryptionAlgorithm(_))
    ));
    Ok(())
}
