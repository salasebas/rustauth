#[cfg(feature = "saml-signed")]
use openauth_sso::saml::assertions::parse_saml_response_with_decryption;
use openauth_sso::saml::{
    assertions::{count_assertions, parse_saml_response, validate_single_assertion},
    collect_saml_runtime_algorithms, validate_saml_config_algorithms,
    validate_saml_config_algorithms_with_policy, validate_saml_runtime_algorithms,
    validate_saml_timestamp,
    xml::validate_saml_xml,
    DeprecatedAlgorithmBehavior, DigestAlgorithm, SamlConditions, SamlRuntimeAlgorithmPolicy,
    SamlSecurityError, SignatureAlgorithm, TimestampValidationOptions,
};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

fn encode_saml_xml(xml: &str) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, xml)
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
fn encrypted_assertion_with_decryption_key_parses_as_plain_assertion(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = read_samael_fixture("response_encrypted_valid.xml")?;
    let key = read_samael_fixture("sp_private.pem")?;

    let parsed = parse_saml_response_with_decryption(&encode_saml_xml(&xml), Some(&key))?;

    assert_eq!(parsed.response_issuer.as_deref(), Some("saml-mock"));
    assert!(!parsed.assertion.id.is_empty());
    assert!(parsed.assertion.name_id.is_some() || !parsed.assertion.attributes.is_empty());
    Ok(())
}

#[cfg(feature = "saml-signed")]
#[test]
fn encrypted_assertion_with_invalid_decryption_key_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = read_samael_fixture("response_encrypted_valid.xml")?;
    let error =
        match parse_saml_response_with_decryption(&encode_saml_xml(&xml), Some("not a pem key")) {
            Ok(_) => return Err("invalid decryption key should fail".into()),
            Err(error) => error,
        };

    assert!(error.to_string().contains("SAML_DECRYPTION_KEY_INVALID"));
    Ok(())
}

#[cfg(feature = "saml-signed")]
fn read_samael_fixture(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
        format!("{home}/.cargo")
    });
    let path = std::path::Path::new(&cargo_home)
        .join("registry/src/index.crates.io-1949cf8c6b5b557f/samael-0.0.20/test_vectors")
        .join(name);
    Ok(std::fs::read_to_string(path)?)
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
