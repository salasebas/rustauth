use openauth_sso::{sso_error_category, sso_error_descriptors, SsoErrorCategory};

#[test]
fn sso_error_categories_distinguish_setup_runtime_and_attack_paths() {
    assert_eq!(
        sso_error_category("INVALID_SAML_CONFIG"),
        SsoErrorCategory::Configuration
    );
    assert_eq!(
        sso_error_category("OIDC_PROVIDER_NOT_CONFIGURED"),
        SsoErrorCategory::Configuration
    );
    assert_eq!(
        sso_error_category("SAML_RESPONSE_NOT_SUCCESS"),
        SsoErrorCategory::IdentityProviderRuntime
    );
    assert_eq!(
        sso_error_category("SAML_SIGNATURE_INVALID"),
        SsoErrorCategory::SuspectedAttack
    );
    assert_eq!(
        sso_error_category("REPLAYED_SAML_ASSERTION"),
        SsoErrorCategory::SuspectedAttack
    );
    assert_eq!(
        sso_error_category("SOME_UNKNOWN_CODE"),
        SsoErrorCategory::Unexpected
    );
}

#[test]
fn sso_error_descriptors_keep_stable_public_codes() -> Result<(), Box<dyn std::error::Error>> {
    let descriptors = sso_error_descriptors();
    let invalid_saml = descriptors
        .iter()
        .find(|descriptor| descriptor.code == "INVALID_SAML_CONFIG")
        .ok_or("missing INVALID_SAML_CONFIG descriptor")?;

    assert_eq!(invalid_saml.category, SsoErrorCategory::Configuration);
    assert!(descriptors
        .iter()
        .any(|descriptor| descriptor.code == "SAML_SIGNATURE_INVALID"));

    Ok(())
}
