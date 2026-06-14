use rustauth_sso::{SsoOptions, DEFAULT_MAX_SAML_METADATA_SIZE, DEFAULT_MAX_SAML_RESPONSE_SIZE};

#[test]
fn default_max_saml_size_constants_match_saml_options_defaults() {
    let options = SsoOptions::default();
    assert_eq!(
        DEFAULT_MAX_SAML_RESPONSE_SIZE,
        options.saml.max_response_size
    );
    assert_eq!(
        DEFAULT_MAX_SAML_METADATA_SIZE,
        options.saml.max_metadata_size
    );
}
