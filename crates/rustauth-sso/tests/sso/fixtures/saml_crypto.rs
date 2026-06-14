//! Shared opensaml-backed SAML crypto fixtures for integration tests.

#[path = "idp_fixtures.rs"]
pub mod idp_fixtures;

use base64::Engine;
use opensaml::constants::{signature_algorithm::RSA_SHA256, Binding};
use opensaml::crypto::encrypt_assertion;
use opensaml::entity::{EntitySetting, User};
use opensaml::flow::HttpRequest;
use opensaml::idp::{IdentityProvider, LoginResponseOptions};
use opensaml::logout::{create_logout_request_with_id, create_logout_response_with_id};
use opensaml::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use opensaml::template::{LoginResponseAttribute, LoginResponseTemplate};
use opensaml::ServiceProvider;

pub const SP_ENTITY_ID: &str = "https://app.example.com/saml/sp";
pub const IDP_ENTITY_ID: &str = "https://idp.example.com";
pub const ACS_URL: &str = "https://app.example.com/sso/saml2/sp/acs/saml-okta";
pub const SLO_URL: &str = "https://app.example.com/sso/saml2/sp/slo/saml-okta";
pub const IDP_SSO_URL: &str = "https://idp.example.com/saml/sso";

pub fn sp_private_key_pem() -> &'static str {
    include_str!("../../fixtures/saml/key/sp_privkey.pem")
}

pub fn sp_signing_cert_pem() -> &'static str {
    include_str!("../../fixtures/saml/key/sp_signing_cert.cer")
}

pub fn idp_signing_cert_pem() -> &'static str {
    include_str!("../../fixtures/saml/key/sp_signing_cert.cer")
}

fn signing_setting(private_key: &str, cert: &str) -> EntitySetting {
    EntitySetting {
        private_key: Some(private_key.to_owned()),
        signing_cert: Some(cert.to_owned()),
        request_signature_algorithm: RSA_SHA256.to_owned(),
        entity_id: None,
        ..Default::default()
    }
}

pub fn test_idp() -> Result<IdentityProvider, Box<dyn std::error::Error>> {
    idp_with_user(&User::new("saml-subject-123"))
}

pub(super) fn login_attributes_for_user(user: &User) -> Vec<LoginResponseAttribute> {
    const FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
    user.attributes
        .iter()
        .map(|(name, _)| LoginResponseAttribute {
            name: name.clone(),
            name_format: FORMAT.to_owned(),
            value_xsi_type: "xs:string".to_owned(),
            value_tag: name.clone(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        })
        .collect()
}

fn idp_with_user(user: &User) -> Result<IdentityProvider, Box<dyn std::error::Error>> {
    let mut setting = signing_setting(sp_private_key_pem(), idp_signing_cert_pem());
    setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: login_attributes_for_user(user),
    });
    Ok(IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: IDP_ENTITY_ID.to_owned(),
            signing_certs: vec![idp_signing_cert_pem().to_owned()],
            want_authn_requests_signed: false,
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, IDP_SSO_URL.to_owned())],
            single_logout_service: vec![Endpoint::new(Binding::Redirect, IDP_SSO_URL.to_owned())],
            ..Default::default()
        },
        setting,
    )?)
}

pub fn test_sp(
    authn_signed: bool,
    want_signed: bool,
) -> Result<ServiceProvider, Box<dyn std::error::Error>> {
    Ok(ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: SP_ENTITY_ID.to_owned(),
            signing_certs: vec![sp_signing_cert_pem().to_owned()],
            authn_requests_signed: authn_signed,
            want_assertions_signed: want_signed,
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, ACS_URL.to_owned())],
            single_logout_service: vec![
                Endpoint::new(Binding::Redirect, SLO_URL.to_owned()),
                Endpoint::new(Binding::Post, SLO_URL.to_owned()),
            ],
            ..Default::default()
        },
        EntitySetting {
            entity_id: Some(SP_ENTITY_ID.to_owned()),
            private_key: Some(sp_private_key_pem().to_owned()),
            signing_cert: Some(sp_signing_cert_pem().to_owned()),
            request_signature_algorithm: RSA_SHA256.to_owned(),
            authn_requests_signed: authn_signed,
            want_assertions_signed: want_signed,
            enc_private_key: Some(sp_private_key_pem().to_owned()),
            ..Default::default()
        },
    )?)
}

pub fn register_saml_crypto_provider_body(
    authn_signed: bool,
    want_signed: bool,
    private_key: bool,
    decryption_key: bool,
) -> String {
    let mut saml_config = serde_json::json!({
        "issuer": "https://app.example.com/sso/saml2/sp/metadata",
        "entryPoint": IDP_SSO_URL,
        "cert": idp_signing_cert_pem(),
        "callbackUrl": ACS_URL,
        "audience": SP_ENTITY_ID,
        "spMetadata": {"entityId": SP_ENTITY_ID},
        "idpMetadata": {"entityId": IDP_ENTITY_ID},
        "wantAssertionsSigned": want_signed,
        "authnRequestsSigned": authn_signed,
    });
    if private_key {
        saml_config["privateKey"] = serde_json::Value::String(sp_private_key_pem().to_owned());
    }
    if decryption_key {
        saml_config["decryptionPvk"] = serde_json::Value::String(sp_private_key_pem().to_owned());
    }
    saml_config["mapping"] = serde_json::json!({
        "firstName": "firstName",
        "lastName": "lastName"
    });
    serde_json::json!({
        "providerId": "saml-okta",
        "issuer": IDP_ENTITY_ID,
        "domain": "example.com",
        "samlConfig": saml_config,
    })
    .to_string()
}

pub fn default_test_user() -> User {
    User {
        name_id: "saml-subject-123".to_owned(),
        session_index: Some("session-index-1".to_owned()),
        attributes: vec![
            ("email".to_owned(), "saml-user@example.com".to_owned()),
            ("givenName".to_owned(), "Saml".to_owned()),
            ("surname".to_owned(), "User".to_owned()),
        ],
    }
}

pub fn okta_shaped_user() -> User {
    User {
        name_id: "saml-user@example.com".to_owned(),
        session_index: Some("session-index-1".to_owned()),
        attributes: vec![
            ("email".to_owned(), "saml-user@example.com".to_owned()),
            ("firstName".to_owned(), "Saml".to_owned()),
            ("lastName".to_owned(), "User".to_owned()),
        ],
    }
}

pub fn azure_shaped_user() -> User {
    User {
        name_id: "saml-user@example.com".to_owned(),
        session_index: Some("session-index-1".to_owned()),
        attributes: vec![
            (
                "http://schemas.microsoft.com/identity/claims/objectidentifier".to_owned(),
                "azure-object-id".to_owned(),
            ),
            (
                "http://schemas.microsoft.com/identity/claims/tenantid".to_owned(),
                "tenant-123".to_owned(),
            ),
            (
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".to_owned(),
                "saml-user@example.com".to_owned(),
            ),
        ],
    }
}

pub fn google_shaped_user() -> User {
    User {
        name_id: "saml-user@example.com".to_owned(),
        session_index: Some("session-index-1".to_owned()),
        attributes: vec![
            ("email".to_owned(), "saml-user@example.com".to_owned()),
            ("hd".to_owned(), "example.com".to_owned()),
        ],
    }
}

pub fn signed_saml_login_response(
    in_response_to: &str,
    user: &User,
) -> Result<String, Box<dyn std::error::Error>> {
    let idp = idp_with_user(user)?;
    let sp = test_sp(false, true)?;
    let response = idp.create_login_response(
        &sp,
        Binding::Post,
        user,
        &LoginResponseOptions {
            in_response_to: Some(in_response_to),
            ..Default::default()
        },
    )?;
    Ok(response.context)
}

pub fn encrypted_saml_login_response(
    in_response_to: &str,
    user: &User,
) -> Result<String, Box<dyn std::error::Error>> {
    let signed = signed_saml_login_response(in_response_to, user)?;
    let xml = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(signed)?)?;
    let encrypted = encrypt_assertion(
        &xml,
        sp_signing_cert_pem(),
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
        "saml",
    )?;
    Ok(base64::engine::general_purpose::STANDARD.encode(encrypted.as_bytes()))
}

pub fn signed_logout_request_post(
    request_id: &str,
    name_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let idp = test_idp()?;
    let sp = test_sp(false, false)?;
    let ctx = create_logout_request_with_id(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        &User {
            name_id: name_id.to_owned(),
            session_index: Some("session-index-1".to_owned()),
            attributes: Vec::new(),
        },
        None,
        true,
        Some(request_id),
    )?;
    Ok(ctx.context)
}

pub fn signed_logout_request_redirect_url(
    request_id: &str,
    name_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let idp = test_idp()?;
    let sp = test_sp(false, false)?;
    let ctx = create_logout_request_with_id(
        &sp.setting,
        &sp.metadata,
        &idp.metadata,
        Binding::Redirect,
        &User {
            name_id: name_id.to_owned(),
            session_index: Some("session-index-1".to_owned()),
            attributes: Vec::new(),
        },
        None,
        true,
        Some(request_id),
    )?;
    Ok(ctx.context)
}

/// IdP-initiated signed LogoutRequest targeting the SP SLO endpoint (Redirect binding).
pub fn signed_idp_logout_response_post(
    in_response_to: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let idp = test_idp()?;
    let sp = test_sp(false, false)?;
    let ctx = create_logout_response_with_id(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some(in_response_to),
        None,
        true,
        Some("signed-logout-response-1"),
    )?;
    Ok(ctx.context)
}

pub fn signed_idp_logout_request_redirect_url(
    request_id: &str,
    name_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let idp = test_idp()?;
    let sp = test_sp(false, false)?;
    let ctx = create_logout_request_with_id(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Redirect,
        &User {
            name_id: name_id.to_owned(),
            session_index: Some("session-index-1".to_owned()),
            attributes: Vec::new(),
        },
        None,
        true,
        Some(request_id),
    )?;
    Ok(ctx.context)
}

pub fn inject_wrapped_assertion(encoded: &str) -> Result<String, Box<dyn std::error::Error>> {
    let xml = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded)?)?;
    let injected = xml.replace(
        "<samlp:Status>",
        r#"<samlp:Extensions><Wrapper><saml:Assertion ID="xsw-injected" Version="2.0"><saml:Issuer>https://evil.example.com</saml:Issuer></saml:Assertion></Wrapper></samlp:Extensions><samlp:Status>"#,
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(injected.as_bytes()))
}

pub fn verify_signed_login_response(
    encoded: &str,
    request_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = test_idp()?;
    let sp = test_sp(false, true)?;
    let request = HttpRequest::post(vec![("SAMLResponse".to_owned(), encoded.to_owned())]);
    sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, request_id)?;
    Ok(())
}

#[cfg(test)]
mod debug_tests {
    use super::*;

    #[test]
    fn idp_redirect_logout_url_includes_sig_alg() {
        let url = signed_idp_logout_request_redirect_url("test-id", "user@example.com").unwrap();
        let parsed = url::Url::parse(&url).expect("redirect url");
        let keys: Vec<_> = parsed.query_pairs().map(|(k, _)| k.into_owned()).collect();
        assert!(
            keys.iter().any(|key| key == "SigAlg"),
            "keys: {keys:?} url: {url}"
        );
        assert!(keys.iter().any(|key| key == "Signature"));
    }

    #[test]
    fn signed_login_response_includes_okta_attributes() {
        use base64::Engine;
        let encoded = signed_saml_login_response("relay", &okta_shaped_user()).unwrap();
        let xml = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap(),
        )
        .unwrap();
        assert!(xml.contains("firstName"), "missing firstName in {xml}");
        assert!(xml.contains("lastName"), "missing lastName in {xml}");
    }

    #[test]
    fn idp_redirect_logout_signature_verifies() {
        use rustauth_saml::signature::verify_redirect_logout_request;
        let url = signed_idp_logout_request_redirect_url("test-id", "user@example.com").unwrap();
        let parsed = url::Url::parse(&url).expect("redirect url");
        let path_and_query = parsed
            .query()
            .map(|query| format!("{}?{query}", parsed.path()))
            .expect("query");
        verify_redirect_logout_request(&path_and_query, idp_signing_cert_pem())
            .expect("redirect logout signature");
    }
}
