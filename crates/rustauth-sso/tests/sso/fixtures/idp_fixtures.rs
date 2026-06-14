//! Production-shaped SAML IdP fixtures (Okta, Azure AD, Google Workspace).
//!
//! Responses are generated with real XMLDSig via `opensaml` and the vendorized PEM
//! keys under `tests/fixtures/saml/key/`. Provider registration JSON lives in
//! `tests/fixtures/saml/idp/*-shaped.json`.

use base64::Engine;
use opensaml::constants::{signature_algorithm::RSA_SHA256, Binding};
use opensaml::crypto::encrypt_assertion;
use opensaml::entity::{EntitySetting, User};
use opensaml::idp::{IdentityProvider, LoginResponseOptions};
use opensaml::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use opensaml::template::{LoginResponseAttribute, LoginResponseTemplate};
use opensaml::ServiceProvider;
use serde_json::{json, Value};

use super::{
    idp_signing_cert_pem, login_attributes_for_user, sp_private_key_pem, sp_signing_cert_pem,
    SP_ENTITY_ID,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdpFixtureRegistrationOptions {
    pub decryption_key: bool,
    pub authn_signed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdpFixtureKind {
    Okta,
    Azure,
    Google,
}

impl IdpFixtureKind {
    pub fn provider_id(self) -> &'static str {
        match self {
            Self::Okta => "saml-okta-prod",
            Self::Azure => "saml-azure-prod",
            Self::Google => "saml-google-prod",
        }
    }

    pub fn acs_url(self) -> String {
        format!(
            "https://app.example.com/sso/saml2/sp/acs/{}",
            self.provider_id()
        )
    }

    fn registration_template(self) -> &'static str {
        match self {
            Self::Okta => include_str!("../../fixtures/saml/idp/okta-shaped.json"),
            Self::Azure => include_str!("../../fixtures/saml/idp/azure-shaped.json"),
            Self::Google => include_str!("../../fixtures/saml/idp/google-shaped.json"),
        }
    }

    pub fn idp_entity_id(self) -> &'static str {
        match self {
            Self::Okta => "http://www.okta.com/exkabc123",
            Self::Azure => "https://sts.windows.net/11111111-1111-1111-1111-111111111111/",
            Self::Google => "https://accounts.google.com/o/saml2?idpid=C01234567",
        }
    }

    pub fn entry_point(self) -> &'static str {
        match self {
            Self::Okta => "https://dev-123456.okta.com/app/myapp/exkabc123/sso/saml",
            Self::Azure => {
                "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/saml2"
            }
            Self::Google => "https://accounts.google.com/o/saml2/idp?idpid=C01234567",
        }
    }

    pub fn test_user(self) -> User {
        match self {
            Self::Okta => User {
                name_id: "okta.user@example.com".to_owned(),
                session_index: Some("okta-session-1".to_owned()),
                attributes: vec![
                    ("email".to_owned(), "okta.user@example.com".to_owned()),
                    ("firstName".to_owned(), "Okta".to_owned()),
                    ("lastName".to_owned(), "User".to_owned()),
                ],
            },
            Self::Azure => User {
                name_id: "ada@contoso.com".to_owned(),
                session_index: Some("azure-session-1".to_owned()),
                attributes: vec![
                    (
                        "http://schemas.microsoft.com/identity/claims/objectidentifier".to_owned(),
                        "azure-oid-prod-456".to_owned(),
                    ),
                    (
                        "http://schemas.microsoft.com/identity/claims/tenantid".to_owned(),
                        "11111111-1111-1111-1111-111111111111".to_owned(),
                    ),
                    (
                        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
                            .to_owned(),
                        "ada@contoso.com".to_owned(),
                    ),
                    (
                        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".to_owned(),
                        "Ada Azure".to_owned(),
                    ),
                ],
            },
            Self::Google => User {
                name_id: "google.user@example.com".to_owned(),
                session_index: Some("google-session-1".to_owned()),
                attributes: vec![
                    ("email".to_owned(), "google.user@example.com".to_owned()),
                    ("hd".to_owned(), "example.com".to_owned()),
                ],
            },
        }
    }
}

pub fn register_idp_fixture_body(kind: IdpFixtureKind) -> String {
    register_idp_fixture_body_with_options(kind, IdpFixtureRegistrationOptions::default())
}

pub fn register_idp_fixture_body_with_options(
    kind: IdpFixtureKind,
    options: IdpFixtureRegistrationOptions,
) -> String {
    let mut body: Value = serde_json::from_str(kind.registration_template()).expect("fixture json");
    body["samlConfig"]["cert"] = json!(idp_signing_cert_pem());
    body["samlConfig"]["callbackUrl"] = json!(kind.acs_url());
    if options.decryption_key {
        body["samlConfig"]["decryptionPvk"] = json!(sp_private_key_pem());
    }
    if options.authn_signed {
        body["samlConfig"]["authnRequestsSigned"] = json!(true);
        body["samlConfig"]["privateKey"] = json!(sp_private_key_pem());
    }
    body.to_string()
}

fn signing_setting(private_key: &str, cert: &str, entity_id: &str) -> EntitySetting {
    EntitySetting {
        entity_id: Some(entity_id.to_owned()),
        private_key: Some(private_key.to_owned()),
        signing_cert: Some(cert.to_owned()),
        request_signature_algorithm: RSA_SHA256.to_owned(),
        ..Default::default()
    }
}

pub fn idp_for_fixture(
    kind: IdpFixtureKind,
    user: &User,
) -> Result<IdentityProvider, Box<dyn std::error::Error>> {
    let mut setting = signing_setting(
        sp_private_key_pem(),
        idp_signing_cert_pem(),
        kind.idp_entity_id(),
    );
    setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: login_attributes_for_user(user),
    });
    Ok(IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: kind.idp_entity_id().to_owned(),
            signing_certs: vec![idp_signing_cert_pem().to_owned()],
            want_authn_requests_signed: false,
            single_sign_on_service: vec![Endpoint::new(
                Binding::Redirect,
                kind.entry_point().to_owned(),
            )],
            single_logout_service: vec![Endpoint::new(
                Binding::Redirect,
                kind.entry_point().to_owned(),
            )],
            ..Default::default()
        },
        setting,
    )?)
}

pub fn sp_for_fixture(kind: IdpFixtureKind) -> Result<ServiceProvider, Box<dyn std::error::Error>> {
    Ok(ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: SP_ENTITY_ID.to_owned(),
            signing_certs: vec![sp_signing_cert_pem().to_owned()],
            authn_requests_signed: false,
            want_assertions_signed: true,
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, kind.acs_url())],
            ..Default::default()
        },
        EntitySetting {
            entity_id: Some(SP_ENTITY_ID.to_owned()),
            private_key: Some(sp_private_key_pem().to_owned()),
            signing_cert: Some(sp_signing_cert_pem().to_owned()),
            request_signature_algorithm: RSA_SHA256.to_owned(),
            want_assertions_signed: true,
            ..Default::default()
        },
    )?)
}

pub fn signed_login_response_for_fixture(
    kind: IdpFixtureKind,
    in_response_to: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let user = kind.test_user();
    let idp = idp_for_fixture(kind, &user)?;
    let sp = sp_for_fixture(kind)?;
    let response = idp.create_login_response(
        &sp,
        Binding::Post,
        &user,
        &LoginResponseOptions {
            in_response_to: Some(in_response_to),
            ..Default::default()
        },
    )?;
    Ok(response.context)
}

pub fn encrypted_login_response_for_fixture(
    kind: IdpFixtureKind,
    in_response_to: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let signed = signed_login_response_for_fixture(kind, in_response_to)?;
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
