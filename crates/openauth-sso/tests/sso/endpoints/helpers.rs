use super::*;

#[path = "helpers/oidc_server.rs"]
mod oidc_server;
#[cfg(feature = "saml-signed")]
#[path = "helpers/saml_signed.rs"]
mod saml_signed;

pub(super) use oidc_server::*;
#[cfg(feature = "saml-signed")]
pub(super) use saml_signed::*;

pub(super) async fn register_oidc_provider(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            r#"{
                "providerId":"okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"https://idp.example.com/oauth2/v1/authorize",
                    "tokenEndpoint":"https://idp.example.com/oauth2/v1/token",
                    "jwksEndpoint":"https://idp.example.com/oauth2/v1/keys",
                    "skipDiscovery":true,
                    "pkce":true
                }
            }"#,
            Some(cookie),
        )?)
        .await?;
    Ok(())
}

pub(super) async fn register_saml_provider(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
                    "wantAssertionsSigned":true,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(cookie),
        )?)
        .await?;
    Ok(())
}

pub(super) async fn register_saml_provider_allowing_unsigned_assertions(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
                    "authnRequestsSigned":false
                }
            }"#,
            Some(cookie),
        )?)
        .await?;
    Ok(())
}

pub(super) async fn register_saml_provider_with_post_single_logout_service(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
                    "idpMetadata":{
                        "singleLogoutService":[{
                            "Binding":"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                            "Location":"https://idp.example.com/saml/slo-post?tenant=acme&mode=logout"
                        }]
                    },
                    "spMetadata":{"entityId":"https://app.example.com/saml/sp"},
                    "wantAssertionsSigned":false,
                    "authnRequestsSigned":false
                }
            }"#,
            Some(cookie),
        )?)
        .await?;
    Ok(())
}

pub(super) async fn seed_saml_provider_record(
    adapter: &MemoryAdapter,
) -> Result<(), Box<dyn std::error::Error>> {
    SsoProviderStore::new(adapter)
        .create(CreateSsoProviderInput {
            provider_id: "saml-okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            user_id: "user_1".to_owned(),
            organization_id: None,
            oidc_config: None,
            saml_config: Some(serde_json::to_string(&SamlConfig {
                issuer: "https://app.example.com/sso/saml2/sp/metadata".to_owned(),
                entry_point: "https://idp.example.com/saml/sso".to_owned(),
                cert: "CERTIFICATE".to_owned(),
                callback_url: "https://app.example.com/sso/saml2/sp/acs/saml-okta".to_owned(),
                acs_url: None,
                audience: None,
                idp_metadata: None,
                sp_metadata: SamlSpMetadata {
                    entity_id: Some("https://app.example.com/saml/sp".to_owned()),
                    ..SamlSpMetadata::default()
                },
                mapping: None,
                want_assertions_signed: false,
                authn_requests_signed: false,
                signature_algorithm: None,
                digest_algorithm: None,
                identifier_format: None,
                private_key: None,
                decryption_pvk: None,
                additional_params: None,
            })?),
            domain_verified: Some(true),
        })
        .await?;
    Ok(())
}

#[cfg(feature = "saml-signed")]
pub(super) async fn register_saml_provider_with_cert(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
    cert: &str,
    want_assertions_signed: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                "providerId":"saml-okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "samlConfig":{{
                    "issuer":"https://app.example.com/sso/saml2/sp/metadata",
                    "entryPoint":"https://idp.example.com/saml/sso",
                    "cert":{},
                    "callbackUrl":"https://app.example.com/sso/saml2/sp/acs/saml-okta",
                    "spMetadata":{{"entityId":"https://app.example.com/saml/sp"}},
                    "wantAssertionsSigned":{},
                    "authnRequestsSigned":false
                }}
            }}"#,
                serde_json::to_string(cert)?,
                want_assertions_signed
            ),
            Some(cookie),
        )?)
        .await?;
    Ok(())
}

pub(super) async fn register_oidc_provider_with_endpoints(
    router: &openauth_core::api::AuthRouter,
    cookie: &str,
    base_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    router
        .handle_async(json_request(
            Method::POST,
            "/sso/register",
            &format!(
                r#"{{
                "providerId":"okta",
                "issuer":"https://idp.example.com",
                "domain":"example.com",
                "oidcConfig":{{
                    "clientId":"client_123456",
                    "clientSecret":"super-secret",
                    "authorizationEndpoint":"{base_url}/authorize",
                    "tokenEndpoint":"{base_url}/token",
                    "userInfoEndpoint":"{base_url}/userinfo",
                    "jwksEndpoint":"{base_url}/keys",
                    "skipDiscovery":true,
                    "pkce":true
                }}
            }}"#
            ),
            Some(cookie),
        )?)
        .await?;
    Ok(())
}

pub(super) fn authorization_state(
    response: http::Response<Vec<u8>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let body = json_body(response)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    url.query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .ok_or_else(|| "missing state".into())
}

pub(super) async fn seed_existing_sso_user(
    adapter: &MemoryAdapter,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("existing_sso_user".to_owned()))
                .data("name", DbValue::String("Existing SSO User".to_owned()))
                .data("email", DbValue::String("sso-user@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(true))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub(super) async fn seed_org_member(
    adapter: &MemoryAdapter,
    id: &str,
    organization_id: &str,
    user_id: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String(id.to_owned()))
                .data(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("role", DbValue::String(role.to_owned()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub(super) async fn seed_organization(
    adapter: &MemoryAdapter,
    id: &str,
    slug: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String(id.to_owned()))
                .data("name", DbValue::String(slug.to_owned()))
                .data("slug", DbValue::String(slug.to_owned()))
                .data("logo", DbValue::Null)
                .data("metadata", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

pub(super) fn default_oidc_sso_options(base_url: &str) -> SsoOptions {
    SsoOptions {
        default_sso: vec![SsoProvider {
            provider_id: "default-okta".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            organization_id: None,
            oidc_config: Some(OidcConfig {
                issuer: "https://idp.example.com".to_owned(),
                pkce: true,
                client_id: "client_123456".to_owned(),
                client_secret: "super-secret".into(),
                discovery_endpoint: format!("{base_url}/.well-known/openid-configuration"),
                authorization_endpoint: Some(format!("{base_url}/authorize")),
                token_endpoint: Some(format!("{base_url}/token")),
                user_info_endpoint: Some(format!("{base_url}/userinfo")),
                jwks_endpoint: Some(format!("{base_url}/keys")),
                token_endpoint_authentication: Some(TokenEndpointAuthentication::ClientSecretBasic),
                scopes: None,
                mapping: None,
                override_user_info: false,
            }),
            saml_config: None,
        }],
        ..SsoOptions::default()
    }
}

pub(super) fn default_oidc_sso_options_requiring_discovery(base_url: &str) -> SsoOptions {
    SsoOptions {
        default_sso: vec![SsoProvider {
            provider_id: "default-okta".to_owned(),
            issuer: base_url.to_owned(),
            domain: "example.com".to_owned(),
            organization_id: None,
            oidc_config: Some(OidcConfig {
                issuer: base_url.to_owned(),
                pkce: true,
                client_id: "client_123456".to_owned(),
                client_secret: "super-secret".into(),
                discovery_endpoint: format!("{base_url}/.well-known/openid-configuration"),
                authorization_endpoint: None,
                token_endpoint: None,
                user_info_endpoint: None,
                jwks_endpoint: None,
                token_endpoint_authentication: None,
                scopes: None,
                mapping: None,
                override_user_info: false,
            }),
            saml_config: None,
        }],
        ..SsoOptions::default()
    }
}

pub(super) fn default_saml_sso_options() -> SsoOptions {
    SsoOptions {
        default_sso: vec![SsoProvider {
            provider_id: "default-saml".to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            domain: "example.com".to_owned(),
            organization_id: None,
            oidc_config: None,
            saml_config: Some(SamlConfig {
                issuer: "https://app.example.com/sso/saml2/sp/metadata".to_owned(),
                entry_point: "https://idp.example.com/saml/sso".to_owned(),
                cert: "CERTIFICATE".to_owned(),
                callback_url: "https://app.example.com/sso/saml2/sp/acs/default-saml".to_owned(),
                acs_url: None,
                audience: None,
                idp_metadata: None,
                sp_metadata: SamlSpMetadata {
                    entity_id: Some("https://app.example.com/saml/sp".to_owned()),
                    ..SamlSpMetadata::default()
                },
                mapping: None,
                want_assertions_signed: false,
                authn_requests_signed: false,
                signature_algorithm: None,
                digest_algorithm: None,
                identifier_format: None,
                private_key: None,
                decryption_pvk: None,
                additional_params: None,
            }),
        }],
        ..SsoOptions::default()
    }
}

pub(super) async fn seed_runtime_discovery_oidc_provider(
    adapter: &MemoryAdapter,
    base_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = OidcConfig {
        issuer: base_url.to_owned(),
        pkce: true,
        client_id: "client_123456".to_owned(),
        client_secret: "super-secret".into(),
        discovery_endpoint: format!("{base_url}/.well-known/openid-configuration"),
        authorization_endpoint: None,
        token_endpoint: None,
        user_info_endpoint: None,
        jwks_endpoint: None,
        token_endpoint_authentication: None,
        scopes: None,
        mapping: None,
        override_user_info: false,
    };
    SsoProviderStore::new(adapter)
        .create(CreateSsoProviderInput {
            provider_id: "runtime-okta".to_owned(),
            issuer: base_url.to_owned(),
            domain: "example.com".to_owned(),
            user_id: "default".to_owned(),
            organization_id: None,
            oidc_config: Some(serde_json::to_string(&config)?),
            saml_config: None,
            domain_verified: None,
        })
        .await?;
    Ok(())
}

pub(super) async fn saml_sign_in_relay_state(
    router: &openauth_core::api::AuthRouter,
) -> Result<String, Box<dyn std::error::Error>> {
    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/sign-in/sso",
            r#"{"providerId":"saml-okta","providerType":"saml","callbackURL":"/dashboard","errorCallbackURL":"/login-error"}"#,
            None,
        )?)
        .await?;
    let body = json_body(sign_in)?;
    let url = url::Url::parse(body["url"].as_str().ok_or("missing URL")?)?;
    url.query_pairs()
        .find_map(|(key, value)| (key == "RelayState").then(|| value.into_owned()))
        .ok_or_else(|| "missing RelayState".into())
}

pub(super) async fn post_saml_acs(
    router: &openauth_core::api::AuthRouter,
    saml_response: &str,
    relay_state: &str,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(router
        .handle_async(json_request(
            Method::POST,
            "/sso/saml2/sp/acs/saml-okta",
            &format!(
                r#"{{"SAMLResponse":{},"RelayState":{}}}"#,
                serde_json::to_string(saml_response)?,
                serde_json::to_string(relay_state)?
            ),
            None,
        )?)
        .await?)
}

pub(super) fn set_cookie_header(
    response: &http::Response<Vec<u8>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if cookies.is_empty() {
        return Err("missing Set-Cookie".into());
    }
    Ok(cookies.join("; "))
}

pub(super) fn inflate_redirect_binding(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(value.as_bytes())?;
    let mut decoder = DeflateDecoder::new(bytes.as_slice());
    let mut xml = String::new();
    decoder.read_to_string(&mut xml)?;
    Ok(xml)
}

pub(super) fn logout_request_id_from_location(
    location: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = url::Url::parse(location)?;
    let encoded = url
        .query_pairs()
        .find_map(|(key, value)| (key == "SAMLRequest").then(|| value.into_owned()))
        .ok_or("missing SAMLRequest")?;
    let xml = inflate_redirect_binding(&encoded)?;
    xml.split(r#"ID=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .map(str::to_owned)
        .ok_or_else(|| "missing LogoutRequest ID".into())
}

pub(super) fn logout_response_xml(
    in_response_to: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let issue_instant =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let xml = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="logout-response-1" Version="2.0" IssueInstant="{issue_instant}" Destination="https://app.example.com/sso/saml2/sp/slo/saml-okta" InResponseTo="{in_response_to}">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
            <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
        </samlp:LogoutResponse>"#
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(xml.as_bytes()))
}

pub(super) fn logout_request_xml(id: &str) -> Result<String, Box<dyn std::error::Error>> {
    let issue_instant =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let xml = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issue_instant}" Destination="https://app.example.com/sso/saml2/sp/slo/saml-okta">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
            <saml:NameID>saml-subject-123</saml:NameID>
            <samlp:SessionIndex>session-index-1</samlp:SessionIndex>
        </samlp:LogoutRequest>"#
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(xml.as_bytes()))
}

pub(super) fn valid_saml_response(
    in_response_to: &str,
    assertion_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let now = time::OffsetDateTime::now_utc();
    let not_before = (now - time::Duration::minutes(1))
        .format(&time::format_description::well_known::Rfc3339)?;
    let not_on_or_after = (now + time::Duration::minutes(5))
        .format(&time::format_description::well_known::Rfc3339)?;
    let issue_instant = now.format(&time::format_description::well_known::Rfc3339)?;
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="response-1" Version="2.0" IssueInstant="{issue_instant}" Destination="https://app.example.com/sso/saml2/sp/acs/saml-okta" InResponseTo="{in_response_to}">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
            <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
            <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
                <saml:Subject>
                    <saml:NameID>saml-subject-123</saml:NameID>
                    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                        <saml:SubjectConfirmationData Recipient="https://app.example.com/sso/saml2/sp/acs/saml-okta" InResponseTo="{in_response_to}" NotOnOrAfter="{not_on_or_after}"/>
                    </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
                    <saml:AudienceRestriction><saml:Audience>https://app.example.com/saml/sp</saml:Audience></saml:AudienceRestriction>
                </saml:Conditions>
                <saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="session-index-1"/>
                <saml:AttributeStatement>
                    <saml:Attribute Name="email"><saml:AttributeValue>saml-user@example.com</saml:AttributeValue></saml:Attribute>
                    <saml:Attribute Name="givenName"><saml:AttributeValue>Saml</saml:AttributeValue></saml:Attribute>
                    <saml:Attribute Name="surname"><saml:AttributeValue>User</saml:AttributeValue></saml:Attribute>
                </saml:AttributeStatement>
            </saml:Assertion>
        </samlp:Response>"#
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(xml.as_bytes()))
}

pub(super) fn encrypted_saml_response(
    in_response_to: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let issue_instant =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let xml = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" ID="response-encrypted" Version="2.0" IssueInstant="{issue_instant}" Destination="https://app.example.com/sso/saml2/sp/acs/saml-okta" InResponseTo="{in_response_to}">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
            <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
            <saml:EncryptedAssertion>
                <xenc:EncryptedData>encrypted</xenc:EncryptedData>
            </saml:EncryptedAssertion>
        </samlp:Response>"#
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(xml.as_bytes()))
}

#[cfg(not(feature = "saml-signed"))]
pub(super) fn signed_marker_saml_response(
    in_response_to: &str,
    assertion_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = valid_saml_response(in_response_to, assertion_id)?;
    let xml = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(response)?)?;
    let signed = xml.replacen(
        "<saml:Subject>",
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature><saml:Subject>"#,
        1,
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(signed.as_bytes()))
}

pub(super) fn tamper_base64_xml(
    encoded: &str,
    from: &str,
    to: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let xml = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(encoded)?)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(xml.replace(from, to).as_bytes()))
}

#[cfg(feature = "saml-signed")]
pub(super) fn samael_test_vector(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
        format!("{home}/.cargo")
    });
    let path = std::path::Path::new(&cargo_home)
        .join("registry/src/index.crates.io-1949cf8c6b5b557f/samael-0.0.20/test_vectors")
        .join(name);
    Ok(std::fs::read_to_string(path)?)
}
