use super::*;

#[cfg(feature = "saml-signed")]
pub(crate) struct SignedSamlIdp {
    pub(crate) key_pem: String,
    pub(crate) cert: String,
    pub(crate) cert_der: samael::crypto::CertificateDer,
}

#[cfg(feature = "saml-signed")]
pub(crate) fn signed_saml_idp() -> Result<SignedSamlIdp, Box<dyn std::error::Error>> {
    let directory = temp_test_directory("idp")?;
    std::fs::create_dir_all(&directory)?;
    let key_path = directory.join("idp-key.pem");
    let cert_path = directory.join("idp-cert.pem");
    let status = std::process::Command::new("openssl")
        .arg("req")
        .arg("-x509")
        .arg("-newkey")
        .arg("rsa:2048")
        .arg("-keyout")
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .arg("-days")
        .arg("365")
        .arg("-nodes")
        .arg("-subj")
        .arg("/CN=idp.example.com")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&directory);
        return Err("openssl failed to generate SAML test certificate".into());
    }
    let key_pem = std::fs::read_to_string(&key_path)?;
    let cert_pem = std::fs::read_to_string(&cert_path)?;
    let cert = cert_pem
        .lines()
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .collect::<String>();
    let cert_der = samael::crypto::decode_x509_cert(&cert)?;
    let _ = std::fs::remove_dir_all(&directory);
    Ok(SignedSamlIdp {
        key_pem,
        cert,
        cert_der,
    })
}

#[cfg(feature = "saml-signed")]
pub(crate) fn signed_response_saml_response(
    idp: &SignedSamlIdp,
    in_response_to: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use samael::idp::response_builder::build_response_template;
    use samael::traits::ToXml;

    let response = build_response_template(
        &idp.cert_der,
        "saml-subject-123",
        "https://app.example.com/saml/sp",
        "https://idp.example.com",
        "https://app.example.com/sso/saml2/sp/acs/saml-okta",
        in_response_to,
        &saml_response_attributes(),
    );
    let signed_xml = sign_xml_fixture(idp, &response.to_string()?, "Response")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(signed_xml.as_bytes()))
}

#[cfg(feature = "saml-signed")]
pub(crate) fn signed_assertion_saml_response(
    idp: &SignedSamlIdp,
    in_response_to: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use samael::idp::response_builder::build_response_template;
    use samael::traits::ToXml;

    let mut response = build_response_template(
        &idp.cert_der,
        "saml-subject-123",
        "https://app.example.com/saml/sp",
        "https://idp.example.com",
        "https://app.example.com/sso/saml2/sp/acs/saml-okta",
        in_response_to,
        &saml_response_attributes(),
    );
    response.signature = None;
    if let Some(assertion) = response.assertion.as_mut() {
        assertion.signature = Some(samael::signature::Signature::template(
            &assertion.id,
            &idp.cert_der,
        ));
    }
    let signed_xml = sign_xml_fixture(idp, &response.to_string()?, "Assertion")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(signed_xml.as_bytes()))
}

#[cfg(feature = "saml-signed")]
pub(crate) fn saml_response_attributes<'a>(
) -> Vec<samael::idp::response_builder::ResponseAttribute<'a>> {
    use samael::idp::response_builder::ResponseAttribute;
    use samael::idp::sp_extractor::RequiredAttribute;

    vec![
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "email".to_owned(),
                format: None,
            },
            value: "saml-user@example.com",
        },
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "givenName".to_owned(),
                format: None,
            },
            value: "Saml",
        },
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "surname".to_owned(),
                format: None,
            },
            value: "User",
        },
    ]
}

#[cfg(feature = "saml-signed")]
pub(crate) fn signed_logout_response_xml(
    idp: &SignedSamlIdp,
    in_response_to: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let issue_instant =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let id = "signed-logout-response-1";
    let xml = format!(
        r##"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issue_instant}" Destination="https://app.example.com/sso/saml2/sp/slo/saml-okta" InResponseTo="{in_response_to}">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
            {}
            <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
        </samlp:LogoutResponse>"##,
        signature_template(id, &idp.cert)
    );
    let signed_xml = sign_xml_fixture(idp, &xml, "LogoutResponse")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(signed_xml.as_bytes()))
}

#[cfg(feature = "saml-signed")]
pub(crate) fn signed_logout_request_xml(
    idp: &SignedSamlIdp,
    id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let issue_instant =
        time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let xml = format!(
        r##"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issue_instant}" Destination="https://app.example.com/sso/saml2/sp/slo/saml-okta">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
            {}
            <saml:NameID>saml-subject-123</saml:NameID>
            <samlp:SessionIndex>session-index-1</samlp:SessionIndex>
        </samlp:LogoutRequest>"##,
        signature_template(id, &idp.cert)
    );
    let signed_xml = sign_xml_fixture(idp, &xml, "LogoutRequest")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(signed_xml.as_bytes()))
}

#[cfg(feature = "saml-signed")]
pub(crate) fn sign_xml_fixture(
    idp: &SignedSamlIdp,
    xml: &str,
    id_attr_element: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let directory =
        std::env::temp_dir().join(format!("openauth-sso-test-sign-{}", unique_test_suffix()?));
    std::fs::create_dir_all(&directory)?;
    let input_path = directory.join("input.xml");
    let output_path = directory.join("signed.xml");
    let key_path = directory.join("private.pem");
    let cert_path = directory.join("cert.pem");
    std::fs::write(&input_path, xml)?;
    std::fs::write(&key_path, &idp.key_pem)?;
    std::fs::write(
        &cert_path,
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            idp.cert
        ),
    )?;
    let status = std::process::Command::new("xmlsec1")
        .arg("--sign")
        .arg("--lax-key-search")
        .arg("--privkey-pem")
        .arg(format!("{},{}", key_path.display(), cert_path.display()))
        .arg("--id-attr:ID")
        .arg(id_attr_element)
        .arg("--output")
        .arg(&output_path)
        .arg(&input_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&directory);
        return Err("xmlsec1 failed to sign SAML fixture".into());
    }
    let signed = std::fs::read_to_string(&output_path)?;
    let _ = std::fs::remove_dir_all(&directory);
    Ok(signed)
}

#[cfg(feature = "saml-signed")]
pub(crate) fn temp_test_directory(
    prefix: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    Ok(std::env::temp_dir().join(format!(
        "openauth-sso-test-{prefix}-{}",
        unique_test_suffix()?
    )))
}

#[cfg(feature = "saml-signed")]
pub(crate) fn unique_test_suffix() -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
        SAML_SIGNED_TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

#[cfg(feature = "saml-signed")]
pub(crate) fn signature_template(id: &str, cert: &str) -> String {
    format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#{id}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                    <ds:DigestValue></ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue></ds:SignatureValue>
            <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
        </ds:Signature>"##
    )
}
