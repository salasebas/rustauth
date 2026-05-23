use crate::options::SamlConfig;
use crate::saml_impl::authn_request::assertion_consumer_service_url;
use crate::saml_impl::xml::{local_name, validate_saml_xml};
use openauth_core::error::OpenAuthError;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

pub fn service_provider_metadata(
    provider_id: &str,
    base_url: &str,
    config: &SamlConfig,
    single_logout_enabled: bool,
) -> String {
    if let Some(metadata) = config
        .sp_metadata
        .metadata
        .as_deref()
        .filter(|metadata| !metadata.trim().is_empty())
    {
        return metadata.to_owned();
    }

    let entity_id = xml_escape(
        config
            .sp_metadata
            .entity_id
            .as_deref()
            .unwrap_or(config.issuer.as_str()),
    );
    let acs = xml_escape(&assertion_consumer_service_url(
        provider_id,
        base_url,
        config,
    ));
    let name_id_format = config
        .identifier_format
        .as_deref()
        .map(|format| format!("<NameIDFormat>{}</NameIDFormat>", xml_escape(format)))
        .unwrap_or_default();
    let slo = if single_logout_enabled {
        let slo_url = xml_escape(&format!(
            "{}/sso/saml2/sp/slo/{}",
            base_url.trim_end_matches('/'),
            provider_id
        ));
        format!(
            r#"<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{slo_url}"/><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{slo_url}"/>"#
        )
    } else {
        String::new()
    };
    let authn_requests_signed = config.authn_requests_signed;
    let want_assertions_signed = config.want_assertions_signed;

    format!(
        r#"<EntityDescriptor entityID="{entity_id}"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="{authn_requests_signed}" WantAssertionsSigned="{want_assertions_signed}">{name_id_format}{slo}<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs}" index="0"/></SPSSODescriptor></EntityDescriptor>"#
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
}

pub fn first_single_sign_on_service_location(xml: &str) -> Result<Option<String>, OpenAuthError> {
    first_service_location(xml, "SingleSignOnService")
}

pub fn first_single_logout_service_location(xml: &str) -> Result<Option<String>, OpenAuthError> {
    first_service_location(xml, "SingleLogoutService")
}

fn first_service_location(xml: &str, service_name: &str) -> Result<Option<String>, OpenAuthError> {
    validate_saml_xml(xml)?;

    let mut reader = Reader::from_str(xml);
    let mut first_location = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) | Ok(Event::Empty(element))
                if local_name(element.name().as_ref())? == service_name =>
            {
                let location = attribute_value(&reader, &element, "Location")?;
                let binding = attribute_value(&reader, &element, "Binding")?;
                if let Some(location) = location {
                    if binding
                        .as_deref()
                        .is_some_and(|value| value.ends_with("HTTP-Redirect"))
                    {
                        return Ok(Some(location));
                    }
                    first_location.get_or_insert(location);
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                return Err(OpenAuthError::Api(format!(
                    "invalid SAML metadata: {error}"
                )))
            }
            _ => {}
        }
    }
    Ok(first_location)
}

fn attribute_value(
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
    name: &str,
) -> Result<Option<String>, OpenAuthError> {
    for attribute in element.attributes() {
        let attribute = attribute
            .map_err(|error| OpenAuthError::Api(format!("invalid XML attribute: {error}")))?;
        if local_name(attribute.key.as_ref())? == name {
            let value = attribute
                .decode_and_unescape_value(reader.decoder())
                .map_err(|error| OpenAuthError::Api(format!("invalid XML attribute: {error}")))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}
