use openauth_core::error::OpenAuthError;
use quick_xml::events::Event;
use quick_xml::Reader;

pub fn validate_saml_xml(xml: &str) -> Result<(), OpenAuthError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => stack.push(local_name(element.name().as_ref())?),
            Ok(Event::Empty(_)) => {}
            Ok(Event::End(element)) => {
                let name = local_name(element.name().as_ref())?;
                match stack.pop() {
                    Some(start) if start == name => {}
                    _ => {
                        return Err(OpenAuthError::Api(
                            "Invalid SAML XML: mismatched closing element".to_owned(),
                        ));
                    }
                }
            }
            Ok(Event::DocType(_)) => {
                return Err(OpenAuthError::Api(
                    "Invalid SAML XML: DOCTYPE is not allowed".to_owned(),
                ));
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(OpenAuthError::Api(format!("Invalid SAML XML: {error}"))),
            Ok(_) => {}
        }
    }

    if !stack.is_empty() {
        return Err(OpenAuthError::Api(
            "Invalid SAML XML: unexpected end of file".to_owned(),
        ));
    }

    Ok(())
}

pub fn local_name(name: &[u8]) -> Result<String, OpenAuthError> {
    let value = std::str::from_utf8(name)
        .map_err(|error| OpenAuthError::Api(format!("Invalid SAML XML name: {error}")))?;
    Ok(value
        .rsplit_once(':')
        .map_or(value, |(_, local)| local)
        .to_owned())
}
