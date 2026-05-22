//! SCIM filter parsing.

use http::StatusCode;

use crate::errors::ScimError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimFilterOperator {
    Eq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimDbFilter {
    pub field: String,
    pub value: String,
    pub operator: ScimFilterOperator,
}

pub fn parse_user_filter(filter: &str) -> Result<Vec<ScimDbFilter>, ScimError> {
    let mut parts = filter.trim().splitn(3, char::is_whitespace);
    let attribute = parts.next().filter(|value| !value.is_empty());
    let operator = parts.next().filter(|value| !value.is_empty());
    let value = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (Some(attribute), Some(operator), Some(value)) = (attribute, operator, value) else {
        return Err(invalid_filter("Invalid filter expression"));
    };

    if !attribute.eq("userName") {
        return Err(invalid_filter(format!(
            r#"The attribute "{attribute}" is not supported"#
        )));
    }

    if !operator.eq_ignore_ascii_case("eq") {
        return Err(invalid_filter(format!(
            r#"The operator "{}" is not supported"#,
            operator.to_ascii_lowercase()
        )));
    }

    let value = value.trim_matches('"').to_ascii_lowercase();
    if value.is_empty() {
        return Err(invalid_filter("Invalid filter expression"));
    }

    Ok(vec![ScimDbFilter {
        field: "email".to_owned(),
        value,
        operator: ScimFilterOperator::Eq,
    }])
}

fn invalid_filter(detail: impl Into<String>) -> ScimError {
    ScimError::new(StatusCode::BAD_REQUEST, detail).with_scim_type("invalidFilter")
}
