//! SCIM-to-RustAuth field mapping helpers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
}

pub fn account_id(user_name: &str, external_id: Option<&str>) -> String {
    external_id.unwrap_or(user_name).to_owned()
}

pub fn primary_email(user_name: &str, emails: &[ScimEmail]) -> String {
    emails
        .iter()
        .find(|email| email.primary)
        .or_else(|| emails.first())
        .map(|email| email.value.clone())
        .unwrap_or_else(|| user_name.to_owned())
}

pub fn user_full_name(email: &str, name: Option<&ScimName>) -> String {
    let Some(name) = name else {
        return email.to_owned();
    };
    if let Some(formatted) = name
        .formatted
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return formatted.to_owned();
    }

    match (
        name.given_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        name.family_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
    ) {
        (Some(given), Some(family)) => format!("{given} {family}"),
        (Some(given), None) => given.to_owned(),
        (None, Some(family)) => family.to_owned(),
        (None, None) => email.to_owned(),
    }
}

pub fn resource_url(base_url: &str, path: &str) -> String {
    let base = if base_url.ends_with('/') {
        base_url.to_owned()
    } else {
        format!("{base_url}/")
    };
    let path = path.trim_start_matches('/');
    format!("{base}{path}")
}
