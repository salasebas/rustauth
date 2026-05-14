use openauth_oauth::oauth2::OAuthError;
use serde::Deserialize;
use std::collections::BTreeMap;

use super::GenericOAuthConfig;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
}

pub async fn fetch(config: &GenericOAuthConfig) -> Result<Option<DiscoveryDocument>, OAuthError> {
    let Some(url) = config.discovery_url.as_deref() else {
        return Ok(None);
    };
    let client = reqwest::Client::new();
    let mut request = client.get(url);
    for (key, value) in &config.discovery_headers {
        request = request.header(key, value);
    }
    let document = request
        .send()
        .await?
        .error_for_status()?
        .json::<DiscoveryDocument>()
        .await?;
    Ok(Some(document))
}

pub fn headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
        .collect()
}
