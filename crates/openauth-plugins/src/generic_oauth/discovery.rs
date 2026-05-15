use openauth_oauth::oauth2::OAuthError;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::GenericOAuthConfig;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveryCache {
    documents: Arc<Mutex<BTreeMap<String, DiscoveryDocument>>>,
}

impl DiscoveryCache {
    pub async fn fetch(
        &self,
        config: &GenericOAuthConfig,
    ) -> Result<Option<DiscoveryDocument>, OAuthError> {
        let Some(url) = config.discovery_url.as_deref() else {
            return Ok(None);
        };
        if let Some(document) = self.get(&config.provider_id)? {
            return Ok(Some(document));
        }
        let document = fetch_url(config, url).await?;
        self.insert(config.provider_id.clone(), document.clone())?;
        Ok(Some(document))
    }

    fn get(&self, provider_id: &str) -> Result<Option<DiscoveryDocument>, OAuthError> {
        let documents = self.documents.lock().map_err(|_| {
            OAuthError::InvalidResponse("discovery cache lock was poisoned".to_owned())
        })?;
        Ok(documents.get(provider_id).cloned())
    }

    fn insert(&self, provider_id: String, document: DiscoveryDocument) -> Result<(), OAuthError> {
        let mut documents = self.documents.lock().map_err(|_| {
            OAuthError::InvalidResponse("discovery cache lock was poisoned".to_owned())
        })?;
        documents.insert(provider_id, document);
        Ok(())
    }
}

async fn fetch_url(
    config: &GenericOAuthConfig,
    url: &str,
) -> Result<DiscoveryDocument, OAuthError> {
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
    Ok(document)
}

pub fn headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
        .collect()
}
