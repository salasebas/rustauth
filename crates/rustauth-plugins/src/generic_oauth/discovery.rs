use rustauth_oauth::oauth2::{http::default_http_client, OAuthError, OAuthHttpClient};
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

pub(super) fn resolve_http_client(
    config: &GenericOAuthConfig,
) -> Result<OAuthHttpClient, OAuthError> {
    match &config.http_client {
        Some(client) => Ok(client.clone()),
        None => default_http_client(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveryCache {
    documents: Arc<Mutex<BTreeMap<String, DiscoveryDocument>>>,
}

impl DiscoveryCache {
    pub async fn fetch(
        &self,
        config: &GenericOAuthConfig,
        http_client: &OAuthHttpClient,
    ) -> Result<Option<DiscoveryDocument>, OAuthError> {
        let Some(url) = config.discovery_url.as_deref() else {
            return Ok(None);
        };
        if let Some(document) = self.get(&config.provider_id)? {
            return Ok(Some(document));
        }
        let document = fetch_url(config, url, http_client).await?;
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
    http_client: &OAuthHttpClient,
) -> Result<DiscoveryDocument, OAuthError> {
    let header_pairs = config
        .discovery_headers
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let bytes = http_client
        .get_bytes_with_headers(url, &header_pairs)
        .await?;
    serde_json::from_slice::<DiscoveryDocument>(&bytes)
        .map_err(|error| OAuthError::InvalidResponse(error.to_string()))
}

pub fn headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), value.clone()))
        .collect()
}
