use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use url::form_urlencoded::Serializer;

use super::error::OAuthError;
use super::http::{default_http_client, OAuthHttpClient};
use super::tokens::{get_primary_client_id, ProviderOptions};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClientAuthentication {
    #[default]
    Post,
    Basic,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthFormRequest {
    pub body: Vec<(String, String)>,
    pub headers: BTreeMap<String, String>,
}

impl OAuthFormRequest {
    pub fn new() -> Self {
        Self {
            body: Vec::new(),
            headers: BTreeMap::from([
                (
                    "content-type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                ),
                ("accept".to_owned(), "application/json".to_owned()),
            ]),
        }
    }

    pub fn push_body(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.body.push((key.into(), value.into()));
    }

    pub fn set_body(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        self.body.retain(|(existing, _)| existing != &key);
        self.body.push((key, value.into()));
    }

    pub fn has_body(&self, key: &str) -> bool {
        self.body.iter().any(|(existing, _)| existing == key)
    }

    pub fn form_value(&self, key: &str) -> Option<&str> {
        self.body
            .iter()
            .find(|(existing, _)| existing == key)
            .map(|(_, value)| value.as_str())
    }

    pub fn form_values(&self, key: &str) -> Vec<&str> {
        self.body
            .iter()
            .filter(|(existing, _)| existing == key)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .get(&key.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn set_header(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.headers
            .insert(key.into().to_ascii_lowercase(), value.into());
    }

    pub fn to_form_urlencoded(&self) -> String {
        let mut serializer = Serializer::new(String::new());
        for (key, value) in &self.body {
            serializer.append_pair(key, value);
        }
        serializer.finish()
    }
}

pub fn apply_client_authentication(
    request: &mut OAuthFormRequest,
    options: &ProviderOptions,
    authentication: ClientAuthentication,
    require_secret: bool,
) -> Result<(), OAuthError> {
    let primary_client_id = get_primary_client_id(&options.client_id);
    let client_secret = non_empty_secret(options);

    match authentication {
        ClientAuthentication::Basic => {
            let client_id = primary_client_id.ok_or_else(|| {
                OAuthError::InvalidClientAuthentication(
                    "HTTP Basic authentication requires client_id".to_owned(),
                )
            })?;
            let client_secret = if require_secret {
                client_secret.ok_or(OAuthError::MissingOption("client_secret"))?
            } else {
                client_secret.unwrap_or("")
            };
            let credentials = STANDARD.encode(format!("{client_id}:{client_secret}"));
            request.set_header("authorization", format!("Basic {credentials}"));
        }
        ClientAuthentication::Post => {
            if let Some(client_id) = primary_client_id {
                request.set_body("client_id", client_id);
            }
            if let Some(client_secret) = client_secret {
                request.set_body("client_secret", client_secret);
            } else if require_secret {
                return Err(OAuthError::MissingOption("client_secret"));
            }
        }
    }

    Ok(())
}

fn non_empty_secret(options: &ProviderOptions) -> Option<&str> {
    options
        .client_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
}

pub async fn post_form(
    token_endpoint: &str,
    request: OAuthFormRequest,
) -> Result<serde_json::Value, OAuthError> {
    post_form_with_client(token_endpoint, request, &default_http_client()?).await
}

pub async fn post_form_with_client(
    token_endpoint: &str,
    request: OAuthFormRequest,
    client: &OAuthHttpClient,
) -> Result<serde_json::Value, OAuthError> {
    client.post_form(token_endpoint, request).await
}
