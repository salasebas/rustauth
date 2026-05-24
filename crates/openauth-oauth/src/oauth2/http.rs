use std::sync::OnceLock;
use std::time::Duration;

use reqwest::{Client, Response};
use serde_json::Value;

use super::error::{oauth_error_description, OAuthError};
use super::request::OAuthFormRequest;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_USER_AGENT: &str = concat!("openauth-oauth/", env!("CARGO_PKG_VERSION"));
const SENSITIVE_OAUTH_FIELDS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "client_assertion",
    "subject_token",
    "device_code",
    "code",
    "token",
    "authorization",
];

#[derive(Debug, Clone)]
pub struct OAuthHttpClient {
    client: Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthHttpClientConfig {
    pub timeout: Duration,
    pub user_agent: Option<String>,
}

impl Default for OAuthHttpClientConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            user_agent: Some(DEFAULT_USER_AGENT.to_owned()),
        }
    }
}

impl OAuthHttpClient {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub fn default_client() -> Result<Self, OAuthError> {
        Self::from_config(OAuthHttpClientConfig::default())
    }

    pub fn from_config(config: OAuthHttpClientConfig) -> Result<Self, OAuthError> {
        if config.timeout.is_zero() {
            return Err(OAuthError::InvalidConfiguration(
                "HTTP timeout must be greater than zero".to_owned(),
            ));
        }
        let mut builder = Client::builder().timeout(config.timeout);
        if let Some(user_agent) = config.user_agent {
            builder = builder.user_agent(user_agent);
        }
        builder.build().map(Self::new).map_err(Into::into)
    }

    pub async fn get_bytes(&self, url: &str) -> Result<Vec<u8>, OAuthError> {
        let response = self
            .client
            .get(url)
            .header("accept", "application/json")
            .send()
            .await?;
        response_bytes(response).await
    }

    pub async fn post_form(
        &self,
        token_endpoint: &str,
        request: OAuthFormRequest,
    ) -> Result<Value, OAuthError> {
        let mut builder = self.client.post(token_endpoint);
        for (key, value) in &request.headers {
            builder = builder.header(key, value);
        }
        let response = builder.body(request.to_form_urlencoded()).send().await?;
        response_json(response).await
    }
}

pub fn default_http_client() -> Result<OAuthHttpClient, OAuthError> {
    static CLIENT: OnceLock<Result<OAuthHttpClient, String>> = OnceLock::new();

    CLIENT
        .get_or_init(|| OAuthHttpClient::default_client().map_err(|error| error.to_string()))
        .clone()
        .map_err(OAuthError::InvalidConfiguration)
}

async fn response_bytes(response: Response) -> Result<Vec<u8>, OAuthError> {
    let status = response.status();
    let bytes = response.bytes().await?;
    if status.is_success() {
        return Ok(bytes.to_vec());
    }
    Err(http_status_error(status.as_u16(), &bytes))
}

async fn response_json(response: Response) -> Result<Value, OAuthError> {
    let status = response.status();
    let bytes = response.bytes().await?;
    let value = serde_json::from_slice::<Value>(&bytes);
    if status.is_success() {
        return value.map_err(|error| OAuthError::InvalidResponse(error.to_string()));
    }
    if let Ok(value) = value {
        if let Some(error) = value.get("error").and_then(Value::as_str) {
            return Err(OAuthError::ErrorResponse {
                error: error.to_owned(),
                description: oauth_error_description(redact_error_description(
                    value.get("error_description").and_then(Value::as_str),
                )),
                uri: value
                    .get("error_uri")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            });
        }
    }
    Err(http_status_error(status.as_u16(), &bytes))
}

fn http_status_error(status: u16, body: &[u8]) -> OAuthError {
    OAuthError::HttpStatus {
        status,
        body: redact_body(&String::from_utf8_lossy(body)),
    }
}

fn redact_body(body: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<Value>(body) {
        redact_json_value(&mut value);
        return value.to_string();
    }

    let lower = body.to_ascii_lowercase();
    if SENSITIVE_OAUTH_FIELDS.iter().any(|key| lower.contains(key))
        || lower.contains("bearer ")
        || lower.contains("basic ")
    {
        return "<redacted OAuth response body>".to_owned();
    }
    body.to_owned()
}

fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if SENSITIVE_OAUTH_FIELDS
                    .iter()
                    .any(|sensitive| key.eq_ignore_ascii_case(sensitive))
                {
                    *value = Value::String("<redacted>".to_owned());
                } else {
                    redact_json_value(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_json_value(value);
            }
        }
        _ => {}
    }
}

fn redact_error_description(description: Option<&str>) -> Option<String> {
    let description = description?;
    let lower = description.to_ascii_lowercase();
    if [
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "client_assertion",
        "subject_token",
        "device_code",
        "authorization",
        "bearer ",
        "basic ",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return Some("<redacted error_description>".to_owned());
    }
    Some(description.to_owned())
}
