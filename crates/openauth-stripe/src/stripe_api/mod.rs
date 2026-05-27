use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use reqwest::Method;
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use http::StatusCode;

use crate::errors::StripeErrorCode;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type StripeTransportFuture<'a> = BoxFuture<'a, Result<StripeResponse, StripeApiError>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripeRequest {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StripeResponse {
    pub status: u16,
    pub body: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum StripeApiError {
    #[error("{message}")]
    Stripe {
        status: u16,
        code: Option<String>,
        message: String,
    },
    #[error("transport error: {0}")]
    Transport(String),
    #[error("{0}")]
    Webhook(StripeErrorCode),
}

impl StripeApiError {
    pub fn code(&self) -> &str {
        match self {
            Self::Stripe {
                code: Some(code), ..
            } => code,
            Self::Stripe { .. } => "STRIPE_API_ERROR",
            Self::Transport(_) => "STRIPE_TRANSPORT_ERROR",
            Self::Webhook(code) => code.code(),
        }
    }

    pub fn is_already_scheduled_cancel(&self) -> bool {
        match self {
            Self::Stripe { code, message, .. } => {
                matches!(
                    code.as_deref(),
                    Some(
                        "subscription_already_canceled"
                            | "resource_already_exists"
                            | "invalid_request_error"
                    )
                ) || message.contains("already set to be canceled")
            }
            _ => false,
        }
    }

    pub fn plugin_response(&self, default: StripeErrorCode) -> (StatusCode, StripeErrorCode) {
        match self {
            Self::Webhook(code) => (StatusCode::BAD_REQUEST, *code),
            Self::Transport(_) => (StatusCode::BAD_GATEWAY, StripeErrorCode::FailedToFetchPlans),
            Self::Stripe { status, code, .. } if *status >= 500 => {
                (StatusCode::BAD_GATEWAY, StripeErrorCode::FailedToFetchPlans)
            }
            Self::Stripe { code, .. } => (
                StatusCode::BAD_REQUEST,
                map_stripe_code_to_plugin(default, code.as_deref()),
            ),
        }
    }
}

fn map_stripe_code_to_plugin(
    default: StripeErrorCode,
    stripe_code: Option<&str>,
) -> StripeErrorCode {
    match (default, stripe_code) {
        (StripeErrorCode::UnableToCreateCustomer, Some("resource_missing")) => {
            StripeErrorCode::CustomerNotFound
        }
        (StripeErrorCode::UnableToCreateBillingPortal, Some("resource_missing")) => {
            StripeErrorCode::SubscriptionNotFound
        }
        (StripeErrorCode::SubscriptionNotFound, Some("resource_missing")) => {
            StripeErrorCode::SubscriptionNotFound
        }
        _ => default,
    }
}

/// Signing key bytes for Stripe webhook HMAC verification.
///
/// `whsec_` suffix is base64-encoded (Dashboard and Stripe CLI `listen`).
pub fn webhook_signing_key(secret: &str) -> Result<Vec<u8>, StripeApiError> {
    if let Some(encoded) = secret.strip_prefix("whsec_") {
        match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(bytes) => Ok(bytes),
            // Test secrets such as `whsec_test` are not dashboard-style base64 payloads.
            Err(_) => Ok(secret.as_bytes().to_vec()),
        }
    } else {
        Ok(secret.as_bytes().to_vec())
    }
}

pub trait StripeTransport: Send + Sync {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a>;
}

#[derive(Clone)]
pub struct StripeClient {
    secret_key: String,
    api_base: String,
    api_version: Option<String>,
    transport: Arc<dyn StripeTransport>,
}

impl StripeClient {
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            secret_key: secret_key.into(),
            api_base: "https://api.stripe.com".to_owned(),
            api_version: None,
            transport: Arc::new(ReqwestStripeTransport::new("https://api.stripe.com")),
        }
    }

    pub fn with_transport(
        secret_key: impl Into<String>,
        transport: Arc<dyn StripeTransport>,
    ) -> Self {
        Self {
            secret_key: secret_key.into(),
            api_base: "https://api.stripe.com".to_owned(),
            api_version: None,
            transport,
        }
    }

    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.api_base = api_base.into();
        self.transport = Arc::new(ReqwestStripeTransport::new(self.api_base.clone()));
        self
    }

    pub fn api_version(mut self, api_version: impl Into<String>) -> Self {
        self.api_version = Some(api_version.into());
        self
    }

    pub async fn create_customer(&self, params: Value) -> Result<Value, StripeApiError> {
        self.post("/v1/customers", params).await
    }

    pub async fn update_customer(
        &self,
        customer_id: &str,
        params: Value,
    ) -> Result<Value, StripeApiError> {
        self.post(&format!("/v1/customers/{customer_id}"), params)
            .await
    }

    pub async fn retrieve_customer(&self, customer_id: &str) -> Result<Value, StripeApiError> {
        self.get(&format!("/v1/customers/{customer_id}"), Value::Null)
            .await
    }

    pub async fn search_customers(&self, query: &str) -> Result<Value, StripeApiError> {
        self.get(
            "/v1/customers/search",
            serde_json::json!({ "query": query, "limit": 1 }),
        )
        .await
    }

    pub async fn list_customers(&self, params: Value) -> Result<Value, StripeApiError> {
        self.get("/v1/customers", params).await
    }

    pub async fn retrieve_price(&self, price_id: &str) -> Result<Value, StripeApiError> {
        self.get(&format!("/v1/prices/{price_id}"), Value::Null)
            .await
    }

    pub async fn list_prices(&self, params: Value) -> Result<Value, StripeApiError> {
        self.get("/v1/prices", params).await
    }

    pub async fn price_by_lookup_key(&self, lookup_key: &str) -> Result<Value, StripeApiError> {
        self.list_prices(serde_json::json!({
            "lookup_keys": [lookup_key],
            "active": true,
            "limit": 1
        }))
        .await
    }

    pub async fn create_checkout_session(&self, params: Value) -> Result<Value, StripeApiError> {
        self.post("/v1/checkout/sessions", params).await
    }

    pub async fn retrieve_checkout_session(
        &self,
        session_id: &str,
    ) -> Result<Value, StripeApiError> {
        self.get(&format!("/v1/checkout/sessions/{session_id}"), Value::Null)
            .await
    }

    pub async fn create_billing_portal_session(
        &self,
        params: Value,
    ) -> Result<Value, StripeApiError> {
        self.post("/v1/billing_portal/sessions", params).await
    }

    pub async fn list_subscriptions(&self, params: Value) -> Result<Value, StripeApiError> {
        self.get("/v1/subscriptions", params).await
    }

    pub async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Value, StripeApiError> {
        self.get(&format!("/v1/subscriptions/{subscription_id}"), Value::Null)
            .await
    }

    pub async fn update_subscription(
        &self,
        subscription_id: &str,
        params: Value,
    ) -> Result<Value, StripeApiError> {
        self.post(&format!("/v1/subscriptions/{subscription_id}"), params)
            .await
    }

    pub async fn create_subscription_schedule(
        &self,
        params: Value,
    ) -> Result<Value, StripeApiError> {
        self.post("/v1/subscription_schedules", params).await
    }

    pub async fn list_subscription_schedules(
        &self,
        params: Value,
    ) -> Result<Value, StripeApiError> {
        self.get("/v1/subscription_schedules", params).await
    }

    pub async fn retrieve_subscription_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<Value, StripeApiError> {
        self.get(
            &format!("/v1/subscription_schedules/{schedule_id}"),
            Value::Null,
        )
        .await
    }

    pub async fn update_subscription_schedule(
        &self,
        schedule_id: &str,
        params: Value,
    ) -> Result<Value, StripeApiError> {
        self.post(&format!("/v1/subscription_schedules/{schedule_id}"), params)
            .await
    }

    pub async fn release_subscription_schedule(
        &self,
        schedule_id: &str,
    ) -> Result<Value, StripeApiError> {
        self.post(
            &format!("/v1/subscription_schedules/{schedule_id}/release"),
            Value::Object(Default::default()),
        )
        .await
    }

    async fn post(&self, path: &str, params: Value) -> Result<Value, StripeApiError> {
        self.send("POST", path, params).await
    }

    async fn get(&self, path: &str, params: Value) -> Result<Value, StripeApiError> {
        self.send("GET", path, params).await
    }

    async fn send(&self, method: &str, path: &str, params: Value) -> Result<Value, StripeApiError> {
        let body = if params.is_null() {
            String::new()
        } else {
            encode_form(&params)
        };
        let mut headers = BTreeMap::new();
        headers.insert(
            "Authorization".to_owned(),
            format!("Bearer {}", self.secret_key),
        );
        headers.insert(
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        );
        if let Some(api_version) = &self.api_version {
            headers.insert("Stripe-Version".to_owned(), api_version.clone());
        }
        let request = StripeRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            headers,
            body,
        };
        let response = self.transport.send(request).await?;
        if (200..300).contains(&response.status) {
            Ok(response.body)
        } else {
            Err(stripe_error_from_response(response))
        }
    }
}

pub struct ReqwestStripeTransport {
    client: reqwest::Client,
    api_base: String,
}

const DEFAULT_STRIPE_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

impl ReqwestStripeTransport {
    pub fn new(api_base: impl Into<String>) -> Self {
        Self::with_timeout(api_base, DEFAULT_STRIPE_HTTP_TIMEOUT)
    }

    pub fn with_timeout(api_base: impl Into<String>, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            api_base: api_base.into(),
        }
    }
}

impl StripeTransport for ReqwestStripeTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        Box::pin(async move {
            let method = request
                .method
                .parse::<Method>()
                .map_err(|error| StripeApiError::Transport(error.to_string()))?;
            let url = if request.method == "GET" && !request.body.is_empty() {
                format!("{}{}?{}", self.api_base, request.path, request.body)
            } else {
                format!("{}{}", self.api_base, request.path)
            };
            let mut builder = self.client.request(method, url);
            for (name, value) in request.headers {
                builder = builder.header(name, value);
            }
            if request.method != "GET" {
                builder = builder.body(request.body);
            }
            let response = builder
                .send()
                .await
                .map_err(|error| StripeApiError::Transport(error.to_string()))?;
            let status = response.status().as_u16();
            let body = response
                .json::<Value>()
                .await
                .map_err(|error| StripeApiError::Transport(error.to_string()))?;
            Ok(StripeResponse { status, body })
        })
    }
}

pub fn encode_form(value: &Value) -> String {
    let mut pairs = Vec::new();
    collect_form_pairs(None, value, &mut pairs);
    pairs
        .into_iter()
        .map(|(key, value)| format!("{}={}", form_encode(&key), form_encode(&value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn collect_form_pairs(prefix: Option<String>, value: &Value, pairs: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let key = match &prefix {
                    Some(prefix) => format!("{prefix}[{key}]"),
                    None => key.clone(),
                };
                collect_form_pairs(Some(key), value, pairs);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if let Some(prefix) = &prefix {
                    collect_form_pairs(Some(format!("{prefix}[{index}]")), value, pairs);
                }
            }
        }
        Value::String(value) => {
            if let Some(prefix) = prefix {
                pairs.push((prefix, value.clone()));
            }
        }
        Value::Number(value) => {
            if let Some(prefix) = prefix {
                pairs.push((prefix, value.to_string()));
            }
        }
        Value::Bool(value) => {
            if let Some(prefix) = prefix {
                pairs.push((prefix, value.to_string()));
            }
        }
        Value::Null => {}
    }
}

fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

pub fn verify_webhook_signature(
    payload: &[u8],
    signature_header: &str,
    secret: &str,
    tolerance_seconds: i64,
    now_unix: i64,
) -> Result<(), StripeApiError> {
    let timestamp = signature_header
        .split(',')
        .find_map(|part| part.strip_prefix("t="))
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(StripeApiError::Webhook(
            StripeErrorCode::FailedToConstructStripeEvent,
        ))?;
    if (now_unix - timestamp).abs() > tolerance_seconds {
        return Err(StripeApiError::Webhook(
            StripeErrorCode::FailedToConstructStripeEvent,
        ));
    }
    let expected = webhook_signature(payload, secret, timestamp)?;
    let verified = signature_header
        .split(',')
        .filter_map(|part| part.strip_prefix("v1="))
        .filter_map(|signature| hex::decode(signature).ok())
        .any(|candidate| candidate.ct_eq(expected.as_slice()).into());
    if verified {
        Ok(())
    } else {
        Err(StripeApiError::Webhook(
            StripeErrorCode::FailedToConstructStripeEvent,
        ))
    }
}

fn webhook_signature(
    payload: &[u8],
    secret: &str,
    timestamp: i64,
) -> Result<Vec<u8>, StripeApiError> {
    let signing_key = webhook_signing_key(secret)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&signing_key).map_err(|error| {
        StripeApiError::Transport(format!("failed to initialize webhook verifier: {error}"))
    })?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn stripe_error_from_response(response: StripeResponse) -> StripeApiError {
    let error = response.body.get("error").unwrap_or(&response.body);
    let code = error.get("code").and_then(Value::as_str).map(str::to_owned);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("Stripe API request failed")
        .to_owned();
    StripeApiError::Stripe {
        status: response.status,
        code,
        message,
    }
}
