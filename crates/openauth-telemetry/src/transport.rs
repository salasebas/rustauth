use std::future::Future;
use std::pin::Pin;

use crate::types::{TelemetryHttpError, TelemetryHttpTransport};

#[cfg(not(feature = "http"))]
pub struct NoopTransport;

#[cfg(not(feature = "http"))]
impl TelemetryHttpTransport for NoopTransport {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), TelemetryHttpError>> + Send + 'a>> {
        Box::pin(async move { Ok(()) })
    }
}

#[cfg(feature = "http")]
pub struct ReqwestTelemetryTransport {
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl Default for ReqwestTelemetryTransport {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "http")]
impl TelemetryHttpTransport for ReqwestTelemetryTransport {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), TelemetryHttpError>> + Send + 'a>> {
        Box::pin(async move {
            let response = self
                .client
                .post(url)
                .json(body)
                .send()
                .await
                .map_err(|e| TelemetryHttpError(e.to_string()))?;
            if response.status().is_success() {
                Ok(())
            } else {
                Err(TelemetryHttpError(format!(
                    "http status {}",
                    response.status()
                )))
            }
        })
    }
}
