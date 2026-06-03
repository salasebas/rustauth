//! API error handling options (parity with Better Auth `onAPIError`).

use std::fmt;
use std::sync::Arc;

use crate::api::{ApiRequest, ApiResponse};
use crate::error::OpenAuthError;

/// Configuration for unhandled API errors.
#[derive(Clone, Default)]
pub struct OnApiErrorOptions {
    /// When true, internal errors propagate instead of returning JSON/redirect responses.
    pub throw: bool,
    /// Default redirect target for OAuth-style error flows.
    pub error_url: Option<String>,
    pub on_error: Option<Arc<dyn OnApiErrorHandler>>,
}

impl fmt::Debug for OnApiErrorOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnApiErrorOptions")
            .field("throw", &self.throw)
            .field("error_url", &self.error_url)
            .field(
                "on_error",
                &self.on_error.as_ref().map(|_| "<on-api-error>"),
            )
            .finish()
    }
}

impl OnApiErrorOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn throw(mut self, throw: bool) -> Self {
        self.throw = throw;
        self
    }

    #[must_use]
    pub fn error_url(mut self, url: impl Into<String>) -> Self {
        self.error_url = Some(url.into());
        self
    }

    #[must_use]
    pub fn on_error<H>(mut self, handler: H) -> Self
    where
        H: OnApiErrorHandler,
    {
        self.on_error = Some(Arc::new(handler));
        self
    }
}

/// Hook invoked when the router surfaces an unhandled error.
pub trait OnApiErrorHandler: Send + Sync + 'static {
    fn on_error(
        &self,
        error: &OpenAuthError,
        request: &ApiRequest,
    ) -> Result<Option<ApiResponse>, OpenAuthError>;
}

impl<F> OnApiErrorHandler for F
where
    F: Fn(&OpenAuthError, &ApiRequest) -> Result<Option<ApiResponse>, OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn on_error(
        &self,
        error: &OpenAuthError,
        request: &ApiRequest,
    ) -> Result<Option<ApiResponse>, OpenAuthError> {
        self(error, request)
    }
}
