//! API error handling options (parity with Better Auth `onAPIError`).

use std::fmt;
use std::sync::Arc;

use crate::api::{ApiRequest, ApiResponse};
use crate::error::RustAuthError;

/// Configuration for unhandled API errors.
#[derive(Clone, Default)]
pub struct OnApiErrorOptions {
    /// When true, internal errors propagate instead of returning JSON/redirect responses.
    pub throw: bool,
    /// Default redirect target for OAuth-style error flows.
    pub error_url: Option<String>,
    pub default_error_page: DefaultErrorPage,
    pub on_error: Option<Arc<dyn OnApiErrorHandler>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultErrorPage {
    pub title: String,
    pub heading: String,
    pub message: String,
}

impl Default for DefaultErrorPage {
    fn default() -> Self {
        Self {
            title: "Error".to_owned(),
            heading: "Something went wrong".to_owned(),
            message: "We encountered an unexpected error.".to_owned(),
        }
    }
}

impl DefaultErrorPage {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    #[must_use]
    pub fn heading(mut self, heading: impl Into<String>) -> Self {
        self.heading = heading.into();
        self
    }

    #[must_use]
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }
}

impl fmt::Debug for OnApiErrorOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnApiErrorOptions")
            .field("throw", &self.throw)
            .field("error_url", &self.error_url)
            .field("default_error_page", &self.default_error_page)
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
    pub fn default_error_page(mut self, page: DefaultErrorPage) -> Self {
        self.default_error_page = page;
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
        error: &RustAuthError,
        request: &ApiRequest,
    ) -> Result<Option<ApiResponse>, RustAuthError>;
}

impl<F> OnApiErrorHandler for F
where
    F: Fn(&RustAuthError, &ApiRequest) -> Result<Option<ApiResponse>, RustAuthError>
        + Send
        + Sync
        + 'static,
{
    fn on_error(
        &self,
        error: &RustAuthError,
        request: &ApiRequest,
    ) -> Result<Option<ApiResponse>, RustAuthError> {
        self(error, request)
    }
}
