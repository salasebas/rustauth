use std::fmt;
use std::sync::Arc;

use http::Request;

use crate::error::RustAuthError;

/// Request-aware trusted origin provider.
pub trait TrustedOriginsProvider: Send + Sync + 'static {
    fn trusted_origins(
        &self,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<Vec<String>, RustAuthError>;
}

impl<F> TrustedOriginsProvider for F
where
    F: for<'a> Fn(Option<&'a Request<Vec<u8>>>) -> Result<Vec<String>, RustAuthError>
        + Send
        + Sync
        + 'static,
{
    fn trusted_origins(
        &self,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<Vec<String>, RustAuthError> {
        self(request)
    }
}

#[derive(Clone, Default)]
pub enum TrustedOriginOptions {
    #[default]
    None,
    Static(Vec<String>),
    Dynamic {
        origins: Vec<String>,
        provider: Arc<dyn TrustedOriginsProvider>,
    },
}

impl TrustedOriginOptions {
    pub fn dynamic<P>(provider: P) -> Self
    where
        P: TrustedOriginsProvider,
    {
        Self::Dynamic {
            origins: Vec::new(),
            provider: Arc::new(provider),
        }
    }

    pub fn dynamic_with_static<P>(origins: Vec<String>, provider: P) -> Self
    where
        P: TrustedOriginsProvider,
    {
        Self::Dynamic {
            origins,
            provider: Arc::new(provider),
        }
    }

    pub fn as_static_slice(&self) -> &[String] {
        match self {
            Self::None => &[],
            Self::Static(origins) => origins,
            Self::Dynamic { origins, .. } => origins,
        }
    }

    pub fn provider(&self) -> Option<&dyn TrustedOriginsProvider> {
        match self {
            Self::Dynamic { provider, .. } => Some(provider.as_ref()),
            Self::None | Self::Static(_) => None,
        }
    }
}

impl fmt::Debug for TrustedOriginOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::Static(origins) => formatter.debug_tuple("Static").field(origins).finish(),
            Self::Dynamic { origins, .. } => formatter
                .debug_struct("Dynamic")
                .field("origins", origins)
                .field("provider", &"<request-aware>")
                .finish(),
        }
    }
}
