use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Request, Uri};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use rustauth::api::RequestBaseUrl;
use rustauth::auth::oauth::OAuthBaseUrlOverride;
use rustauth::error::RustAuthError;
use rustauth::utils::host::is_loopback_host;
use rustauth::utils::url::{is_valid_forwarded_host, is_valid_forwarded_proto};
use rustauth::RustAuth;

use crate::error::{internal_error_response, RustAuthAxumError};
use crate::request::to_api_request;
use crate::response::from_api_response;
use crate::RustAuthAxumOptions;

#[derive(Clone)]
struct RustAuthAxumState {
    auth: Arc<RustAuth>,
    options: RustAuthAxumOptions,
}

/// Convenience extension methods for mounting RustAuth into Axum.
///
/// Implemented for [`RustAuth`] and [`Arc<RustAuth>`](rustauth::RustAuth).
pub trait RustAuthAxumExt {
    /// Return unmounted RustAuth routes for callers that want to nest manually.
    fn mount_routes(&self, options: RustAuthAxumOptions) -> Result<Router, RustAuthAxumError>;

    /// Mount RustAuth nested at `RustAuthOptions.base_path`, defaulting to `/api/auth`.
    fn mount_at_base_path(&self, options: RustAuthAxumOptions)
        -> Result<Router, RustAuthAxumError>;
}

impl RustAuthAxumExt for RustAuth {
    fn mount_routes(&self, options: RustAuthAxumOptions) -> Result<Router, RustAuthAxumError> {
        routes_from_shared(Arc::new(self.clone()), options)
    }

    fn mount_at_base_path(
        &self,
        options: RustAuthAxumOptions,
    ) -> Result<Router, RustAuthAxumError> {
        mount_router_shared(Arc::new(self.clone()), options)
    }
}

impl RustAuthAxumExt for Arc<RustAuth> {
    fn mount_routes(&self, options: RustAuthAxumOptions) -> Result<Router, RustAuthAxumError> {
        routes_from_shared(Arc::clone(self), options)
    }

    fn mount_at_base_path(
        &self,
        options: RustAuthAxumOptions,
    ) -> Result<Router, RustAuthAxumError> {
        mount_router_shared(Arc::clone(self), options)
    }
}

fn mount_router_shared(
    auth: Arc<RustAuth>,
    options: RustAuthAxumOptions,
) -> Result<Router, RustAuthAxumError> {
    validate_base_url_matches_base_path(auth.as_ref())?;
    let base_path = normalize_base_path(&auth.context().base_path)?;
    if base_path == "/" {
        return routes_from_shared(auth, options);
    }
    Ok(Router::new().nest(&base_path, routes_from_shared(auth, options)?))
}

/// Validate that `RustAuthOptions::base_url` and `base_path` are consistent.
///
/// Call this before manually nesting [`RustAuthAxumExt::mount_routes`] if you
/// bypass the fallible mount helpers.
pub fn validate_mount_config(auth: &RustAuth) -> Result<(), RustAuthAxumError> {
    validate_base_url_matches_base_path(auth)
}

fn routes_from_shared(
    auth: Arc<RustAuth>,
    options: RustAuthAxumOptions,
) -> Result<Router, RustAuthAxumError> {
    validate_mount_config(auth.as_ref())?;
    Ok(Router::new()
        .route("/", any(route_handler))
        .route("/{*path}", any(route_handler))
        .with_state(RustAuthAxumState { auth, options }))
}

/// Handle a single Axum request through RustAuth.
pub async fn handle(
    auth: &RustAuth,
    options: RustAuthAxumOptions,
    request: Request<Body>,
) -> axum::response::Response {
    match to_api_request(request, options).await {
        Ok(mut request) => {
            maybe_insert_base_url(auth, &mut request, options);
            match auth.handler_async(request).await {
                Ok(response) => from_api_response(response),
                Err(error) => {
                    log_internal_error(auth, &error);
                    internal_error_response()
                }
            }
        }
        Err(response) => response,
    }
}

async fn route_handler(
    State(state): State<RustAuthAxumState>,
    request: Request<Body>,
) -> impl IntoResponse {
    handle(state.auth.as_ref(), state.options, request).await
}

fn validate_base_url_matches_base_path(auth: &RustAuth) -> Result<(), RustAuthAxumError> {
    let base_url = auth.context().base_url.as_str();
    if base_url.is_empty() {
        return Ok(());
    }

    let parsed = url::Url::parse(base_url)
        .map_err(|_| RustAuthAxumError::InvalidBaseUrl(base_url.to_owned()))?;
    let url_path = trim_path_suffix(parsed.path());
    let base_path = trim_path_suffix(&auth.context().base_path);
    if url_path == base_path {
        return Ok(());
    }

    Err(RustAuthAxumError::InconsistentBaseUrlPath {
        url_path,
        base_path,
    })
}

fn trim_path_suffix(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn normalize_base_path(base_path: &str) -> Result<String, RustAuthAxumError> {
    if base_path.is_empty() {
        return Ok("/".to_owned());
    }
    if !is_valid_base_path(base_path) {
        return Err(RustAuthAxumError::InvalidBasePath(base_path.to_owned()));
    }

    let trimmed = base_path.trim_end_matches('/');
    if trimmed.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(trimmed.to_owned())
    }
}

fn maybe_insert_base_url(
    auth: &RustAuth,
    request: &mut rustauth::api::ApiRequest,
    options: RustAuthAxumOptions,
) {
    if !options.infer_base_url_from_request
        || !auth.context().base_url.is_empty()
        || request.extensions().get::<OAuthBaseUrlOverride>().is_some()
    {
        return;
    }

    if let Some(base_url) = infer_base_url(
        request.headers(),
        request.uri(),
        &auth.context().base_path,
        options.trust_proxy_headers_for_base_url,
    ) {
        request
            .extensions_mut()
            .insert(RequestBaseUrl(base_url.clone()));
        request
            .extensions_mut()
            .insert(OAuthBaseUrlOverride(base_url));
    }
}

fn infer_base_url(
    headers: &HeaderMap,
    uri: &Uri,
    base_path: &str,
    trust_proxy_headers: bool,
) -> Option<String> {
    let origin = if trust_proxy_headers {
        forwarded_origin(headers)
    } else {
        None
    }
    .or_else(|| uri_origin(uri))
    .or_else(|| host_header_origin(headers))?;
    Some(with_base_path(origin, base_path))
}

fn forwarded_origin(headers: &HeaderMap) -> Option<String> {
    let host = header_str(headers, "x-forwarded-host")?;
    let proto = header_str(headers, "x-forwarded-proto")?;
    if !is_valid_forwarded_host(host) || !is_valid_forwarded_proto(proto) {
        return None;
    }
    Some(format!("{}://{}", proto.to_ascii_lowercase(), host))
}

fn uri_origin(uri: &Uri) -> Option<String> {
    let scheme = uri.scheme_str()?;
    if !is_valid_forwarded_proto(scheme) {
        return None;
    }
    let authority = uri.authority()?.as_str();
    if !is_valid_forwarded_host(authority) {
        return None;
    }
    Some(format!("{}://{}", scheme, authority))
}

fn host_header_origin(headers: &HeaderMap) -> Option<String> {
    let host = header_str(headers, header::HOST.as_str())?;
    if !is_valid_forwarded_host(host) {
        return None;
    }
    let scheme = if is_loopback_host(host) {
        "http"
    } else {
        "https"
    };
    Some(format!("{scheme}://{host}"))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn with_base_path(mut origin: String, base_path: &str) -> String {
    let base_path = base_path.trim_end_matches('/');
    if !base_path.is_empty() && base_path != "/" {
        origin.push_str(base_path);
    }
    origin
}

fn is_valid_base_path(base_path: &str) -> bool {
    base_path.starts_with('/')
        && !base_path.contains('?')
        && !base_path.contains('#')
        && !base_path.contains('{')
        && !base_path.contains('}')
        && !base_path.contains('*')
}

fn log_internal_error(auth: &RustAuth, error: &RustAuthError) {
    let message = error.to_string();
    auth.context()
        .logger
        .error("RustAuth Axum handler failed", &[message.as_str()]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const SECRET: &str = "test-secret-123456789012345678901234";

    #[test]
    fn normalize_base_path_trims_trailing_slashes_except_root() -> Result<(), RustAuthAxumError> {
        assert_eq!(normalize_base_path("")?, "/");
        assert_eq!(normalize_base_path("/")?, "/");
        assert_eq!(normalize_base_path("/api/auth/")?, "/api/auth");
        assert_eq!(normalize_base_path("/api/auth///")?, "/api/auth");
        Ok(())
    }

    #[test]
    fn normalize_base_path_rejects_axum_pattern_syntax_and_non_absolute_paths() {
        for base_path in [
            "api/auth",
            "/api/{auth}",
            "/api/*auth",
            "/api/auth?x=1",
            "/api/auth#x",
        ] {
            assert!(matches!(
                normalize_base_path(base_path),
                Err(RustAuthAxumError::InvalidBasePath(_))
            ));
        }
    }

    #[test]
    fn infer_base_url_rejects_malicious_forwarded_headers_and_falls_back_to_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("javascript:alert(1)"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        headers.insert(header::HOST, HeaderValue::from_static("app.example.com"));

        let base = infer_base_url(
            &headers,
            &Uri::from_static("/api/auth/ok"),
            "/api/auth",
            true,
        );
        assert_eq!(base.as_deref(), Some("https://app.example.com/api/auth"));
    }

    #[test]
    fn infer_base_url_uses_forwarded_headers_when_trusted_and_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("public.example.com"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert(header::HOST, HeaderValue::from_static("internal.local"));

        let base = infer_base_url(&headers, &Uri::from_static("/ok"), "/api/auth", true);
        assert_eq!(base.as_deref(), Some("https://public.example.com/api/auth"));
    }

    #[test]
    fn infer_base_url_uses_absolute_request_uri_origin() {
        let headers = HeaderMap::new();
        let uri = Uri::from_static("https://app.example.com/api/auth/sign-in/social");
        let base = infer_base_url(&headers, &uri, "/api/auth", false);
        assert_eq!(base.as_deref(), Some("https://app.example.com/api/auth"));
    }

    #[test]
    fn infer_base_url_uses_http_for_loopback_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:3000"));

        let base = infer_base_url(&headers, &Uri::from_static("/ok"), "/api/auth", false);
        assert_eq!(base.as_deref(), Some("http://127.0.0.1:3000/api/auth"));
    }

    #[tokio::test]
    async fn validate_base_url_accepts_matching_pathname() -> Result<(), RustAuthError> {
        let auth = RustAuth::builder()
            .secret(SECRET)
            .base_path("/api/auth")
            .base_url("http://localhost:3000/api/auth/")
            .build()
            .await?;
        assert!(validate_base_url_matches_base_path(&auth).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn validate_base_url_rejects_mismatched_pathname() -> Result<(), RustAuthError> {
        let auth = RustAuth::builder()
            .secret(SECRET)
            .base_path("/api/auth")
            .base_url("http://localhost:3000/wrong")
            .build()
            .await?;
        assert!(matches!(
            validate_base_url_matches_base_path(&auth),
            Err(RustAuthAxumError::InconsistentBaseUrlPath { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn validate_base_url_rejects_invalid_absolute_url() -> Result<(), RustAuthError> {
        let auth = RustAuth::builder()
            .secret(SECRET)
            .base_path("/api/auth")
            .base_url("not-a-url")
            .build()
            .await?;
        assert!(matches!(
            validate_base_url_matches_base_path(&auth),
            Err(RustAuthAxumError::InvalidBaseUrl(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn mount_routes_rejects_mismatched_base_url_path() -> Result<(), RustAuthError> {
        let auth = Arc::new(
            RustAuth::builder()
                .secret(SECRET)
                .base_path("/api/auth")
                .base_url("http://localhost:3000/wrong")
                .build()
                .await?,
        );
        assert!(matches!(
            auth.mount_routes(RustAuthAxumOptions::default()),
            Err(RustAuthAxumError::InconsistentBaseUrlPath { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn mount_routes_keeps_shared_auth_available() -> Result<(), RustAuthError> {
        let auth = Arc::new(RustAuth::builder().secret(SECRET).build().await?);
        let routes = auth
            .mount_routes(RustAuthAxumOptions::default())
            .map_err(|error| RustAuthError::Api(error.to_string()))?;
        drop(routes);

        assert_eq!(Arc::strong_count(&auth), 1);
        assert!(validate_mount_config(auth.as_ref()).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn axum_state_clones_only_the_shared_auth_pointer() -> Result<(), RustAuthError> {
        let auth = Arc::new(RustAuth::builder().secret(SECRET).build().await?);
        let state = RustAuthAxumState {
            auth: Arc::clone(&auth),
            options: RustAuthAxumOptions::default(),
        };

        let cloned = state.clone();

        assert_eq!(Arc::strong_count(&auth), 3);
        drop(cloned);
        assert_eq!(Arc::strong_count(&auth), 2);
        Ok(())
    }
}
