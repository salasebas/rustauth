use std::sync::Arc;

use rustauth::db::MemoryAdapter;
use rustauth::error::RustAuthError;
use rustauth::options::{
    AdvancedOptions, EmailPasswordOptions, RateLimitOptions, RustAuthOptions,
};
use rustauth::RustAuth;
use time::ext::NumericalDuration;

pub const AUTH_BASE_PATH: &str = "/api/auth";
pub const DEFAULT_SECRET: &str = "rustauth-example-dev-secret-at-least-32-chars";
pub const DEFAULT_BASE_URL: &str = "http://127.0.0.1:8080/api/auth";

pub async fn build_auth() -> Result<Arc<RustAuth>, RustAuthError> {
    let options = rustauth_core::test_utils::apply_fast_password_defaults(
        RustAuthOptions::new()
            .base_url(DEFAULT_BASE_URL)
            .base_path(AUTH_BASE_PATH)
            .email_password(EmailPasswordOptions::new().enabled(true))
            .rate_limit(
                RateLimitOptions::memory()
                    .enabled(true)
                    .window(60.seconds())
                    .max(100),
            )
            .advanced(
                AdvancedOptions::new()
                    .disable_csrf_check(true)
                    .disable_origin_check(true),
            ),
    );

    let auth = RustAuth::builder()
        .secret(DEFAULT_SECRET)
        .options(options)
        .adapter(MemoryAdapter::new())
        .build()
        .await?;

    Ok(Arc::new(auth))
}
