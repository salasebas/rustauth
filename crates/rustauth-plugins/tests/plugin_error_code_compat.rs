//! Regression: passkey, captcha, and generic-oauth register together after error-code namespacing.

use std::sync::Arc;

use rustauth_core::context::create_auth_context_with_adapter;
use rustauth_core::db::MemoryAdapter;
use rustauth_core::options::RustAuthOptions;
use rustauth_core::plugin::AuthPlugin;
use rustauth_passkey::{passkey, PasskeyOptions};
use rustauth_plugins::captcha::{captcha, CaptchaOptions};
use rustauth_plugins::generic_oauth::{generic_oauth, GenericOAuthOptions};

#[test]
fn passkey_captcha_and_generic_oauth_register_without_error_code_conflicts(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugins: Vec<AuthPlugin> = vec![
        captcha(CaptchaOptions::cloudflare_turnstile("secret").endpoints(["/sign-up"]))?,
        passkey(PasskeyOptions::default()),
        generic_oauth(GenericOAuthOptions::default()),
    ];

    let context = create_auth_context_with_adapter(
        RustAuthOptions {
            base_url: Some("http://127.0.0.1:3000/api/auth".to_owned()),
            plugins,
            ..RustAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()),
    )?;

    assert!(context
        .plugin_error_codes
        .contains_key("PASSKEY_SESSION_REQUIRED"));
    assert!(context
        .plugin_error_codes
        .contains_key("CAPTCHA_UNKNOWN_ERROR"));
    assert!(context
        .plugin_error_codes
        .contains_key("GENERIC_OAUTH_SESSION_REQUIRED"));
    Ok(())
}
