//! Okta generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;

pub const PROVIDER_ID: &str = "okta";

pub fn okta(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
    issuer: impl AsRef<str>,
) -> GenericOAuthConfig {
    let issuer = issuer.as_ref().trim_end_matches('/');
    let mut config = GenericOAuthConfig::discovery(
        PROVIDER_ID,
        client_id,
        Some(client_secret),
        format!("{issuer}/.well-known/openid-configuration"),
    );
    config.scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ];
    config
}
