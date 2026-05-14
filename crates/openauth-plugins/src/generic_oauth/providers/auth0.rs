//! Auth0 generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;

pub const PROVIDER_ID: &str = "auth0";

pub fn auth0(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
    domain: impl AsRef<str>,
) -> GenericOAuthConfig {
    let domain = domain
        .as_ref()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let mut config = GenericOAuthConfig::discovery(
        PROVIDER_ID,
        client_id,
        Some(client_secret),
        format!("https://{domain}/.well-known/openid-configuration"),
    );
    config.scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ];
    config
}
