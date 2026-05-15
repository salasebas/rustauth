//! Auth0 generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;

pub const PROVIDER_ID: &str = "auth0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth0Options {
    pub base: super::BaseOAuthProviderOptions,
    pub domain: String,
}

pub fn auth0(options: Auth0Options) -> GenericOAuthConfig {
    let domain = options
        .domain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let mut config = GenericOAuthConfig::discovery(
        PROVIDER_ID,
        "",
        None::<String>,
        format!("https://{domain}/.well-known/openid-configuration"),
    );
    super::apply_base_options(&mut config, options.base, openid_scopes());
    config
}

fn openid_scopes() -> Vec<String> {
    vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ]
}
