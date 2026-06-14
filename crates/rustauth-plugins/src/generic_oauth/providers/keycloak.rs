//! Keycloak generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;

pub const PROVIDER_ID: &str = "keycloak";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeycloakOptions {
    pub base: super::BaseOAuthProviderOptions,
    pub issuer: String,
}

pub fn keycloak(options: KeycloakOptions) -> GenericOAuthConfig {
    let issuer = options.issuer.trim_end_matches('/');
    let mut config = GenericOAuthConfig::discovery(
        PROVIDER_ID,
        "",
        None::<String>,
        format!("{issuer}/.well-known/openid-configuration"),
    );
    super::apply_base_options(
        &mut config,
        options.base,
        vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ],
    );
    config
}
