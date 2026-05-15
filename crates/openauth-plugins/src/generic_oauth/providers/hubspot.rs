//! HubSpot generic OAuth provider helper.

use openauth_oauth::oauth2::ClientAuthentication;
use std::sync::Arc;

use crate::generic_oauth::GenericOAuthConfig;

pub const PROVIDER_ID: &str = "hubspot";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubSpotOptions {
    pub base: super::BaseOAuthProviderOptions,
}

pub fn hubspot(options: HubSpotOptions) -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        "",
        None::<String>,
        "https://app.hubspot.com/oauth/authorize",
        "https://api.hubapi.com/oauth/v1/token",
    );
    super::apply_base_options(&mut config, options.base, vec!["oauth".to_owned()]);
    config.authentication = ClientAuthentication::Post;
    config.get_user_info = Some(Arc::new(|tokens| {
        Box::pin(super::user_info::hubspot(tokens))
    }));
    config
}
