//! Gumroad generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;
use std::sync::Arc;

pub const PROVIDER_ID: &str = "gumroad";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GumroadOptions {
    pub base: super::BaseOAuthProviderOptions,
}

pub fn gumroad(options: GumroadOptions) -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        "",
        None::<String>,
        "https://gumroad.com/oauth/authorize",
        "https://api.gumroad.com/oauth/token",
    );
    config.user_info_url = Some("https://api.gumroad.com/v2/user".to_owned());
    super::apply_base_options(&mut config, options.base, vec!["view_profile".to_owned()]);
    config.get_user_info = Some(Arc::new(|tokens| {
        Box::pin(super::user_info::gumroad(tokens))
    }));
    config
}
