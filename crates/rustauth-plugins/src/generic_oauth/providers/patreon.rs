//! Patreon generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;
use std::sync::Arc;

pub const PROVIDER_ID: &str = "patreon";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatreonOptions {
    pub base: super::BaseOAuthProviderOptions,
}

pub fn patreon(options: PatreonOptions) -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        "",
        None::<String>,
        "https://www.patreon.com/oauth2/authorize",
        "https://www.patreon.com/api/oauth2/token",
    );
    config.user_info_url = Some(
        "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified"
            .to_owned(),
    );
    super::apply_base_options(
        &mut config,
        options.base,
        vec!["identity[email]".to_owned()],
    );
    config.get_user_info = Some(Arc::new(|tokens| {
        Box::pin(super::user_info::patreon(tokens))
    }));
    config
}
