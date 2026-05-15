//! LINE generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;
use std::sync::Arc;

pub const PROVIDER_ID: &str = "line";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineOptions {
    pub base: super::BaseOAuthProviderOptions,
    pub provider_id: Option<String>,
}

pub fn line(options: LineOptions) -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        options
            .provider_id
            .unwrap_or_else(|| PROVIDER_ID.to_owned()),
        "",
        None::<String>,
        "https://access.line.me/oauth2/v2.1/authorize",
        "https://api.line.me/oauth2/v2.1/token",
    );
    config.user_info_url = Some("https://api.line.me/oauth2/v2.1/userinfo".to_owned());
    super::apply_base_options(
        &mut config,
        options.base,
        vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ],
    );
    config.get_user_info = Some(Arc::new(|tokens| Box::pin(super::user_info::line(tokens))));
    config
}
