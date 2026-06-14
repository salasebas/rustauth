//! Slack generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;
use std::sync::Arc;

pub const PROVIDER_ID: &str = "slack";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackOptions {
    pub base: super::BaseOAuthProviderOptions,
}

pub fn slack(options: SlackOptions) -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        "",
        None::<String>,
        "https://slack.com/openid/connect/authorize",
        "https://slack.com/api/openid.connect.token",
    );
    config.user_info_url = Some("https://slack.com/api/openid.connect.userInfo".to_owned());
    super::apply_base_options(
        &mut config,
        options.base,
        vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ],
    );
    config.get_user_info = Some(Arc::new(|tokens| Box::pin(super::user_info::slack(tokens))));
    config
}
