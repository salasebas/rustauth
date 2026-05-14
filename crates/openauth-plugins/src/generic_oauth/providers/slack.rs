//! Slack generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;
use std::sync::Arc;

pub const PROVIDER_ID: &str = "slack";

pub fn slack(client_id: impl Into<String>, client_secret: impl Into<String>) -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        client_id,
        Some(client_secret),
        "https://slack.com/openid/connect/authorize",
        "https://slack.com/api/openid.connect.token",
    );
    config.user_info_url = Some("https://slack.com/api/openid.connect.userInfo".to_owned());
    config.scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ];
    config.get_user_info = Some(Arc::new(|tokens| Box::pin(super::user_info::slack(tokens))));
    config
}
