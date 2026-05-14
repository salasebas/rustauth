//! LINE generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;
use std::sync::Arc;

pub const PROVIDER_ID: &str = "line";

pub fn line(client_id: impl Into<String>, client_secret: impl Into<String>) -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        client_id,
        Some(client_secret),
        "https://access.line.me/oauth2/v2.1/authorize",
        "https://api.line.me/oauth2/v2.1/token",
    );
    config.user_info_url = Some("https://api.line.me/oauth2/v2.1/userinfo".to_owned());
    config.scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ];
    config.get_user_info = Some(Arc::new(|tokens| Box::pin(super::user_info::line(tokens))));
    config
}
