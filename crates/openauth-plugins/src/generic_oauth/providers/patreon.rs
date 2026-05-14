//! Patreon generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;
use std::sync::Arc;

pub const PROVIDER_ID: &str = "patreon";

pub fn patreon(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        client_id,
        Some(client_secret),
        "https://www.patreon.com/oauth2/authorize",
        "https://www.patreon.com/api/oauth2/token",
    );
    config.user_info_url = Some(
        "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified"
            .to_owned(),
    );
    config.scopes = vec!["identity[email]".to_owned()];
    config.get_user_info = Some(Arc::new(|tokens| {
        Box::pin(super::user_info::patreon(tokens))
    }));
    config
}
