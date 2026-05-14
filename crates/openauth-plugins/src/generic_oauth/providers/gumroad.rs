//! Gumroad generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;

pub const PROVIDER_ID: &str = "gumroad";

pub fn gumroad(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        client_id,
        Some(client_secret),
        "https://gumroad.com/oauth/authorize",
        "https://api.gumroad.com/oauth/token",
    );
    config.user_info_url = Some("https://api.gumroad.com/v2/user".to_owned());
    config.scopes = vec!["view_profile".to_owned()];
    config
}
