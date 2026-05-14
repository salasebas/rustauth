//! HubSpot generic OAuth provider helper.

use openauth_oauth::oauth2::ClientAuthentication;
use std::sync::Arc;

use crate::generic_oauth::GenericOAuthConfig;

pub const PROVIDER_ID: &str = "hubspot";

pub fn hubspot(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> GenericOAuthConfig {
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        client_id,
        Some(client_secret),
        "https://app.hubspot.com/oauth/authorize",
        "https://api.hubapi.com/oauth/v1/token",
    );
    config.scopes = vec!["oauth".to_owned()];
    config.authentication = ClientAuthentication::Post;
    config.get_user_info = Some(Arc::new(|tokens| {
        Box::pin(super::user_info::hubspot(tokens))
    }));
    config
}
