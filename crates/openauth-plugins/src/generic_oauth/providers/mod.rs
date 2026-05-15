//! Generic OAuth provider helpers.

pub mod auth0;
pub mod gumroad;
pub mod hubspot;
pub mod keycloak;
pub mod line;
pub mod microsoft_entra_id;
pub mod okta;
pub mod patreon;
pub mod slack;
mod user_info;

use crate::generic_oauth::GenericOAuthConfig;

pub const PROVIDER_IDS: &[&str] = &[
    "auth0",
    "gumroad",
    "hubspot",
    "keycloak",
    "line",
    "microsoft-entra-id",
    "okta",
    "patreon",
    "slack",
];

pub use auth0::{auth0, Auth0Options};
pub use gumroad::{gumroad, GumroadOptions};
pub use hubspot::{hubspot, HubSpotOptions};
pub use keycloak::{keycloak, KeycloakOptions};
pub use line::{line, LineOptions};
pub use microsoft_entra_id::{microsoft_entra_id, MicrosoftEntraIdOptions};
pub use okta::{okta, OktaOptions};
pub use patreon::{patreon, PatreonOptions};
pub use slack::{slack, SlackOptions};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaseOAuthProviderOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub redirect_uri: Option<String>,
    pub pkce: bool,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub override_user_info: bool,
}

pub(crate) fn apply_base_options(
    config: &mut GenericOAuthConfig,
    base: BaseOAuthProviderOptions,
    default_scopes: Vec<String>,
) {
    config.client_id = base.client_id;
    config.client_secret = base.client_secret;
    config.scopes = base.scopes.unwrap_or(default_scopes);
    config.redirect_uri = base.redirect_uri;
    config.pkce = base.pkce;
    config.disable_implicit_sign_up = base.disable_implicit_sign_up;
    config.disable_sign_up = base.disable_sign_up;
    config.override_user_info = base.override_user_info;
}
