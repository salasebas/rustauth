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

pub use auth0::auth0;
pub use gumroad::gumroad;
pub use hubspot::hubspot;
pub use keycloak::keycloak;
pub use line::line;
pub use microsoft_entra_id::microsoft_entra_id;
pub use okta::okta;
pub use patreon::patreon;
pub use slack::slack;
