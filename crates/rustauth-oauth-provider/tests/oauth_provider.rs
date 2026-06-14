#[path = "oauth_provider/authorization.rs"]
mod authorization;
#[path = "oauth_provider/clients.rs"]
mod clients;
#[path = "oauth_provider/common.rs"]
mod common;
#[path = "oauth_provider/config_metadata.rs"]
mod config_metadata;
#[path = "oauth_provider/consent.rs"]
mod consent;
#[cfg(feature = "mcp-client")]
#[path = "oauth_provider/mcp_client.rs"]
mod mcp_client;
#[path = "oauth_provider/mcp_metadata.rs"]
mod mcp_metadata;
#[path = "oauth_provider/oidc_misc.rs"]
mod oidc_misc;
#[path = "oauth_provider/tokens.rs"]
mod tokens;
