//! Microsoft Entra ID generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;

pub const PROVIDER_ID: &str = "microsoft-entra-id";

pub fn microsoft_entra_id(
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
    tenant_id: impl AsRef<str>,
) -> GenericOAuthConfig {
    let tenant_id = tenant_id.as_ref();
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        client_id,
        Some(client_secret),
        format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"),
        format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"),
    );
    config.user_info_url = Some("https://graph.microsoft.com/oidc/userinfo".to_owned());
    config.scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ];
    config
}
