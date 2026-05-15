//! Microsoft Entra ID generic OAuth provider helper.

use crate::generic_oauth::GenericOAuthConfig;
use std::sync::Arc;

pub const PROVIDER_ID: &str = "microsoft-entra-id";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrosoftEntraIdOptions {
    pub base: super::BaseOAuthProviderOptions,
    pub tenant_id: String,
}

pub fn microsoft_entra_id(options: MicrosoftEntraIdOptions) -> GenericOAuthConfig {
    let tenant_id = options.tenant_id;
    let mut config = GenericOAuthConfig::new(
        PROVIDER_ID,
        "",
        None::<String>,
        format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"),
        format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"),
    );
    config.user_info_url = Some("https://graph.microsoft.com/oidc/userinfo".to_owned());
    super::apply_base_options(
        &mut config,
        options.base,
        vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
        ],
    );
    config.get_user_info = Some(Arc::new(|tokens| {
        Box::pin(super::user_info::microsoft_entra_id(tokens))
    }));
    config
}
