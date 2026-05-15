use openauth_core::auth::oauth::{OAuthAccountInput, OAuthUserInfo};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OAuthProxyStatePackage {
    pub state: String,
    pub state_cookie: String,
    pub is_oauth_proxy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PassthroughPayload {
    pub user_info: OAuthUserInfo,
    pub account: OAuthAccountInput,
    pub state: String,
    pub callback_url: String,
    pub new_user_url: Option<String>,
    pub error_url: Option<String>,
    pub disable_sign_up: bool,
    pub timestamp: i64,
}

impl PassthroughPayload {
    pub(crate) fn has_required_fields(&self) -> bool {
        !self.user_info.id.is_empty()
            && !self.user_info.email.is_empty()
            && !self.account.provider_id.is_empty()
            && !self.account.account_id.is_empty()
            && !self.callback_url.is_empty()
            && self.timestamp > 0
    }
}
