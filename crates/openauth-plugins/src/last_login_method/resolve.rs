use openauth_core::api::ApiRequest;
use openauth_core::context::AuthContext;

/// Request data used to resolve a login method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginMethodContext {
    path: String,
}

impl LoginMethodContext {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    pub fn from_request(context: &AuthContext, request: &ApiRequest) -> Self {
        Self::new(auth_path(context, request))
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

pub fn default_login_method(context: &LoginMethodContext) -> Option<String> {
    let path = context.path();
    if path.starts_with("/callback/") || path.starts_with("/oauth2/callback/") {
        return path.rsplit('/').next().map(str::to_owned);
    }
    if path == "/sign-in/email" || path == "/sign-up/email" {
        return Some("email".to_owned());
    }
    if path.contains("siwe") {
        return Some("siwe".to_owned());
    }
    if path.contains("/passkey/verify-authentication") {
        return Some("passkey".to_owned());
    }
    if path.starts_with("/magic-link/verify") {
        return Some("magic-link".to_owned());
    }
    None
}

fn auth_path(context: &AuthContext, request: &ApiRequest) -> String {
    let path = request.uri().path();
    let base_path = context.base_path.trim_end_matches('/');
    path.strip_prefix(base_path)
        .filter(|value| !value.is_empty())
        .unwrap_or(path)
        .to_owned()
}
