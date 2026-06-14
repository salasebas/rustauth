pub const SECURE_COOKIE_PREFIX: &str = "__Secure-";
pub const HOST_COOKIE_PREFIX: &str = "__Host-";
pub const DEFAULT_COOKIE_PREFIX: &str = "rustauth";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub attributes: CookieOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCookie {
    pub name: String,
    pub attributes: CookieOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCookies {
    pub session_token: AuthCookie,
    pub session_data: AuthCookie,
    pub account_data: AuthCookie,
    pub dont_remember_token: AuthCookie,
    pub oauth_state: AuthCookie,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CookieOptions {
    pub max_age: Option<u64>,
    pub expires: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<String>,
    pub partitioned: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedCookie {
    pub value: String,
    pub max_age: Option<u64>,
    pub expires: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<String>,
    pub partitioned: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionCookieOptions {
    pub dont_remember: bool,
    pub overrides: CookieOptions,
}

pub fn strip_secure_cookie_prefix(cookie_name: &str) -> &str {
    cookie_name
        .strip_prefix(SECURE_COOKIE_PREFIX)
        .or_else(|| cookie_name.strip_prefix(HOST_COOKIE_PREFIX))
        .unwrap_or(cookie_name)
}
