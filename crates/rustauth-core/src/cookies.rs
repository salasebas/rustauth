//! Cookie naming, parsing, and chunking helpers.

mod cache;
mod chunked;
mod config;
mod parse;
mod session;
mod signing;
mod types;

pub use crate::options::CookieCacheStrategy;
pub use crate::options::CookieConfig;

pub use cache::{get_cookie_cache, set_cookie_cache, CookieCachePayload};
pub use chunked::ChunkedCookieStore;
pub use config::{create_auth_cookie, get_cookies};
pub use parse::{parse_cookies, parse_set_cookie_header, to_cookie_options};
pub use session::{delete_session_cookie, expire_cookie, get_session_cookie, set_session_cookie};
pub use signing::{sign_cookie_value, verify_cookie_value};
pub use types::{
    strip_secure_cookie_prefix, AuthCookie, AuthCookies, Cookie, CookieOptions, ParsedCookie,
    SessionCookieOptions, HOST_COOKIE_PREFIX, SECURE_COOKIE_PREFIX,
};
