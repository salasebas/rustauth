use crate::env::is_production;
use crate::error::OpenAuthError;
use crate::options::{CookieAttributesOverride, OpenAuthOptions};

use super::types::{AuthCookie, AuthCookies, CookieOptions, SECURE_COOKIE_PREFIX};

pub fn get_cookies(options: &OpenAuthOptions) -> Result<AuthCookies, OpenAuthError> {
    let session_max_age = options.session.expires_in.unwrap_or(60 * 60 * 24 * 7);
    let cache_max_age = options.session.cookie_cache.max_age.unwrap_or(60 * 5);

    Ok(AuthCookies {
        session_token: create_auth_cookie(options, "session_token", Some(session_max_age))?,
        session_data: create_auth_cookie(options, "session_data", Some(cache_max_age))?,
        account_data: create_auth_cookie(options, "account_data", Some(cache_max_age))?,
        dont_remember_token: create_auth_cookie(options, "dont_remember", None)?,
    })
}

/// Build a single auth cookie definition using the same name prefixing and
/// attribute merge policy as [`get_cookies`].
///
/// Plugins should route their own security-sensitive cookies (for example the
/// passkey challenge cookie) through this helper so they inherit the configured
/// `cookie_prefix`, secure-name prefix, cross-subdomain `domain`, and
/// `default_cookie_attributes` instead of using a raw, unnamespaced cookie name.
pub fn create_auth_cookie(
    options: &OpenAuthOptions,
    name: &str,
    max_age: Option<u64>,
) -> Result<AuthCookie, OpenAuthError> {
    let secure = resolve_secure(options);
    let secure_prefix = if secure { SECURE_COOKIE_PREFIX } else { "" };
    let prefix = options
        .advanced
        .cookie_prefix
        .as_deref()
        .unwrap_or("open-auth");
    let domain = resolve_domain(options)?;

    Ok(AuthCookie {
        name: format!("{secure_prefix}{prefix}.{name}"),
        attributes: merge_cookie_attributes(
            CookieOptions {
                max_age,
                expires: None,
                domain,
                path: Some("/".to_owned()),
                secure: Some(secure),
                http_only: Some(true),
                same_site: Some("lax".to_owned()),
                partitioned: None,
            },
            &options.advanced.default_cookie_attributes,
        ),
    })
}

fn resolve_secure(options: &OpenAuthOptions) -> bool {
    if let Some(secure) = options.advanced.use_secure_cookies {
        return secure;
    }
    if let Some(base_url) = &options.base_url {
        return base_url.starts_with("https://");
    }
    options.production || is_production()
}

fn resolve_domain(options: &OpenAuthOptions) -> Result<Option<String>, OpenAuthError> {
    let Some(config) = &options.advanced.cross_subdomain_cookies else {
        return Ok(None);
    };
    if !config.enabled {
        return Ok(None);
    }
    if let Some(domain) = &config.domain {
        return Ok(Some(domain.clone()));
    }
    let Some(base_url) = &options.base_url else {
        return Err(OpenAuthError::Cookie(
            "base_url is required when cross-subdomain cookies are enabled".to_owned(),
        ));
    };
    host_from_url(base_url)
        .map(Some)
        .ok_or_else(|| OpenAuthError::Cookie("could not resolve cookie domain".to_owned()))
}

fn host_from_url(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let host = rest.split('/').next().unwrap_or(rest);
    let host = host.split(':').next().unwrap_or(host);
    (!host.is_empty()).then(|| host.to_owned())
}

fn merge_cookie_attributes(
    mut base: CookieOptions,
    override_attrs: &CookieAttributesOverride,
) -> CookieOptions {
    if override_attrs.domain.is_some() {
        base.domain.clone_from(&override_attrs.domain);
    }
    if override_attrs.path.is_some() {
        base.path.clone_from(&override_attrs.path);
    }
    if override_attrs.secure.is_some() {
        base.secure = override_attrs.secure;
    }
    if override_attrs.http_only.is_some() {
        base.http_only = override_attrs.http_only;
    }
    if override_attrs.same_site.is_some() {
        base.same_site.clone_from(&override_attrs.same_site);
    }
    if override_attrs.max_age.is_some() {
        base.max_age = override_attrs.max_age;
    }
    if override_attrs.partitioned.is_some() {
        base.partitioned = override_attrs.partitioned;
    }
    base
}

pub(super) fn merge_options(mut base: CookieOptions, overrides: CookieOptions) -> CookieOptions {
    if overrides.max_age.is_some() {
        base.max_age = overrides.max_age;
    }
    if overrides.expires.is_some() {
        base.expires = overrides.expires;
    }
    if overrides.domain.is_some() {
        base.domain = overrides.domain;
    }
    if overrides.path.is_some() {
        base.path = overrides.path;
    }
    if overrides.secure.is_some() {
        base.secure = overrides.secure;
    }
    if overrides.http_only.is_some() {
        base.http_only = overrides.http_only;
    }
    if overrides.same_site.is_some() {
        base.same_site = overrides.same_site;
    }
    if overrides.partitioned.is_some() {
        base.partitioned = overrides.partitioned;
    }
    base
}
