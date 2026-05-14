use crate::utils::ip::Ipv6Subnet;

use super::cookies::CookieConfig;

/// Advanced configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvancedOptions {
    pub use_secure_cookies: Option<bool>,
    pub cookie_prefix: Option<String>,
    pub cross_subdomain_cookies: Option<CookieConfig>,
    pub default_cookie_attributes: CookieAttributesOverride,
    pub disable_csrf_check: bool,
    pub disable_origin_check: bool,
    pub skip_trailing_slashes: bool,
    pub ip_address: IpAddressOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressOptions {
    pub headers: Vec<String>,
    pub disable_ip_tracking: bool,
    pub ipv6_subnet: Ipv6Subnet,
}

impl Default for IpAddressOptions {
    fn default() -> Self {
        Self {
            headers: vec!["x-forwarded-for".to_owned()],
            disable_ip_tracking: false,
            ipv6_subnet: Ipv6Subnet::Prefix64,
        }
    }
}

/// User-supplied cookie attribute defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CookieAttributesOverride {
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<String>,
    pub max_age: Option<u64>,
    pub partitioned: Option<bool>,
}
