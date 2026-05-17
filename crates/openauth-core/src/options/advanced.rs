use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::utils::ip::Ipv6Subnet;

use super::cookies::CookieConfig;

/// Advanced configuration.
pub type BackgroundTaskFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

pub trait BackgroundTaskRunner: Send + Sync + 'static {
    fn spawn(&self, task: BackgroundTaskFuture);
}

#[derive(Clone, Default)]
pub struct AdvancedOptions {
    pub use_secure_cookies: Option<bool>,
    pub cookie_prefix: Option<String>,
    pub cross_subdomain_cookies: Option<CookieConfig>,
    pub default_cookie_attributes: CookieAttributesOverride,
    pub disable_csrf_check: bool,
    pub disable_origin_check: bool,
    pub skip_trailing_slashes: bool,
    pub ip_address: IpAddressOptions,
    pub background_tasks: Option<Arc<dyn BackgroundTaskRunner>>,
}

impl AdvancedOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn use_secure_cookies(mut self, enabled: bool) -> Self {
        self.use_secure_cookies = Some(enabled);
        self
    }

    #[must_use]
    pub fn cookie_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.cookie_prefix = Some(prefix.into());
        self
    }

    #[must_use]
    pub fn cross_subdomain_cookies(mut self, config: CookieConfig) -> Self {
        self.cross_subdomain_cookies = Some(config);
        self
    }

    #[must_use]
    pub fn default_cookie_attributes(mut self, attributes: CookieAttributesOverride) -> Self {
        self.default_cookie_attributes = attributes;
        self
    }

    #[must_use]
    pub fn disable_csrf_check(mut self, disabled: bool) -> Self {
        self.disable_csrf_check = disabled;
        self
    }

    #[must_use]
    pub fn disable_origin_check(mut self, disabled: bool) -> Self {
        self.disable_origin_check = disabled;
        self
    }

    #[must_use]
    pub fn skip_trailing_slashes(mut self, enabled: bool) -> Self {
        self.skip_trailing_slashes = enabled;
        self
    }

    #[must_use]
    pub fn ip_address(mut self, ip_address: IpAddressOptions) -> Self {
        self.ip_address = ip_address;
        self
    }

    #[must_use]
    pub fn background_tasks(mut self, runner: Arc<dyn BackgroundTaskRunner>) -> Self {
        self.background_tasks = Some(runner);
        self
    }
}

impl std::fmt::Debug for AdvancedOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdvancedOptions")
            .field("use_secure_cookies", &self.use_secure_cookies)
            .field("cookie_prefix", &self.cookie_prefix)
            .field("cross_subdomain_cookies", &self.cross_subdomain_cookies)
            .field("default_cookie_attributes", &self.default_cookie_attributes)
            .field("disable_csrf_check", &self.disable_csrf_check)
            .field("disable_origin_check", &self.disable_origin_check)
            .field("skip_trailing_slashes", &self.skip_trailing_slashes)
            .field("ip_address", &self.ip_address)
            .field(
                "background_tasks",
                &self.background_tasks.as_ref().map(|_| "<background-tasks>"),
            )
            .finish()
    }
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
            headers: Vec::new(),
            disable_ip_tracking: false,
            ipv6_subnet: Ipv6Subnet::Prefix64,
        }
    }
}

impl IpAddressOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn header(mut self, header: impl Into<String>) -> Self {
        self.headers.push(header.into());
        self
    }

    #[must_use]
    pub fn headers<I, S>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.headers = headers.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn disable_ip_tracking(mut self, disabled: bool) -> Self {
        self.disable_ip_tracking = disabled;
        self
    }

    #[must_use]
    pub fn ipv6_subnet(mut self, subnet: Ipv6Subnet) -> Self {
        self.ipv6_subnet = subnet;
        self
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

impl CookieAttributesOverride {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    #[must_use]
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = Some(secure);
        self
    }

    #[must_use]
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = Some(http_only);
        self
    }

    #[must_use]
    pub fn same_site(mut self, same_site: impl Into<String>) -> Self {
        self.same_site = Some(same_site.into());
        self
    }

    #[must_use]
    pub fn max_age(mut self, max_age: u64) -> Self {
        self.max_age = Some(max_age);
        self
    }

    #[must_use]
    pub fn partitioned(mut self, partitioned: bool) -> Self {
        self.partitioned = Some(partitioned);
        self
    }
}
