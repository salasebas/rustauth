const DEFAULT_BODY_LIMIT: usize = 10 * 1024 * 1024;

/// Actix Web adapter options.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustAuthActixWebOptions {
    pub(crate) body_limit: usize,
    pub(crate) use_peer_addr_for_ip: bool,
    pub(crate) infer_base_url_from_request: bool,
    pub(crate) trust_proxy_headers_for_base_url: bool,
}

impl RustAuthActixWebOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn body_limit(mut self, body_limit: usize) -> Self {
        self.body_limit = body_limit;
        self
    }

    #[must_use]
    pub fn use_peer_addr_for_ip(mut self, enabled: bool) -> Self {
        self.use_peer_addr_for_ip = enabled;
        self
    }

    #[must_use]
    pub fn infer_base_url_from_request(mut self, enabled: bool) -> Self {
        self.infer_base_url_from_request = enabled;
        self
    }

    #[must_use]
    pub fn trust_proxy_headers_for_base_url(mut self, enabled: bool) -> Self {
        self.trust_proxy_headers_for_base_url = enabled;
        self
    }
}

impl Default for RustAuthActixWebOptions {
    fn default() -> Self {
        Self {
            body_limit: DEFAULT_BODY_LIMIT,
            use_peer_addr_for_ip: true,
            infer_base_url_from_request: false,
            trust_proxy_headers_for_base_url: false,
        }
    }
}
