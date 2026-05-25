const DEFAULT_BODY_LIMIT: usize = 10 * 1024 * 1024;

/// Axum adapter options.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenAuthAxumOptions {
    pub(crate) body_limit: usize,
    pub(crate) use_connect_info_for_ip: bool,
    pub(crate) infer_base_url_from_request: bool,
    pub(crate) trust_proxy_headers_for_base_url: bool,
}

impl OpenAuthAxumOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn body_limit(mut self, body_limit: usize) -> Self {
        self.body_limit = body_limit;
        self
    }

    #[must_use]
    pub fn use_connect_info_for_ip(mut self, enabled: bool) -> Self {
        self.use_connect_info_for_ip = enabled;
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

    #[must_use]
    pub fn request_body_limit(&self) -> usize {
        self.body_limit
    }

    #[must_use]
    pub fn connect_info_for_ip_enabled(&self) -> bool {
        self.use_connect_info_for_ip
    }

    #[must_use]
    pub fn base_url_inference_enabled(&self) -> bool {
        self.infer_base_url_from_request
    }

    #[must_use]
    pub fn trusted_proxy_headers_for_base_url_enabled(&self) -> bool {
        self.trust_proxy_headers_for_base_url
    }
}

impl Default for OpenAuthAxumOptions {
    fn default() -> Self {
        Self {
            body_limit: DEFAULT_BODY_LIMIT,
            use_connect_info_for_ip: true,
            infer_base_url_from_request: true,
            trust_proxy_headers_for_base_url: false,
        }
    }
}
