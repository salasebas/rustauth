#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FredRateLimitOptions {
    pub key_prefix: String,
}

impl Default for FredRateLimitOptions {
    fn default() -> Self {
        Self {
            key_prefix: "openauth:".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FredSecondaryStorageOptions {
    pub key_prefix: String,
    pub scan_count: u32,
}

impl Default for FredSecondaryStorageOptions {
    fn default() -> Self {
        Self {
            key_prefix: "openauth:".to_owned(),
            scan_count: 100,
        }
    }
}
