use time::OffsetDateTime;

use super::models::ApiKeyRecord;
use super::options::ApiKeyConfiguration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitResult {
    pub success: bool,
    pub try_again_in: Option<i64>,
    pub last_request: Option<OffsetDateTime>,
    pub request_count: Option<i64>,
}

pub fn check(
    api_key: &ApiKeyRecord,
    options: &ApiKeyConfiguration,
    now: OffsetDateTime,
) -> RateLimitResult {
    if !options.rate_limit.enabled || !api_key.rate_limit_enabled {
        return RateLimitResult {
            success: true,
            try_again_in: None,
            last_request: Some(now),
            request_count: None,
        };
    }
    let (Some(window), Some(max)) = (api_key.rate_limit_time_window, api_key.rate_limit_max) else {
        return RateLimitResult {
            success: true,
            try_again_in: None,
            last_request: None,
            request_count: None,
        };
    };
    let Some(last_request) = api_key.last_request else {
        return RateLimitResult {
            success: true,
            try_again_in: None,
            last_request: Some(now),
            request_count: Some(1),
        };
    };
    let elapsed = (now - last_request).whole_milliseconds();
    if elapsed > i128::from(window) {
        return RateLimitResult {
            success: true,
            try_again_in: None,
            last_request: Some(now),
            request_count: Some(1),
        };
    }
    if api_key.request_count >= max {
        return RateLimitResult {
            success: false,
            try_again_in: Some(
                i64::try_from(i128::from(window).saturating_sub(elapsed)).unwrap_or(i64::MAX),
            ),
            last_request: None,
            request_count: None,
        };
    }
    RateLimitResult {
        success: true,
        try_again_in: None,
        last_request: Some(now),
        request_count: Some(api_key.request_count.saturating_add(1)),
    }
}
