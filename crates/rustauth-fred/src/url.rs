use std::borrow::Cow;

pub fn normalize_fred_url(redis_url: &str) -> Cow<'_, str> {
    if let Some(rest) = redis_url.strip_prefix("valkey://") {
        return Cow::Owned(format!("redis://{rest}"));
    }
    if let Some(rest) = redis_url.strip_prefix("valkeys://") {
        return Cow::Owned(format!("rediss://{rest}"));
    }
    Cow::Borrowed(redis_url)
}
