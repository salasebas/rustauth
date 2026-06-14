use std::borrow::Cow;

pub fn normalize_redis_url(redis_url: &str) -> Cow<'_, str> {
    if let Some(rest) = redis_url.strip_prefix("valkey://") {
        return Cow::Owned(format!("redis://{rest}"));
    }
    if let Some(rest) = redis_url.strip_prefix("valkeys://") {
        return Cow::Owned(format!("rediss://{rest}"));
    }
    Cow::Borrowed(redis_url)
}

pub(crate) fn secondary_storage_scan_pattern(prefix: &str) -> String {
    let mut pattern = String::with_capacity(prefix.len() + 1);
    for character in prefix.chars() {
        match character {
            '*' | '?' | '[' | ']' | '\\' => {
                pattern.push('\\');
                pattern.push(character);
            }
            _ => pattern.push(character),
        }
    }
    pattern.push('*');
    pattern
}

pub(crate) fn validate_key_prefix(prefix: &str) -> Result<(), rustauth_core::error::RustAuthError> {
    if prefix.is_empty() {
        return Err(rustauth_core::error::RustAuthError::InvalidConfig(
            "secondary storage key prefix must not be empty".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_rate_limit_key_prefix(
    prefix: &str,
) -> Result<(), rustauth_core::error::RustAuthError> {
    if prefix.is_empty() {
        return Err(rustauth_core::error::RustAuthError::InvalidConfig(
            "rate limit key prefix must not be empty".to_owned(),
        ));
    }
    Ok(())
}
