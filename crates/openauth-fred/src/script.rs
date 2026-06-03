use fred::types::Value;
use openauth_core::error::OpenAuthError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitScriptResult {
    pub permitted: bool,
    pub count: u64,
    pub last_request: i64,
}

pub(crate) const RATE_LIMIT_SCRIPT: &str = r#"
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max = tonumber(ARGV[3])

local data = redis.call("HMGET", key, "count", "last_request")
local count = tonumber(data[1])
local last_request = tonumber(data[2])

if count == nil or last_request == nil or (now - last_request) > window then
  redis.call("HSET", key, "count", 1, "last_request", now)
  redis.call("PEXPIRE", key, window)
  return {1, 1, now}
end

if count >= max then
  redis.call("PEXPIRE", key, window)
  return {0, count, last_request}
end

count = count + 1
redis.call("HSET", key, "count", count, "last_request", now)
redis.call("PEXPIRE", key, window)
return {1, count, now}
"#;

#[cfg(test)]
mod tests {
    use super::RATE_LIMIT_SCRIPT;

    #[test]
    fn rate_limit_script_resets_only_after_window_elapses() {
        assert!(RATE_LIMIT_SCRIPT.contains("(now - last_request) > window"));
        assert!(!RATE_LIMIT_SCRIPT.contains("(now - last_request) >= window"));
    }
}

pub fn parse_rate_limit_script_result(
    value: Value,
) -> Result<RateLimitScriptResult, OpenAuthError> {
    let Value::Array(values) = value else {
        return Err(OpenAuthError::Adapter(
            "invalid fred rate limit script result: expected array".to_owned(),
        ));
    };
    let [permitted, count, last_request]: [Value; 3] =
        values.try_into().map_err(|values: Vec<Value>| {
            OpenAuthError::Adapter(format!(
                "invalid fred rate limit script result: expected 3 values, got {}",
                values.len()
            ))
        })?;
    let permitted = match integer_value(permitted, "permitted")? {
        0 => false,
        1 => true,
        _ => {
            return Err(OpenAuthError::Adapter(
                "invalid fred rate limit script result: `permitted` was not 0 or 1".to_owned(),
            ));
        }
    };
    let count = integer_value(count, "count")?;
    if count < 0 {
        return Err(OpenAuthError::Adapter(
            "invalid fred rate limit script result: `count` was negative".to_owned(),
        ));
    }
    let last_request = integer_value(last_request, "last_request")?;
    Ok(RateLimitScriptResult {
        permitted,
        count: count as u64,
        last_request,
    })
}

fn integer_value(value: Value, field: &str) -> Result<i64, OpenAuthError> {
    match value {
        Value::Integer(value) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "invalid fred rate limit script result: `{field}` was not an integer"
        ))),
    }
}
