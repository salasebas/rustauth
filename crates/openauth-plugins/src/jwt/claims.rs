use openauth_core::error::OpenAuthError;
use serde_json::{Number, Value};

pub type JwtClaims = serde_json::Map<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeInput {
    Seconds(i64),
    UnixTimestamp(i64),
    Duration(String),
}

pub fn to_exp_jwt(expiration_time: TimeInput, iat: i64) -> Result<i64, OpenAuthError> {
    match expiration_time {
        TimeInput::Seconds(value) | TimeInput::UnixTimestamp(value) => Ok(value),
        TimeInput::Duration(value) => parse_duration(&value).map(|seconds| iat + seconds),
    }
}

pub(crate) fn claims_with_defaults(
    mut claims: JwtClaims,
    base_url: &str,
    options: &super::JwtOptions,
) -> Result<JwtClaims, OpenAuthError> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let iat = numeric_claim(&claims, "iat").unwrap_or(now);
    claims
        .entry("iat".to_owned())
        .or_insert_with(|| Value::Number(Number::from(iat)));
    if !claims.contains_key("exp") {
        let exp = to_exp_jwt(
            options
                .jwt
                .expiration_time
                .clone()
                .unwrap_or_else(|| TimeInput::Duration("15m".to_owned())),
            iat,
        )?;
        claims.insert("exp".to_owned(), Value::Number(Number::from(exp)));
    }
    claims.entry("iss".to_owned()).or_insert_with(|| {
        Value::String(
            options
                .jwt
                .issuer
                .clone()
                .unwrap_or_else(|| base_url.to_owned()),
        )
    });
    if !claims.contains_key("aud") {
        match &options.jwt.audience {
            Some(audience) if audience.len() == 1 => {
                claims.insert("aud".to_owned(), Value::String(audience[0].clone()));
            }
            Some(audience) => {
                claims.insert(
                    "aud".to_owned(),
                    Value::Array(audience.iter().cloned().map(Value::String).collect()),
                );
            }
            None => {
                claims.insert("aud".to_owned(), Value::String(base_url.to_owned()));
            }
        }
    }
    Ok(claims)
}

pub(crate) fn numeric_claim(claims: &JwtClaims, name: &str) -> Option<i64> {
    claims.get(name).and_then(Value::as_i64)
}

fn parse_duration(value: &str) -> Result<i64, OpenAuthError> {
    let mut input = value.trim().to_ascii_lowercase();
    if input.is_empty() {
        return Err(invalid_duration(value));
    }
    let ago = input.ends_with(" ago");
    if ago {
        input.truncate(input.len() - 4);
    }
    if input.ends_with(" from now") {
        input.truncate(input.len() - 9);
    }
    let negative = input.starts_with('-');
    if negative {
        input.remove(0);
    }
    let input = input.trim();
    let number_len = input
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_digit())
        .map(|(index, ch)| index + ch.len_utf8())
        .last()
        .ok_or_else(|| invalid_duration(value))?;
    let amount = input[..number_len]
        .parse::<i64>()
        .map_err(|_| invalid_duration(value))?;
    let unit = input[number_len..].trim();
    let multiplier = match unit {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60 * 60,
        "d" | "day" | "days" => 60 * 60 * 24,
        "w" | "week" | "weeks" => 60 * 60 * 24 * 7,
        "y" | "yr" | "yrs" | "year" | "years" => 31_557_600,
        _ => return Err(invalid_duration(value)),
    };
    let seconds = amount * multiplier;
    Ok(if ago || negative { -seconds } else { seconds })
}

fn invalid_duration(value: &str) -> OpenAuthError {
    OpenAuthError::InvalidConfig(format!("invalid JWT duration `{value}`"))
}
