use serde_json::Value;
use time::OffsetDateTime;

use super::error::OAuthError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenValidationOptions {
    pub audience: Vec<String>,
    pub issuer: Vec<String>,
    pub allowed_algorithms: Vec<String>,
    pub leeway_seconds: i64,
    pub require_expiration: bool,
    pub require_subject: bool,
    pub require_audience: bool,
    pub require_issuer: bool,
}

impl Default for TokenValidationOptions {
    fn default() -> Self {
        Self {
            audience: Vec::new(),
            issuer: Vec::new(),
            allowed_algorithms: default_allowed_algorithms(),
            leeway_seconds: 60,
            require_expiration: false,
            require_subject: false,
            require_audience: false,
            require_issuer: false,
        }
    }
}

impl TokenValidationOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow_hmac_algorithms(mut self) -> Self {
        for algorithm in ["HS256", "HS384", "HS512"] {
            if !self
                .allowed_algorithms
                .iter()
                .any(|value| value == algorithm)
            {
                self.allowed_algorithms.push(algorithm.to_owned());
            }
        }
        self
    }

    pub fn allowed_algorithms(
        mut self,
        algorithms: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.allowed_algorithms = algorithms.into_iter().map(Into::into).collect();
        self
    }

    pub fn leeway_seconds(mut self, seconds: i64) -> Self {
        self.leeway_seconds = seconds.max(0);
        self
    }

    pub fn require_standard_claims(mut self) -> Self {
        self.require_expiration = true;
        self.require_subject = true;
        self.require_audience = true;
        self.require_issuer = true;
        self
    }
}

fn default_allowed_algorithms() -> Vec<String> {
    [
        "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub(crate) fn validate_payload_claims(
    claims: &serde_json::Map<String, Value>,
    options: &TokenValidationOptions,
) -> Result<(), OAuthError> {
    validate_temporal_claims_with_leeway(claims, options.leeway_seconds)?;
    validate_required_claims(claims, options)?;
    if !options.audience.is_empty() && !audience_matches(claims.get("aud"), &options.audience) {
        return Err(OAuthError::TokenVerification(
            "audience mismatch".to_owned(),
        ));
    }
    if !options.issuer.is_empty() {
        let issuer = claims.get("iss").and_then(Value::as_str);
        if !issuer.is_some_and(|issuer| options.issuer.iter().any(|expected| expected == issuer)) {
            return Err(OAuthError::TokenVerification("issuer mismatch".to_owned()));
        }
    }
    Ok(())
}

pub(crate) fn validate_temporal_claims_with_leeway(
    claims: &serde_json::Map<String, Value>,
    leeway_seconds: i64,
) -> Result<(), OAuthError> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let leeway_seconds = leeway_seconds.max(0);
    if let Some(expiration) = required_numeric_claim(claims, "exp", false)? {
        if expiration <= now - leeway_seconds {
            return Err(OAuthError::TokenVerification("token expired".to_owned()));
        }
    }
    if let Some(not_before) = required_numeric_claim(claims, "nbf", false)? {
        if not_before > now + leeway_seconds {
            return Err(OAuthError::TokenVerification("token not active".to_owned()));
        }
    }
    if let Some(issued_at) = required_numeric_claim(claims, "iat", false)? {
        if issued_at > now + leeway_seconds {
            return Err(OAuthError::TokenVerification(
                "token issued in the future".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_required_claims(
    claims: &serde_json::Map<String, Value>,
    options: &TokenValidationOptions,
) -> Result<(), OAuthError> {
    if options.require_expiration {
        required_numeric_claim(claims, "exp", true)?;
    }
    if options.require_subject {
        required_string_claim(claims, "sub")?;
    }
    if options.require_audience {
        required_audience_claim(claims)?;
    }
    if options.require_issuer {
        required_string_claim(claims, "iss")?;
    }
    Ok(())
}

pub(crate) fn audience_matches(value: Option<&Value>, expected: &[String]) -> bool {
    match value {
        Some(Value::String(audience)) => expected.iter().any(|expected| expected == audience),
        Some(Value::Array(audiences)) => audiences
            .iter()
            .filter_map(Value::as_str)
            .any(|audience| expected.iter().any(|expected| expected == audience)),
        _ => false,
    }
}

fn required_string_claim(
    claims: &serde_json::Map<String, Value>,
    claim: &'static str,
) -> Result<(), OAuthError> {
    match claims.get(claim) {
        Some(Value::String(value)) if !value.is_empty() => Ok(()),
        Some(_) => Err(OAuthError::InvalidClaim {
            claim,
            reason: "must be a non-empty string".to_owned(),
        }),
        None => Err(OAuthError::InvalidClaim {
            claim,
            reason: "missing required claim".to_owned(),
        }),
    }
}

fn required_audience_claim(claims: &serde_json::Map<String, Value>) -> Result<(), OAuthError> {
    match claims.get("aud") {
        Some(Value::String(value)) if !value.is_empty() => Ok(()),
        Some(Value::Array(values))
            if values
                .iter()
                .any(|value| value.as_str().is_some_and(|value| !value.is_empty())) =>
        {
            Ok(())
        }
        Some(_) => Err(OAuthError::InvalidClaim {
            claim: "aud",
            reason: "must be a non-empty string or string array".to_owned(),
        }),
        None => Err(OAuthError::InvalidClaim {
            claim: "aud",
            reason: "missing required claim".to_owned(),
        }),
    }
}

const INVALID_NUMERIC_TIMESTAMP_REASON: &str = "must be an integer NumericDate timestamp";

pub fn parse_numeric_timestamp_claim(
    value: Option<&Value>,
    claim: &'static str,
    required: bool,
) -> Result<Option<i64>, OAuthError> {
    match value {
        Some(Value::Number(number)) => {
            if let Some(timestamp) = number
                .as_i64()
                .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
            {
                Ok(Some(timestamp))
            } else {
                Err(OAuthError::InvalidClaim {
                    claim,
                    reason: INVALID_NUMERIC_TIMESTAMP_REASON.to_owned(),
                })
            }
        }
        Some(_) => Err(OAuthError::InvalidClaim {
            claim,
            reason: "must be a numeric timestamp".to_owned(),
        }),
        None if required => Err(OAuthError::InvalidClaim {
            claim,
            reason: "missing required claim".to_owned(),
        }),
        None => Ok(None),
    }
}

fn required_numeric_claim(
    claims: &serde_json::Map<String, Value>,
    claim: &'static str,
    required: bool,
) -> Result<Option<i64>, OAuthError> {
    parse_numeric_timestamp_claim(claims.get(claim), claim, required)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::str::FromStr;

    #[test]
    fn validate_temporal_claims_rejects_fractional_exp_nbf_and_iat() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        for (claim_name, value) in [
            ("exp", json!(0.1)),
            ("nbf", json!(now as f64 + 0.5)),
            ("iat", json!(now as f64 + 0.5)),
        ] {
            let mut claims = serde_json::Map::new();
            claims.insert(claim_name.to_owned(), value);
            let error = validate_temporal_claims_with_leeway(&claims, 0)
                .expect_err("fractional temporal claim should be rejected");
            assert!(matches!(
                error,
                OAuthError::InvalidClaim { claim, .. } if *claim == *claim_name
            ));
        }
    }

    #[test]
    fn validate_temporal_claims_rejects_oversized_exp() {
        let mut claims = serde_json::Map::new();
        claims.insert(
            "exp".to_owned(),
            Value::Number(
                serde_json::Number::from_str("9223372036854775808")
                    .expect("oversized exp should parse as JSON number"),
            ),
        );
        let error = validate_temporal_claims_with_leeway(&claims, 0)
            .expect_err("oversized exp should be rejected");
        assert!(matches!(
            error,
            OAuthError::InvalidClaim { claim: "exp", .. }
        ));
    }

    #[test]
    fn validate_required_claims_rejects_unparseable_exp_when_required() {
        let mut claims = serde_json::Map::new();
        claims.insert("exp".to_owned(), json!(1.5));
        let error = validate_required_claims(
            &claims,
            &TokenValidationOptions {
                require_expiration: true,
                ..TokenValidationOptions::default()
            },
        )
        .expect_err("required exp must be an integer timestamp");
        assert!(matches!(
            error,
            OAuthError::InvalidClaim { claim: "exp", .. }
        ));
    }

    #[test]
    fn validate_temporal_claims_accepts_integer_timestamps() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let claims = serde_json::Map::from_iter([
            ("exp".to_owned(), json!(now + 3600)),
            ("nbf".to_owned(), json!(now - 60)),
            ("iat".to_owned(), json!(now)),
        ]);
        validate_temporal_claims_with_leeway(&claims, 60).expect("integer timestamps should pass");
    }
}
