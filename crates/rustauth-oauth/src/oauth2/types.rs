use url::Url;

use super::error::OAuthError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationEndpoint(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEndpoint(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectUri(String);

#[derive(Clone, PartialEq, Eq)]
pub struct ClientSecret(String);

impl AuthorizationEndpoint {
    pub fn new(value: impl Into<String>) -> Result<Self, OAuthError> {
        validated_absolute_url(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TokenEndpoint {
    pub fn new(value: impl Into<String>) -> Result<Self, OAuthError> {
        validated_absolute_url(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl RedirectUri {
    pub fn new(value: impl Into<String>) -> Result<Self, OAuthError> {
        validated_absolute_url(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ClientSecret {
    pub fn new(value: impl Into<String>) -> Result<Self, OAuthError> {
        let value = value.into();
        if value.is_empty() {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(Self(value))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClientSecret(<redacted>)")
    }
}

fn validated_absolute_url(value: impl Into<String>) -> Result<String, OAuthError> {
    let value = value.into();
    let url = Url::parse(&value)?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(OAuthError::InvalidConfiguration(format!(
            "unsupported URL scheme `{}`",
            url.scheme()
        )));
    }
    Ok(value)
}
