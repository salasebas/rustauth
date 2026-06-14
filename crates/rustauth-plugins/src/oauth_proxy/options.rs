use serde::Serialize;
use time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OAuthProxyOptions {
    #[serde(skip_serializing_if = "Option::is_none", rename = "currentURL")]
    pub current_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "productionURL")]
    pub production_url: Option<String>,
    #[serde(rename = "maxAge")]
    pub max_age: Duration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl Default for OAuthProxyOptions {
    fn default() -> Self {
        Self {
            current_url: None,
            production_url: None,
            max_age: Duration::minutes(1),
            secret: None,
        }
    }
}

impl OAuthProxyOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn builder() -> OAuthProxyOptionsBuilder {
        OAuthProxyOptionsBuilder::default()
    }

    #[must_use]
    pub fn current_url(mut self, current_url: impl Into<String>) -> Self {
        self.current_url = Some(current_url.into());
        self
    }

    #[must_use]
    pub fn production_url(mut self, production_url: impl Into<String>) -> Self {
        self.production_url = Some(production_url.into());
        self
    }

    #[must_use]
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    #[must_use]
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    pub(crate) fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

#[derive(Debug, Clone, Default)]
pub struct OAuthProxyOptionsBuilder {
    current_url: Option<Option<String>>,
    production_url: Option<Option<String>>,
    max_age: Option<Duration>,
    secret: Option<Option<String>>,
}

impl OAuthProxyOptionsBuilder {
    #[must_use]
    pub fn current_url(mut self, current_url: impl Into<String>) -> Self {
        self.current_url = Some(Some(current_url.into()));
        self
    }

    #[must_use]
    pub fn production_url(mut self, production_url: impl Into<String>) -> Self {
        self.production_url = Some(Some(production_url.into()));
        self
    }

    #[must_use]
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    #[must_use]
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(Some(secret.into()));
        self
    }

    #[must_use]
    pub fn build(self) -> OAuthProxyOptions {
        let defaults = OAuthProxyOptions::default();
        OAuthProxyOptions {
            current_url: self.current_url.unwrap_or(defaults.current_url),
            production_url: self.production_url.unwrap_or(defaults.production_url),
            max_age: self.max_age.unwrap_or(defaults.max_age),
            secret: self.secret.unwrap_or(defaults.secret),
        }
    }
}
