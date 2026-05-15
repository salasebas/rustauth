use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OAuthProxyOptions {
    #[serde(skip_serializing_if = "Option::is_none", rename = "currentURL")]
    pub current_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "productionURL")]
    pub production_url: Option<String>,
    #[serde(rename = "maxAge")]
    pub max_age: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl Default for OAuthProxyOptions {
    fn default() -> Self {
        Self {
            current_url: None,
            production_url: None,
            max_age: 60,
            secret: None,
        }
    }
}

impl OAuthProxyOptions {
    pub fn new() -> Self {
        Self::default()
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
    pub fn max_age(mut self, max_age: u64) -> Self {
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
