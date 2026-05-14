//! CAPTCHA options.

use serde::{Deserialize, Serialize};

use super::error::CaptchaConfigError;

pub const DEFAULT_ENDPOINTS: &[&str] = &[
    "/sign-up/email",
    "/sign-in/email",
    "/request-password-reset",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptchaProvider {
    #[serde(rename = "cloudflare-turnstile")]
    CloudflareTurnstile,
    #[serde(rename = "google-recaptcha")]
    GoogleRecaptcha,
    #[serde(rename = "hcaptcha")]
    HCaptcha,
    #[serde(rename = "captchafox")]
    CaptchaFox,
}

impl CaptchaProvider {
    pub fn site_verify_url(self) -> &'static str {
        match self {
            Self::CloudflareTurnstile => {
                "https://challenges.cloudflare.com/turnstile/v0/siteverify"
            }
            Self::GoogleRecaptcha => "https://www.google.com/recaptcha/api/siteverify",
            Self::HCaptcha => "https://api.hcaptcha.com/siteverify",
            Self::CaptchaFox => "https://api.captchafox.com/siteverify",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaOptions {
    pub provider: CaptchaProvider,
    #[serde(skip_serializing)]
    pub secret_key: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub site_verify_url_override: Option<String>,
    #[serde(default)]
    pub min_score: Option<f64>,
    #[serde(default)]
    pub site_key: Option<String>,
    #[serde(skip)]
    pub http_client: Option<reqwest::Client>,
}

impl CaptchaOptions {
    pub fn with_provider(provider: CaptchaProvider, secret_key: impl Into<String>) -> Self {
        Self {
            provider,
            secret_key: secret_key.into(),
            endpoints: Vec::new(),
            site_verify_url_override: None,
            min_score: None,
            site_key: None,
            http_client: None,
        }
    }

    pub fn cloudflare_turnstile(secret_key: impl Into<String>) -> Self {
        Self::with_provider(CaptchaProvider::CloudflareTurnstile, secret_key)
    }

    pub fn google_recaptcha(secret_key: impl Into<String>) -> Self {
        Self::with_provider(CaptchaProvider::GoogleRecaptcha, secret_key)
    }

    pub fn hcaptcha(secret_key: impl Into<String>) -> Self {
        Self::with_provider(CaptchaProvider::HCaptcha, secret_key)
    }

    pub fn captchafox(secret_key: impl Into<String>) -> Self {
        Self::with_provider(CaptchaProvider::CaptchaFox, secret_key)
    }

    #[must_use]
    pub fn endpoints<I, S>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.endpoints = endpoints.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn site_verify_url_override(mut self, url: impl Into<String>) -> Self {
        self.site_verify_url_override = Some(url.into());
        self
    }

    #[must_use]
    pub fn min_score(mut self, min_score: f64) -> Self {
        self.min_score = Some(min_score);
        self
    }

    #[must_use]
    pub fn site_key(mut self, site_key: impl Into<String>) -> Self {
        self.site_key = Some(site_key.into());
        self
    }

    #[must_use]
    pub fn http_client(mut self, http_client: reqwest::Client) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub(crate) fn validate(&self) -> Result<(), CaptchaConfigError> {
        if self.secret_key.trim().is_empty() {
            return Err(CaptchaConfigError::MissingSecretKey);
        }
        Ok(())
    }

    pub(crate) fn with_defaults(mut self) -> Self {
        if self.endpoints.is_empty() {
            self.endpoints = DEFAULT_ENDPOINTS
                .iter()
                .map(|endpoint| (*endpoint).to_owned())
                .collect();
        }
        self
    }

    pub(crate) fn site_verify_url(&self) -> &str {
        self.site_verify_url_override
            .as_deref()
            .unwrap_or_else(|| self.provider.site_verify_url())
    }

    pub(crate) fn http_client_ref(&self) -> reqwest::Client {
        self.http_client.clone().unwrap_or_default()
    }

    pub(crate) fn google_min_score(&self) -> f64 {
        self.min_score.unwrap_or(0.5)
    }
}
