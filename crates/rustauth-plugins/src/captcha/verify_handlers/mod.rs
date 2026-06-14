//! CAPTCHA verification handlers.

pub mod captchafox;
pub mod cloudflare_turnstile;
pub mod google_recaptcha;
pub mod h_captcha;

use super::options::{CaptchaOptions, CaptchaProvider};

#[derive(Debug, thiserror::Error)]
pub enum CaptchaVerifyError {
    #[error("captcha service unavailable: {0}")]
    ServiceUnavailable(String),
}

pub struct VerifyCaptchaInput<'a> {
    pub options: &'a CaptchaOptions,
    pub captcha_response: &'a str,
    pub remote_ip: Option<String>,
}

pub async fn verify_captcha(input: VerifyCaptchaInput<'_>) -> Result<bool, CaptchaVerifyError> {
    match input.options.provider {
        CaptchaProvider::CloudflareTurnstile => {
            cloudflare_turnstile::verify(input.options, input.captcha_response, input.remote_ip)
                .await
        }
        CaptchaProvider::GoogleRecaptcha => {
            google_recaptcha::verify(input.options, input.captcha_response, input.remote_ip).await
        }
        CaptchaProvider::HCaptcha => {
            h_captcha::verify(input.options, input.captcha_response, input.remote_ip).await
        }
        CaptchaProvider::CaptchaFox => {
            captchafox::verify(input.options, input.captcha_response, input.remote_ip).await
        }
    }
}

fn service_unavailable(error: impl ToString) -> CaptchaVerifyError {
    CaptchaVerifyError::ServiceUnavailable(error.to_string())
}
