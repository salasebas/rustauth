//! CaptchaFox verification handler.

use serde::Deserialize;

use super::{service_unavailable, CaptchaVerifyError};
use crate::captcha::CaptchaOptions;

#[derive(Deserialize)]
struct SiteVerifyResponse {
    success: bool,
}

pub async fn verify(
    options: &CaptchaOptions,
    captcha_response: &str,
    remote_ip: Option<String>,
) -> Result<bool, CaptchaVerifyError> {
    let client = options.http_client_ref();
    let mut form = vec![
        ("secret", options.secret_key.as_str()),
        ("response", captcha_response),
    ];
    if let Some(site_key) = options.site_key.as_deref() {
        form.push(("sitekey", site_key));
    }
    if let Some(remote_ip) = remote_ip.as_deref() {
        form.push(("remoteIp", remote_ip));
    }

    let response = client
        .post(options.site_verify_url())
        .form(&form)
        .send()
        .await
        .map_err(service_unavailable)?;
    if !response.status().is_success() {
        return Err(service_unavailable(response.status()));
    }
    let data = response
        .json::<SiteVerifyResponse>()
        .await
        .map_err(service_unavailable)?;

    Ok(data.success)
}
