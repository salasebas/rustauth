//! End-to-end flows that demonstrate how an application consumes the public API.

use http::StatusCode;

use crate::client::requests::{sign_in_email, sign_up_email, SignInEmailBody, SignUpEmailBody};
use crate::client::responses::{parse_json_body, session_cookie};
use crate::config::AppConfig;

/// Register a user with email/password and return the session cookie value.
pub async fn register_and_sign_in(
    auth: &rustauth::RustAuth,
    config: &AppConfig,
    name: &str,
    email: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let sign_up = sign_up_email(
        config,
        SignUpEmailBody {
            name,
            email,
            password,
            remember_me: Some(true),
        },
    )?;
    let sign_up_response = auth.handler_async(sign_up).await?;
    if sign_up_response.status() != StatusCode::OK {
        return Err(format!("sign-up failed with status {}", sign_up_response.status()).into());
    }

    let cookie = session_cookie(&sign_up_response)
        .ok_or("sign-up succeeded but no session cookie was set")?;

    let sign_in = sign_in_email(
        config,
        SignInEmailBody {
            email,
            password,
            remember_me: Some(true),
        },
    )?;
    let sign_in_response = auth.handler_async(sign_in).await?;
    if sign_in_response.status() != StatusCode::OK {
        return Err(format!("sign-in failed with status {}", sign_in_response.status()).into());
    }

    let body = parse_json_body(&sign_in_response)?;
    if body["user"]["email"].as_str() != Some(email) {
        return Err("sign-in response user email mismatch".into());
    }

    Ok(cookie)
}
