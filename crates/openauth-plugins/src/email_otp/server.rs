use std::sync::Arc;

use http::StatusCode;
use openauth_core::api::{parse_request_body, ApiRequest};
use openauth_core::context::AuthContext;
use openauth_core::db::DbAdapter;
use openauth_core::verification::DbVerificationStore;
use serde::{Deserialize, Serialize};

use super::helpers::{parse_type, resolve_otp, validated_email};
use super::otp;
use super::response;
use super::types::{EmailOtpOptions, OtpStorage};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateOtpBody {
    email: String,
    #[serde(rename = "type")]
    otp_type: String,
}

#[derive(Debug, Serialize)]
struct GetOtpResponse {
    otp: Option<String>,
}

pub(super) fn create_verification_otp<'a>(
    context: &'a AuthContext,
    request: ApiRequest,
    adapter: Arc<dyn DbAdapter>,
    options: Arc<EmailOtpOptions>,
) -> openauth_core::api::EndpointFuture<'a> {
    Box::pin(async move {
        let body: CreateOtpBody = parse_request_body(&request)?;
        let email = match validated_email(&body.email)? {
            Ok(email) => email,
            Err(response) => return Ok(response),
        };
        let otp_type = match parse_type(&body.otp_type)? {
            Ok(otp_type) => otp_type,
            Err(response) => return Ok(response),
        };
        let identifier = otp::identifier(otp_type, &email);
        let otp = resolve_otp(
            adapter.as_ref(),
            &options,
            &context.secret_config,
            &email,
            otp_type,
            &identifier,
        )
        .await?;
        response::json(StatusCode::OK, &otp, Vec::new())
    })
}

pub(super) fn get_verification_otp<'a>(
    context: &'a AuthContext,
    request: ApiRequest,
    adapter: Arc<dyn DbAdapter>,
    options: Arc<EmailOtpOptions>,
) -> openauth_core::api::EndpointFuture<'a> {
    Box::pin(async move {
        let (email, otp_type) = match (
            query_param(&request, "email"),
            query_param(&request, "type"),
        ) {
            (Some(email), Some(otp_type)) => (email, otp_type),
            (None, _) => {
                return response::error(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email");
            }
            (_, None) => {
                return response::error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_OTP_TYPE",
                    "Invalid OTP type",
                );
            }
        };
        let email = match validated_email(&email)? {
            Ok(email) => email,
            Err(response) => return Ok(response),
        };
        let otp_type = match parse_type(&otp_type)? {
            Ok(otp_type) => otp_type,
            Err(response) => return Ok(response),
        };
        let store = DbVerificationStore::new(adapter.as_ref());
        let Some(verification) = store
            .find_verification(&otp::identifier(otp_type, &email))
            .await?
        else {
            return response::json(StatusCode::OK, &GetOtpResponse { otp: None }, Vec::new());
        };
        if verification.expires_at <= time::OffsetDateTime::now_utc() {
            store.delete_verification(&verification.identifier).await?;
            return response::json(StatusCode::OK, &GetOtpResponse { otp: None }, Vec::new());
        }
        let parts = otp::split_value(&verification.value);
        let plain = otp::reusable_otp(&options, &context.secret_config, &parts)?;
        if plain.is_none()
            && matches!(
                options.store_otp,
                OtpStorage::Hashed | OtpStorage::CustomHash(_)
            )
        {
            return response::error(
                StatusCode::BAD_REQUEST,
                "INVALID_OTP",
                "OTP is hashed, cannot return the plain text OTP",
            );
        }
        response::json(StatusCode::OK, &GetOtpResponse { otp: plain }, Vec::new())
    })
}

fn query_param(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key == name).then(|| percent_decode(value))
        })
    })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        output.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
