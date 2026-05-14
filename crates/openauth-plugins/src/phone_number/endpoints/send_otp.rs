use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{
    create_auth_endpoint, parse_request_body, AsyncAuthEndpoint, AuthEndpointOptions, BodyField,
    BodySchema, JsonSchemaType,
};
use openauth_core::db::DbAdapter;
use serde::{Deserialize, Serialize};

use super::validate_phone_number;
use crate::phone_number::errors::{error_response, json_response, send_otp_not_implemented};
use crate::phone_number::options::PhoneNumberOptions;
use crate::phone_number::otp;

#[derive(Debug, Deserialize)]
struct SendOtpBody {
    #[serde(alias = "phoneNumber")]
    phone_number: String,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: &'static str,
}

pub(crate) fn endpoint(
    adapter: Arc<dyn DbAdapter>,
    options: Arc<PhoneNumberOptions>,
) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/phone-number/send-otp",
        Method::POST,
        AuthEndpointOptions::new()
            .operation_id("sendPhoneNumberOTP")
            .allowed_media_types(["application/json", "application/x-www-form-urlencoded"])
            .body_schema(BodySchema::object([BodyField::new(
                "phoneNumber",
                JsonSchemaType::String,
            )])),
        move |_context, request| {
            let adapter = Arc::clone(&adapter);
            let options = Arc::clone(&options);
            Box::pin(async move {
                let body: SendOtpBody = parse_request_body(&request)?;
                let Some(sender) = &options.send_otp else {
                    return error_response(StatusCode::NOT_IMPLEMENTED, send_otp_not_implemented());
                };
                if let Some(response) = validate_phone_number(&options, &body.phone_number)? {
                    return Ok(response);
                }
                let code = otp::generate_otp(options.otp_length);
                otp::create(
                    adapter.as_ref(),
                    body.phone_number.clone(),
                    &code,
                    options.expires_in,
                )
                .await?;
                sender(&body.phone_number, &code)?;
                json_response(
                    StatusCode::OK,
                    &MessageResponse {
                        message: "code sent",
                    },
                    Vec::new(),
                )
            })
        },
    )
}
