use http::{Method, StatusCode};
use serde::Serialize;

use super::{endpoint, json, SharedConfigurations};
use crate::api_key::cleanup;

#[derive(Debug, Clone, Serialize)]
struct DeleteExpiredResponse {
    success: bool,
    error: Option<String>,
}

pub fn delete_expired_endpoint(
    configurations: SharedConfigurations,
) -> openauth_core::api::AsyncAuthEndpoint {
    endpoint(
        "/api-key/delete-all-expired-api-keys",
        Method::POST,
        configurations,
        |context, _request, configurations| {
            Box::pin(async move {
                let options = configurations.resolve(None)?;
                match cleanup::delete_all_expired_api_keys(context, &options, true).await {
                    Ok(_) => json(
                        StatusCode::OK,
                        &DeleteExpiredResponse {
                            success: true,
                            error: None,
                        },
                    ),
                    Err(error) => json(
                        StatusCode::OK,
                        &DeleteExpiredResponse {
                            success: false,
                            error: Some(error.to_string()),
                        },
                    ),
                }
            })
        },
    )
}
