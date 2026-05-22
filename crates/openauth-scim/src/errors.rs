//! SCIM error responses.

use http::{header, Response, StatusCode};
use openauth_core::api::ApiResponse;
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};

pub const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimError {
    pub status: StatusCode,
    pub detail: Option<String>,
    pub scim_type: Option<String>,
}

impl ScimError {
    pub fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: Some(detail.into()),
            scim_type: None,
        }
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, detail)
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, detail)
    }

    #[must_use]
    pub fn with_scim_type(mut self, scim_type: impl Into<String>) -> Self {
        self.scim_type = Some(scim_type.into());
        self
    }

    pub fn body(&self) -> ScimErrorBody {
        ScimErrorBody {
            schemas: vec![SCIM_ERROR_SCHEMA.to_owned()],
            status: self.status.as_u16().to_string(),
            detail: self.detail.clone(),
            scim_type: self.scim_type.clone(),
        }
    }

    pub fn into_response(self) -> Result<ApiResponse, OpenAuthError> {
        let body = serde_json::to_vec(&self.body())
            .map_err(|error| OpenAuthError::Api(error.to_string()))?;
        Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(body)
            .map_err(|error| OpenAuthError::Api(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimErrorBody {
    pub schemas: Vec<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "scimType")]
    pub scim_type: Option<String>,
}
