use http::header;
use http::StatusCode;
use time::OffsetDateTime;

use crate::api::response_helpers::json_response;
use crate::api::{ApiErrorResponse, EndpointMiddleware, PathParams};
use crate::auth::session::{GetSessionInput, SessionAuth};
use crate::context::request_state::current_session;
use crate::db::{DbValue, FindOne, Where};
use crate::error::RustAuthError;
use crate::error_codes;

/// Require the current request's session to be within `SessionOptions::fresh_age`.
pub fn fresh_session_middleware() -> EndpointMiddleware {
    EndpointMiddleware::new(|context, _request| {
        Box::pin(async move {
            let Some(current) = current_session()? else {
                return Ok(None);
            };
            if context.session_config.fresh_age.is_zero() {
                return Ok(None);
            }
            let age = OffsetDateTime::now_utc() - current.session.created_at;
            if age < context.session_config.fresh_age {
                return Ok(None);
            }
            json_response(
                StatusCode::BAD_REQUEST,
                &ApiErrorResponse {
                    code: error_codes::SESSION_EXPIRED.to_owned(),
                    message: "Session expired".to_owned(),
                    original_message: None,
                },
                Vec::new(),
            )
            .map(Some)
        })
    })
}

/// Require the resource identified by a path param to belong to the current user.
pub fn require_resource_ownership(
    model: impl Into<String>,
    resource_id_param: impl Into<String>,
    owner_field: impl Into<String>,
) -> EndpointMiddleware {
    let model = model.into();
    let resource_id_param = resource_id_param.into();
    let owner_field = owner_field.into();
    EndpointMiddleware::new(move |context, request| {
        let model = model.clone();
        let resource_id_param = resource_id_param.clone();
        let owner_field = owner_field.clone();
        Box::pin(async move {
            let resource_id = request
                .extensions()
                .get::<PathParams>()
                .and_then(|params| params.get(&resource_id_param))
                .ok_or(RustAuthError::MissingPathParam {
                    name: resource_id_param,
                })?;
            let Some(adapter) = context.adapter() else {
                return Err(RustAuthError::InvalidConfig(
                    "resource ownership middleware requires an adapter".to_owned(),
                ));
            };
            let cookie_header = request
                .headers()
                .get(header::COOKIE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let Some(result) = SessionAuth::new(context)?
                .get_session(GetSessionInput::new(cookie_header))
                .await?
            else {
                return unauthorized_response().map(Some);
            };
            let Some(user) = result.user else {
                return unauthorized_response().map(Some);
            };
            let record = adapter
                .find_one(
                    FindOne::new(&model)
                        .where_clause(Where::new("id", DbValue::String(resource_id.to_owned()))),
                )
                .await?;
            let owns_resource = record.and_then(|record| record.get(&owner_field).cloned())
                == Some(DbValue::String(user.id));
            if owns_resource {
                return Ok(None);
            }
            forbidden_response().map(Some)
        })
    })
}

fn unauthorized_response() -> Result<crate::api::ApiResponse, RustAuthError> {
    json_response(
        StatusCode::UNAUTHORIZED,
        &ApiErrorResponse {
            code: "UNAUTHORIZED".to_owned(),
            message: "Authentication required".to_owned(),
            original_message: None,
        },
        Vec::new(),
    )
}

fn forbidden_response() -> Result<crate::api::ApiResponse, RustAuthError> {
    json_response(
        StatusCode::FORBIDDEN,
        &ApiErrorResponse {
            code: "FORBIDDEN".to_owned(),
            message: "Forbidden".to_owned(),
            original_message: None,
        },
        Vec::new(),
    )
}

pub(crate) fn ensure_fresh_session(
    context: &crate::context::AuthContext,
    session: &crate::db::Session,
) -> Result<(), RustAuthError> {
    if context.session_config.fresh_age.is_zero() {
        return Ok(());
    }
    let age = OffsetDateTime::now_utc() - session.created_at;
    if age >= context.session_config.fresh_age {
        return Err(RustAuthError::Api(error_codes::SESSION_EXPIRED.to_owned()));
    }
    Ok(())
}
