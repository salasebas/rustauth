use axum::body::Body;
use axum::http::Response;

pub(crate) fn from_api_response(response: rustauth::api::ApiResponse) -> axum::response::Response {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, Body::from(body))
}
