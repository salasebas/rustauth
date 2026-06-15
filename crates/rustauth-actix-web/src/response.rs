use actix_web::http::StatusCode;
use actix_web::HttpResponse;

pub(crate) fn from_api_response(response: rustauth::api::ApiResponse) -> HttpResponse {
    let (parts, body) = response.into_parts();
    let status =
        StatusCode::from_u16(parts.status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    // Actix HttpResponse does not expose a safe response-version setter; status,
    // headers, and body are preserved below.
    for (name, value) in parts.headers.iter() {
        builder.append_header((name.as_str(), value.as_bytes()));
    }
    builder.body(body)
}
