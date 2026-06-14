use std::error::Error as _;
use std::net::SocketAddr;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::Request;
use http_body_util::LengthLimitError;
use rustauth::api::ApiRequest;
use rustauth::rate_limit::RequestClientIp;

use crate::error::{bad_request_response, payload_too_large_response};
use crate::RustAuthAxumOptions;

pub(crate) async fn to_api_request(
    request: Request<Body>,
    options: RustAuthAxumOptions,
) -> Result<ApiRequest, axum::response::Response> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, options.body_limit)
        .await
        .map_err(body_error_response)?
        .to_vec();
    let mut request = Request::from_parts(parts, body);
    maybe_insert_client_ip(&mut request, options);
    Ok(request)
}

fn maybe_insert_client_ip(request: &mut ApiRequest, options: RustAuthAxumOptions) {
    if !options.use_connect_info_for_ip || request.extensions().get::<RequestClientIp>().is_some() {
        return;
    }

    let client_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(socket_addr)| socket_addr.ip());
    if let Some(client_ip) = client_ip {
        request.extensions_mut().insert(RequestClientIp(client_ip));
    }
}

fn body_error_response(error: axum::Error) -> axum::response::Response {
    if error
        .source()
        .is_some_and(|source| source.is::<LengthLimitError>())
    {
        payload_too_large_response()
    } else {
        bad_request_response()
    }
}
