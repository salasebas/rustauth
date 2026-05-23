use std::error::Error as _;
use std::net::SocketAddr;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::Request;
use http_body_util::LengthLimitError;
use openauth::{ApiRequest, RequestClientIp};

use crate::error::{bad_request_response, payload_too_large_response};
use crate::OpenAuthAxumOptions;

pub(crate) async fn to_api_request(
    request: Request<Body>,
    options: OpenAuthAxumOptions,
) -> Result<ApiRequest, axum::response::Response> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, options.body_limit)
        .await
        .map_err(body_error_response)?
        .to_vec();
    let headers = parts.headers;
    let extensions = parts.extensions;
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(parts.uri)
        .version(parts.version);
    let Some(builder_headers) = builder.headers_mut() else {
        return Err(bad_request_response());
    };
    *builder_headers = headers;
    let mut request = builder
        .body(body)
        .map_err(|_error| bad_request_response())?;
    *request.extensions_mut() = extensions;
    maybe_insert_client_ip(&mut request, options);
    Ok(request)
}

fn maybe_insert_client_ip(request: &mut ApiRequest, options: OpenAuthAxumOptions) {
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
