use actix_web::web::Payload;
use actix_web::{HttpMessage, HttpRequest};
use http::Request;
use rustauth::api::{ApiRequest, RequestBaseUrl};
use rustauth::auth::oauth::OAuthBaseUrlOverride;
use rustauth::rate_limit::RequestClientIp;

use crate::error::{bad_request_response, payload_too_large_response};
use crate::RustAuthActixWebOptions;

pub(crate) async fn to_api_request(
    request: HttpRequest,
    payload: Payload,
    options: RustAuthActixWebOptions,
) -> Result<ApiRequest, actix_web::HttpResponse> {
    let body = match actix_web::web::Payload::to_bytes_limited(payload, options.body_limit).await {
        Ok(Ok(bytes)) => bytes.to_vec(),
        Ok(Err(_)) => return Err(bad_request_response()),
        Err(_) => return Err(payload_too_large_response()),
    };

    let method = http::Method::from_bytes(request.method().as_str().as_bytes())
        .map_err(|_| bad_request_response())?;
    let version = match request.version() {
        actix_web::http::Version::HTTP_10 => http::Version::HTTP_10,
        actix_web::http::Version::HTTP_2 => http::Version::HTTP_2,
        _ => http::Version::HTTP_11,
    };

    let mut builder = Request::builder()
        .method(method)
        .uri(request.uri().to_string())
        .version(version);
    for (name, value) in request.headers().iter() {
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    let mut api_request = builder.body(body).map_err(|_| bad_request_response())?;

    copy_request_extensions(&request, &mut api_request);
    maybe_insert_client_ip(&mut api_request, &request, options);
    Ok(api_request)
}

fn copy_request_extensions(request: &HttpRequest, api_request: &mut ApiRequest) {
    if let Some(client_ip) = request.extensions().get::<RequestClientIp>() {
        api_request
            .extensions_mut()
            .insert(RequestClientIp(client_ip.0));
    }
    if let Some(base_url) = request.extensions().get::<RequestBaseUrl>() {
        api_request
            .extensions_mut()
            .insert(RequestBaseUrl(base_url.0.clone()));
    }
    if let Some(override_url) = request.extensions().get::<OAuthBaseUrlOverride>() {
        api_request
            .extensions_mut()
            .insert(OAuthBaseUrlOverride(override_url.0.clone()));
    }
}

fn maybe_insert_client_ip(
    api_request: &mut ApiRequest,
    request: &HttpRequest,
    options: RustAuthActixWebOptions,
) {
    if !options.use_peer_addr_for_ip || api_request.extensions().get::<RequestClientIp>().is_some()
    {
        return;
    }

    if let Some(peer) = request.peer_addr() {
        api_request
            .extensions_mut()
            .insert(RequestClientIp(peer.ip()));
    }
}
