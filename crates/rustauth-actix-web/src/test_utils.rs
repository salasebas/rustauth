//! Test helpers for exercising RustAuth Actix Web routes without peer address.

use std::net::{IpAddr, Ipv4Addr};

use actix_web::test::TestRequest;
use actix_web::{HttpMessage, HttpRequest};
use rustauth::rate_limit::RequestClientIp;

/// Inject a loopback client IP for rate limiting when using
/// `actix_web::test::call_service` without a real peer socket address.
pub fn with_loopback_client_ip(request: TestRequest) -> HttpRequest {
    let http_request = request.to_http_request();
    http_request
        .extensions_mut()
        .insert(RequestClientIp(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    http_request
}
