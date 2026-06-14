//! Test helpers for exercising RustAuth Axum routes without `ConnectInfo`.

use std::net::{IpAddr, Ipv4Addr};

use axum::http::Request;
use rustauth::rate_limit::RequestClientIp;

/// Inject a loopback client IP for rate limiting when using
/// `tower::ServiceExt::oneshot` without Axum [`ConnectInfo`].
pub fn with_loopback_client_ip<B>(mut request: Request<B>) -> Request<B> {
    request
        .extensions_mut()
        .insert(RequestClientIp(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    request
}
