//! Request IP extraction for CAPTCHA verification.

use openauth_core::api::ApiRequest;
use openauth_core::context::AuthContext;
use openauth_core::utils::ip::{is_valid_ip, normalize_ip_with_options, NormalizeIpOptions};

pub(crate) fn request_ip(context: &AuthContext, request: &ApiRequest) -> Option<String> {
    if context.options.advanced.ip_address.disable_ip_tracking {
        return None;
    }

    for header_name in &context.options.advanced.ip_address.headers {
        let Some(value) = request
            .headers()
            .get(header_name.as_str())
            .and_then(|value| value.to_str().ok())
        else {
            continue;
        };
        for candidate in value.split(',').map(str::trim) {
            if candidate.is_empty() || !is_valid_ip(candidate) {
                continue;
            }
            return Some(normalize_ip_with_options(
                candidate,
                NormalizeIpOptions {
                    ipv6_subnet: context.options.advanced.ip_address.ipv6_subnet,
                },
            ));
        }
    }

    None
}
