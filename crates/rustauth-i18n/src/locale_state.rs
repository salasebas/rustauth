//! Request-scoped locale detected before synchronous response translation.

use std::sync::OnceLock;

use rustauth_core::context::request_state::{define_request_state, has_request_state};
use rustauth_core::error::RustAuthError;

static DETECTED_LOCALE: OnceLock<
    rustauth_core::context::request_state::RequestState<Option<String>>,
> = OnceLock::new();

fn detected_locale_state(
) -> &'static rustauth_core::context::request_state::RequestState<Option<String>> {
    DETECTED_LOCALE.get_or_init(|| define_request_state(|| None))
}

pub(crate) fn set_detected_locale(locale: String) -> Result<(), RustAuthError> {
    detected_locale_state().set(Some(locale))
}

pub(crate) fn detected_locale() -> Result<Option<String>, RustAuthError> {
    if !has_request_state() {
        return Ok(None);
    }
    detected_locale_state().get()
}
