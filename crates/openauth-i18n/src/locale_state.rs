//! Request-scoped locale detected before synchronous response translation.

use std::sync::OnceLock;

use openauth_core::context::request_state::{define_request_state, has_request_state};
use openauth_core::error::OpenAuthError;

static DETECTED_LOCALE: OnceLock<
    openauth_core::context::request_state::RequestState<Option<String>>,
> = OnceLock::new();

fn detected_locale_state(
) -> &'static openauth_core::context::request_state::RequestState<Option<String>> {
    DETECTED_LOCALE.get_or_init(|| define_request_state(|| None))
}

pub(crate) fn set_detected_locale(locale: String) -> Result<(), OpenAuthError> {
    detected_locale_state().set(Some(locale))
}

pub(crate) fn detected_locale() -> Result<Option<String>, OpenAuthError> {
    if !has_request_state() {
        return Ok(None);
    }
    detected_locale_state().get()
}
