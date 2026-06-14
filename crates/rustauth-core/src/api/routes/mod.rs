//! Framework-neutral auth route builders.

use http::Method;

use crate::api::AsyncAuthEndpoint;

mod account;
mod change_email;
mod delete_user;
pub(in crate::api) mod email_verification;
mod error;
mod password;
mod session;
mod shared;
mod sign_in;
mod sign_out;
mod sign_up;
#[cfg(feature = "oauth")]
mod social;
mod update_user;

/// Build Better Auth-inspired core endpoints backed by an RustAuth database adapter.
///
/// The returned endpoints are framework-neutral and can be passed to
/// `AuthRouter::with_async_endpoints` or the public `rustauth_with_endpoints`
/// initializer. Concrete web frameworks only need to adapt HTTP requests and
/// responses at their edge.
pub fn core_auth_async_endpoints() -> Vec<AsyncAuthEndpoint> {
    vec![
        sign_up::sign_up_email_endpoint(),
        sign_in::sign_in_email_endpoint(),
        #[cfg(feature = "oauth")]
        social::sign_in_social_endpoint(),
        #[cfg(feature = "oauth")]
        social::callback_oauth_endpoint(Method::GET),
        #[cfg(feature = "oauth")]
        social::callback_oauth_endpoint(Method::POST),
        #[cfg(feature = "oauth")]
        social::link_social_endpoint(),
        error::error_endpoint(),
        session::get_session_endpoint(Method::GET),
        session::get_session_endpoint(Method::POST),
        session::list_sessions_endpoint(),
        session::update_session_endpoint(),
        session::revoke_session_endpoint(),
        session::revoke_sessions_endpoint(),
        session::revoke_other_sessions_endpoint(),
        account::list_user_accounts_endpoint(),
        account::unlink_account_endpoint(),
        #[cfg(feature = "oauth")]
        account::get_access_token_endpoint(),
        #[cfg(feature = "oauth")]
        account::refresh_token_endpoint(),
        #[cfg(feature = "oauth")]
        account::account_info_endpoint(),
        update_user::update_user_endpoint(),
        change_email::change_email_endpoint(),
        email_verification::send_verification_email_endpoint(),
        email_verification::verify_email_endpoint(),
        delete_user::delete_user_endpoint(),
        delete_user::delete_user_callback_endpoint(),
        password::change_password_endpoint(),
        password::set_password_endpoint(),
        password::verify_password_endpoint(),
        password::request_password_reset_endpoint(),
        password::reset_password_callback_endpoint(),
        password::reset_password_endpoint(),
        sign_out::sign_out_endpoint(),
    ]
}
