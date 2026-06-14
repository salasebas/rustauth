//! Client-side helpers for calling the public auth HTTP API from your backend.

pub mod flows;
pub mod requests;
pub mod responses;

pub use flows::register_and_sign_in;
pub use requests::{
    absolute_uri, get_session, sign_in_email, sign_out, sign_up_email, SignInEmailBody,
    SignUpEmailBody,
};
pub use responses::{parse_json_body, session_cookie, AuthSessionResponse};
