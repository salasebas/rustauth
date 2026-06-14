pub const AUTHN_REQUEST_PREFIX: &str = "saml-authn-request:";
pub const USED_ASSERTION_PREFIX: &str = "saml-used-assertion:";
pub const SESSION_PREFIX: &str = "saml-session:";
pub const SESSION_BY_ID_PREFIX: &str = "saml-session-by-id:";
pub const LOGOUT_REQUEST_PREFIX: &str = "saml-logout-request:";

pub fn authn_request_key(id: &str) -> String {
    format!("{AUTHN_REQUEST_PREFIX}{id}")
}

pub fn used_assertion_key(id: &str) -> String {
    format!("{USED_ASSERTION_PREFIX}{id}")
}

pub fn saml_session_key(provider_id: &str, name_id: &str) -> String {
    format!("{SESSION_PREFIX}{provider_id}:{name_id}")
}

pub fn saml_session_by_id_key(session_id: &str) -> String {
    format!("{SESSION_BY_ID_PREFIX}{session_id}")
}

pub fn logout_request_key(id: &str) -> String {
    format!("{LOGOUT_REQUEST_PREFIX}{id}")
}
