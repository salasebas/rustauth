pub mod account_linking;
pub mod errors;
pub mod state;
pub mod tokens;

pub use account_linking::{
    handle_oauth_user_info, HandleOAuthUserInfoInput, HandleOAuthUserInfoResult, OAuthAccountInput,
    OAuthSessionUser, OAuthUserInfo,
};
pub use errors::{missing_email_log_message, OAuthUserInfoError};
pub use state::{
    generate_oauth_state, oauth_state_identifier, parse_oauth_state, GeneratedOAuthState,
    OAuthStateData, OAuthStateInput, OAuthStateLink,
};
pub use tokens::{decrypt_oauth_token, set_token_util};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthBaseUrlOverride(pub String);
