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
    generate_oauth_state, oauth_state_identifier, parse_oauth_state, parse_oauth_state_with_input,
    GeneratedOAuthState, OAuthStateData, OAuthStateInput, OAuthStateLink, OAuthStateParseInput,
};
pub use tokens::{
    decrypt_oauth_token, decrypt_optional_oauth_token, encrypt_oauth_tokens_for_storage,
    set_token_util, StoredOAuthTokens,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthBaseUrlOverride(pub String);
