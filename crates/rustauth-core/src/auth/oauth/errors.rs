use std::error::Error;
use std::fmt;

use crate::error::RustAuthError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthUserInfoError {
    AccountNotLinked,
    SignupDisabled,
    UnableToCreateUser,
    UnableToCreateSession,
    UnableToLinkAccount,
}

impl OAuthUserInfoError {
    pub fn code_str(self) -> &'static str {
        match self {
            Self::AccountNotLinked => "account_not_linked",
            Self::SignupDisabled => "signup_disabled",
            Self::UnableToCreateUser => "unable_to_create_user",
            Self::UnableToCreateSession => "unable_to_create_session",
            Self::UnableToLinkAccount => "unable_to_link_account",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::AccountNotLinked => "Account not linked",
            Self::SignupDisabled => "Signup disabled",
            Self::UnableToCreateUser => "Unable to create user",
            Self::UnableToCreateSession => "Unable to create session",
            Self::UnableToLinkAccount => "Unable to link account",
        }
    }
}

impl fmt::Display for OAuthUserInfoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code_str(), self.message())
    }
}

impl Error for OAuthUserInfoError {}

impl From<OAuthUserInfoError> for RustAuthError {
    fn from(error: OAuthUserInfoError) -> Self {
        Self::OAuth(error.to_string())
    }
}

const HANDLING_DOCS_URL: &str =
    "https://www.better-auth.com/docs/concepts/oauth#handling-providers-without-email";

pub fn missing_email_log_message(provider_id: &str, source: Option<&str>) -> String {
    let subject = if source == Some("generic") {
        format!("Generic OAuth provider \"{provider_id}\"")
    } else {
        format!("Provider \"{provider_id}\"")
    };
    let where_text = if source == Some("id_token") {
        " in the id token"
    } else {
        ""
    };
    format!(
        "{subject} did not return an email{where_text}. Either request the provider's email scope, or synthesize one via `mapProfileToUser`. See {HANDLING_DOCS_URL}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_user_info_error_bridges_to_rustauth_error() {
        let error = OAuthUserInfoError::AccountNotLinked;
        let bridged: RustAuthError = error.into();
        assert_eq!(
            bridged,
            RustAuthError::OAuth("account_not_linked: Account not linked".to_owned())
        );
    }

    #[test]
    fn oauth_user_info_error_code_str_matches_http_helpers() {
        assert_eq!(
            OAuthUserInfoError::SignupDisabled.code_str(),
            "signup_disabled"
        );
        assert_eq!(
            OAuthUserInfoError::UnableToLinkAccount.message(),
            "Unable to link account"
        );
    }
}
