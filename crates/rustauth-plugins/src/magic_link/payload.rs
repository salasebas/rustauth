use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub(crate) struct SignInMagicLinkBody {
    pub email: String,
    pub name: Option<String>,
    #[serde(default, alias = "callbackURL")]
    pub callback_url: Option<String>,
    #[serde(default, alias = "newUserCallbackURL")]
    pub new_user_callback_url: Option<String>,
    #[serde(default, alias = "errorCallbackURL")]
    pub error_callback_url: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifyMagicLinkQuery {
    pub token: String,
    pub callback_url: Option<String>,
    pub error_callback_url: Option<String>,
    pub new_user_callback_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct VerificationPayload {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub attempt: u64,
}

pub(crate) fn parse_verify_query(query: Option<&str>) -> VerifyMagicLinkQuery {
    let mut parsed = VerifyMagicLinkQuery {
        token: String::new(),
        callback_url: None,
        error_callback_url: None,
        new_user_callback_url: None,
    };

    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "token" => parsed.token = value.into_owned(),
            "callbackURL" => parsed.callback_url = Some(value.into_owned()),
            "errorCallbackURL" => parsed.error_callback_url = Some(value.into_owned()),
            "newUserCallbackURL" => parsed.new_user_callback_url = Some(value.into_owned()),
            _ => {}
        }
    }

    parsed
}
