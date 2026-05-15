use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneTapOptions {
    #[serde(default)]
    pub disable_signup: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}
