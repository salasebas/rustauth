use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneTapOptions {
    #[serde(default)]
    pub disable_signup: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

impl OneTapOptions {
    #[must_use]
    pub fn builder() -> OneTapOptionsBuilder {
        OneTapOptionsBuilder::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct OneTapOptionsBuilder {
    disable_signup: Option<bool>,
    client_id: Option<Option<String>>,
}

impl OneTapOptionsBuilder {
    #[must_use]
    pub fn disable_signup(mut self, disable_signup: bool) -> Self {
        self.disable_signup = Some(disable_signup);
        self
    }

    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(Some(client_id.into()));
        self
    }

    #[must_use]
    pub fn build(self) -> OneTapOptions {
        let defaults = OneTapOptions::default();
        OneTapOptions {
            disable_signup: self.disable_signup.unwrap_or(defaults.disable_signup),
            client_id: self.client_id.unwrap_or(defaults.client_id),
        }
    }
}
