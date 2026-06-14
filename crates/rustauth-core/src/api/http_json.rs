//! HTTP JSON wire-format helpers for Better Auth parity (`camelCase` keys).

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::db::{Session, User};
use crate::error::RustAuthError;

/// Converts logical / storage field names to HTTP JSON keys.
pub(crate) fn snake_to_camel(value: &str) -> String {
    let mut output = String::new();
    let mut uppercase_next = false;
    for character in value.chars() {
        if character == '_' {
            uppercase_next = true;
            continue;
        }
        if uppercase_next {
            output.extend(character.to_uppercase());
            uppercase_next = false;
        } else {
            output.push(character);
        }
    }
    output
}

/// HTTP wire representation of a [`User`] (camelCase keys).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_username: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// HTTP wire representation of a [`Session`] (camelCase keys).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpSession {
    pub id: String,
    pub user_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub token: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<&User> for HttpUser {
    fn from(user: &User) -> Self {
        Self {
            id: user.id.clone(),
            name: user.name.clone(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            image: user.image.clone(),
            username: user.username.clone(),
            display_username: user.display_username.clone(),
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

impl From<&Session> for HttpSession {
    fn from(session: &Session) -> Self {
        Self {
            id: session.id.clone(),
            user_id: session.user_id.clone(),
            expires_at: session.expires_at,
            token: session.token.clone(),
            ip_address: session.ip_address.clone(),
            user_agent: session.user_agent.clone(),
            created_at: session.created_at,
            updated_at: session.updated_at,
        }
    }
}

pub(crate) fn user_to_http_value(user: &User) -> Result<Value, RustAuthError> {
    serde_json::to_value(HttpUser::from(user)).map_err(|error| RustAuthError::Serialization {
        context: "serializing HTTP user output",
        message: error.to_string(),
    })
}

pub(crate) fn session_to_http_value(session: &Session) -> Result<Value, RustAuthError> {
    serde_json::to_value(HttpSession::from(session)).map_err(|error| RustAuthError::Serialization {
        context: "serializing HTTP session output",
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;
    use time::OffsetDateTime;

    /// Mirrors `SignInEmailBody` serde policy for fixture round-trips.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PilotSignInEmailBody {
        email: String,
        password: String,
        #[serde(default)]
        remember_me: Option<bool>,
        #[serde(default, rename = "callbackURL", alias = "callbackUrl")]
        callback_url: Option<String>,
    }

    /// Mirrors `SessionUserBody` serde policy for fixture round-trips.
    #[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PilotSessionUserBody {
        session: Map<String, Value>,
        user: Map<String, Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        needs_refresh: Option<bool>,
    }

    #[test]
    fn user_to_http_value_emits_camel_case_fields() -> Result<(), RustAuthError> {
        let now = OffsetDateTime::now_utc();
        let user = User {
            id: "user_1".to_owned(),
            name: "Ada".to_owned(),
            email: "ada@example.com".to_owned(),
            email_verified: true,
            image: None,
            username: None,
            display_username: Some("Ada Lovelace".to_owned()),
            created_at: now,
            updated_at: now,
        };
        let value = user_to_http_value(&user)?;
        assert_eq!(value["emailVerified"], true);
        assert_eq!(value["displayUsername"], "Ada Lovelace");
        assert!(value["createdAt"].as_str().is_some());
        assert!(value.get("email_verified").is_none());
        Ok(())
    }

    #[test]
    fn pilot_sign_in_email_body_round_trips_camel_case_fixture() -> Result<(), serde_json::Error> {
        let fixture = include_str!("../../tests/fixtures/http_json/sign_in_email_request.json");
        let body: PilotSignInEmailBody = serde_json::from_str(fixture)?;
        assert_eq!(body.email, "ada@example.com");
        assert_eq!(body.password, "secret123");
        assert_eq!(body.remember_me, Some(false));
        assert_eq!(body.callback_url.as_deref(), Some("/dashboard"));
        let encoded = serde_json::to_string(&body)?;
        let round_trip: PilotSignInEmailBody = serde_json::from_str(&encoded)?;
        assert_eq!(round_trip, body);
        assert!(encoded.contains("rememberMe"));
        assert!(encoded.contains("callbackURL"));
        Ok(())
    }

    #[test]
    fn pilot_get_session_body_round_trips_camel_case_fixture() -> Result<(), serde_json::Error> {
        let fixture = include_str!("../../tests/fixtures/http_json/get_session_response.json");
        let body: PilotSessionUserBody = serde_json::from_str(fixture)?;
        assert_eq!(body.session["userId"], "user_1");
        assert_eq!(body.user["emailVerified"], true);
        let encoded = serde_json::to_string(&body)?;
        let round_trip: PilotSessionUserBody = serde_json::from_str(&encoded)?;
        assert_eq!(round_trip, body);
        assert!(encoded.contains("emailVerified"));
        assert!(encoded.contains("expiresAt"));
        Ok(())
    }
}
