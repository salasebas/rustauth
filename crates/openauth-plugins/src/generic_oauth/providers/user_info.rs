use openauth_oauth::oauth2::{OAuth2Tokens, OAuth2UserInfo, OAuthError};
use serde_json::Value;

use super::super::user_info;

pub async fn gumroad(tokens: OAuth2Tokens) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    let Some(profile) = bearer_json(
        "https://api.gumroad.com/v2/user",
        tokens.access_token.as_deref(),
    )
    .await?
    else {
        return Ok(None);
    };
    Ok(map_gumroad_profile(&profile))
}

pub async fn hubspot(tokens: OAuth2Tokens) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    let Some(access_token) = tokens.access_token.as_deref() else {
        return Ok(None);
    };
    let profile = reqwest::Client::new()
        .get(format!(
            "https://api.hubapi.com/oauth/v1/access-tokens/{access_token}"
        ))
        .header("content-type", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    Ok(map_hubspot_profile(&profile))
}

pub async fn line(tokens: OAuth2Tokens) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    if let Some(id_token) = tokens.id_token.as_deref() {
        if let Some(user) = user_info::decode_id_token_claims(id_token)
            .as_ref()
            .and_then(map_line_profile)
        {
            return Ok(Some(user));
        }
    }
    let profile = bearer_json(
        "https://api.line.me/oauth2/v2.1/userinfo",
        tokens.access_token.as_deref(),
    )
    .await?;
    Ok(profile.as_ref().and_then(map_line_profile))
}

pub async fn microsoft_entra_id(
    tokens: OAuth2Tokens,
) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    let profile = bearer_json(
        "https://graph.microsoft.com/oidc/userinfo",
        tokens.access_token.as_deref(),
    )
    .await?;
    Ok(profile.as_ref().and_then(map_microsoft_entra_profile))
}

pub async fn patreon(tokens: OAuth2Tokens) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    let profile = bearer_json(
        "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified",
        tokens.access_token.as_deref(),
    )
    .await?;
    Ok(profile.as_ref().and_then(map_patreon_profile))
}

pub async fn slack(tokens: OAuth2Tokens) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    let profile = bearer_json(
        "https://slack.com/api/openid.connect.userInfo",
        tokens.access_token.as_deref(),
    )
    .await?;
    Ok(profile.as_ref().and_then(map_slack_profile))
}

fn map_gumroad_profile(profile: &Value) -> Option<OAuth2UserInfo> {
    let user = profile.get("user")?;
    if profile.get("success").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    Some(OAuth2UserInfo {
        id: string_value(user, "user_id")?,
        name: string_value(user, "name"),
        email: string_value(user, "email"),
        image: string_value(user, "profile_url"),
        email_verified: false,
    })
}

fn map_hubspot_profile(profile: &Value) -> Option<OAuth2UserInfo> {
    let id = string_value(profile, "user_id").or_else(|| {
        profile
            .get("signed_access_token")
            .and_then(|value| string_value(value, "userId"))
    })?;
    Some(OAuth2UserInfo {
        id,
        name: string_value(profile, "user"),
        email: string_value(profile, "user"),
        image: None,
        email_verified: false,
    })
}

fn map_line_profile(profile: &Value) -> Option<OAuth2UserInfo> {
    Some(OAuth2UserInfo {
        id: string_value(profile, "sub")?,
        name: string_value(profile, "name"),
        email: string_value(profile, "email"),
        image: string_value(profile, "picture"),
        email_verified: false,
    })
}

fn map_microsoft_entra_profile(profile: &Value) -> Option<OAuth2UserInfo> {
    Some(OAuth2UserInfo {
        id: string_value(profile, "sub")?,
        name: string_value(profile, "name").or_else(|| full_name(profile)),
        email: string_value(profile, "email")
            .or_else(|| string_value(profile, "preferred_username")),
        image: string_value(profile, "picture"),
        email_verified: profile
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn map_patreon_profile(profile: &Value) -> Option<OAuth2UserInfo> {
    let data = profile.get("data")?;
    let attributes = data.get("attributes")?;
    Some(OAuth2UserInfo {
        id: string_value(data, "id")?,
        name: string_value(attributes, "full_name"),
        email: string_value(attributes, "email"),
        image: string_value(attributes, "image_url"),
        email_verified: attributes
            .get("is_email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn map_slack_profile(profile: &Value) -> Option<OAuth2UserInfo> {
    Some(OAuth2UserInfo {
        id: string_value(profile, "https://slack.com/user_id")
            .or_else(|| string_value(profile, "sub"))?,
        name: string_value(profile, "name"),
        email: string_value(profile, "email"),
        image: string_value(profile, "picture")
            .or_else(|| string_value(profile, "https://slack.com/user_image_512")),
        email_verified: profile
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

async fn bearer_json(url: &str, access_token: Option<&str>) -> Result<Option<Value>, OAuthError> {
    let Some(access_token) = access_token else {
        return Ok(None);
    };
    let profile = reqwest::Client::new()
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    Ok(Some(profile))
}

fn string_value(profile: &Value, key: &str) -> Option<String> {
    match profile.get(key)? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn full_name(profile: &Value) -> Option<String> {
    let given = string_value(profile, "given_name").unwrap_or_default();
    let family = string_value(profile, "family_name").unwrap_or_default();
    let name = format!("{given} {family}").trim().to_owned();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        reason = "fixture tests should fail immediately when a fixture no longer maps"
    )]

    use serde_json::json;

    use super::{
        map_gumroad_profile, map_hubspot_profile, map_line_profile, map_microsoft_entra_profile,
        map_patreon_profile, map_slack_profile,
    };

    #[test]
    fn maps_gumroad_profile() {
        let Some(user) = map_gumroad_profile(&json!({
            "success": true,
            "user": {
                "user_id": "gum-1",
                "name": "Ada",
                "email": "ada@example.com",
                "profile_url": "https://img.example.com/ada.png"
            }
        })) else {
            panic!("expected gumroad fixture to map");
        };

        assert_eq!(user.id, "gum-1");
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert!(!user.email_verified);
    }

    #[test]
    fn maps_hubspot_profile() {
        let Some(user) = map_hubspot_profile(&json!({
            "user": "ada@example.com",
            "signed_access_token": { "userId": 42 }
        })) else {
            panic!("expected hubspot fixture to map");
        };

        assert_eq!(user.id, "42");
        assert_eq!(user.name.as_deref(), Some("ada@example.com"));
    }

    #[test]
    fn maps_line_profile() {
        let Some(user) = map_line_profile(&json!({
            "sub": "line-1",
            "name": "Ada",
            "email": "ada@example.com",
            "picture": "https://img.example.com/line.png"
        })) else {
            panic!("expected line fixture to map");
        };

        assert_eq!(user.id, "line-1");
        assert_eq!(
            user.image.as_deref(),
            Some("https://img.example.com/line.png")
        );
    }

    #[test]
    fn maps_microsoft_entra_profile() {
        let Some(user) = map_microsoft_entra_profile(&json!({
            "sub": "ms-1",
            "given_name": "Ada",
            "family_name": "Lovelace",
            "preferred_username": "ada@example.com"
        })) else {
            panic!("expected microsoft entra fixture to map");
        };

        assert_eq!(user.name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert!(!user.email_verified);
    }

    #[test]
    fn maps_patreon_profile() {
        let Some(user) = map_patreon_profile(&json!({
            "data": {
                "id": "pat-1",
                "attributes": {
                    "full_name": "Ada",
                    "email": "ada@example.com",
                    "image_url": "https://img.example.com/patreon.png",
                    "is_email_verified": true
                }
            }
        })) else {
            panic!("expected patreon fixture to map");
        };

        assert_eq!(user.id, "pat-1");
        assert!(user.email_verified);
    }

    #[test]
    fn maps_slack_profile() {
        let Some(user) = map_slack_profile(&json!({
            "sub": "slack-sub",
            "https://slack.com/user_id": "slack-1",
            "email": "ada@example.com",
            "email_verified": true,
            "name": "Ada",
            "https://slack.com/user_image_512": "https://img.example.com/slack.png"
        })) else {
            panic!("expected slack fixture to map");
        };

        assert_eq!(user.id, "slack-1");
        assert_eq!(
            user.image.as_deref(),
            Some("https://img.example.com/slack.png")
        );
    }
}
