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
    let Some(user) = profile.get("user") else {
        return Ok(None);
    };
    if profile.get("success").and_then(Value::as_bool) != Some(true) {
        return Ok(None);
    }
    Ok(Some(OAuth2UserInfo {
        id: string_value(user, "user_id").unwrap_or_default(),
        name: string_value(user, "name"),
        email: string_value(user, "email"),
        image: string_value(user, "profile_url"),
        email_verified: false,
    })
    .filter(|user| !user.id.is_empty()))
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
    let id = string_value(&profile, "user_id").or_else(|| {
        profile
            .get("signed_access_token")
            .and_then(|value| string_value(value, "userId"))
    });
    Ok(id.map(|id| OAuth2UserInfo {
        id,
        name: string_value(&profile, "user"),
        email: string_value(&profile, "user"),
        image: None,
        email_verified: false,
    }))
}

pub async fn line(tokens: OAuth2Tokens) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    if let Some(id_token) = tokens.id_token.as_deref() {
        if let Some(user) = user_info::decode_id_token_claims(id_token)
            .as_ref()
            .and_then(line_profile)
        {
            return Ok(Some(user));
        }
    }
    let profile = bearer_json(
        "https://api.line.me/oauth2/v2.1/userinfo",
        tokens.access_token.as_deref(),
    )
    .await?;
    Ok(profile.as_ref().and_then(line_profile))
}

pub async fn microsoft_entra_id(
    tokens: OAuth2Tokens,
) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    let profile = bearer_json(
        "https://graph.microsoft.com/oidc/userinfo",
        tokens.access_token.as_deref(),
    )
    .await?;
    Ok(profile.and_then(|profile| {
        let id = string_value(&profile, "sub")?;
        Some(OAuth2UserInfo {
            id,
            name: string_value(&profile, "name").or_else(|| full_name(&profile)),
            email: string_value(&profile, "email")
                .or_else(|| string_value(&profile, "preferred_username")),
            image: string_value(&profile, "picture"),
            email_verified: profile
                .get("email_verified")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }))
}

pub async fn patreon(tokens: OAuth2Tokens) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    let profile = bearer_json(
        "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified",
        tokens.access_token.as_deref(),
    )
    .await?;
    Ok(profile.and_then(|profile| {
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
    }))
}

pub async fn slack(tokens: OAuth2Tokens) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    let profile = bearer_json(
        "https://slack.com/api/openid.connect.userInfo",
        tokens.access_token.as_deref(),
    )
    .await?;
    Ok(profile.and_then(|profile| {
        let id = string_value(&profile, "https://slack.com/user_id")
            .or_else(|| string_value(&profile, "sub"))?;
        Some(OAuth2UserInfo {
            id,
            name: string_value(&profile, "name"),
            email: string_value(&profile, "email"),
            image: string_value(&profile, "picture")
                .or_else(|| string_value(&profile, "https://slack.com/user_image_512")),
            email_verified: profile
                .get("email_verified")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }))
}

fn line_profile(profile: &Value) -> Option<OAuth2UserInfo> {
    Some(OAuth2UserInfo {
        id: string_value(profile, "sub")?,
        name: string_value(profile, "name"),
        email: string_value(profile, "email"),
        image: string_value(profile, "picture"),
        email_verified: false,
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
