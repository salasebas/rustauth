use openauth_oauth::oauth2::{OAuth2Tokens, OAuth2UserInfo, OAuthError};
use serde_json::Value;

pub async fn get_user_info(
    tokens: &OAuth2Tokens,
    user_info_url: Option<&str>,
) -> Result<Option<OAuth2UserInfo>, OAuthError> {
    if let Some(id_token) = tokens.id_token.as_deref() {
        if let Some(user) =
            user_info_from_claims(&decode_id_token_claims(id_token).unwrap_or(Value::Null))
        {
            return Ok(Some(user));
        }
    }
    let Some(url) = user_info_url else {
        return Ok(None);
    };
    let Some(access_token) = tokens.access_token.as_deref() else {
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
    Ok(user_info_from_claims(&profile))
}

pub fn decode_id_token_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = decode_base64_url(payload)?;
    serde_json::from_slice(&bytes).ok()
}

pub fn user_info_from_claims(profile: &Value) -> Option<OAuth2UserInfo> {
    let id = string_value(profile, "sub")
        .or_else(|| string_value(profile, "id"))
        .or_else(|| string_value(profile, "user_id"))
        .unwrap_or_default();
    if id.is_empty() {
        return None;
    }
    Some(OAuth2UserInfo {
        id,
        name: string_value(profile, "name")
            .or_else(|| string_value(profile, "preferred_username"))
            .or_else(|| full_name(profile)),
        email: string_value(profile, "email")
            .or_else(|| string_value(profile, "preferred_username")),
        image: string_value(profile, "picture").or_else(|| string_value(profile, "image")),
        email_verified: profile
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
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

fn decode_base64_url(input: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut bit_count = 0u8;
    let mut output = Vec::new();
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Some(output)
}
