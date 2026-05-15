pub mod permissions;
pub mod sessions;
pub mod users;

use openauth_core::api::ApiRequest;
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;

use super::cookies::cookie_header;
use super::models::{AdminSession, AdminUser};
use super::store::AdminStore;

pub async fn current_admin(
    context: &AuthContext,
    request: &ApiRequest,
) -> Result<Option<(AdminSession, AdminUser)>, OpenAuthError> {
    let Some(adapter) = context.adapter() else {
        return Ok(None);
    };
    let header = cookie_header(request);
    let Some(result) = SessionAuth::new(adapter.as_ref(), context)
        .get_session(GetSessionInput::new(header))
        .await?
    else {
        return Ok(None);
    };
    let Some(session) = result.session else {
        return Ok(None);
    };
    let Some((admin_session, admin_user)) = AdminStore::new(adapter.as_ref())
        .find_session(&session.token)
        .await?
    else {
        return Ok(None);
    };
    Ok(Some((admin_session, admin_user)))
}

pub fn permission(resource: &str, action: &str) -> crate::admin::PermissionMap {
    crate::admin::PermissionMap::from([(resource.to_owned(), vec![action.to_owned()])])
}

pub fn require_adapter(
    context: &AuthContext,
) -> Result<std::sync::Arc<dyn openauth_core::db::DbAdapter>, OpenAuthError> {
    context
        .adapter()
        .ok_or_else(|| OpenAuthError::Api("admin plugin requires a database adapter".to_owned()))
}

pub fn query_value(request: &ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key == name).then(|| percent_decode(value))
        })
    })
}

pub fn query_usize(request: &ApiRequest, name: &str) -> Option<usize> {
    query_value(request, name).and_then(|value| value.parse().ok())
}

fn percent_decode(input: &str) -> String {
    let mut output = String::new();
    let mut bytes = input.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => output.push(' '),
            b'%' => {
                let high = bytes.next().and_then(hex);
                let low = bytes.next().and_then(hex);
                if let (Some(high), Some(low)) = (high, low) {
                    output.push(char::from((high << 4) | low));
                }
            }
            byte => output.push(char::from(byte)),
        }
    }
    output
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
