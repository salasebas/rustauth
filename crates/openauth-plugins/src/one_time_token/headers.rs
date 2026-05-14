use http::{header, HeaderValue};
use openauth_core::api::ApiResponse;
use openauth_core::context::request_state::current_new_session;
use openauth_core::context::AuthContext;
use openauth_core::error::OpenAuthError;

use super::endpoints::generate_and_store_token;
use super::options::{OneTimeTokenOptions, OneTimeTokenSession};

pub async fn set_ott_header_on_new_session(
    context: &AuthContext,
    mut response: ApiResponse,
    options: &OneTimeTokenOptions,
) -> Result<ApiResponse, OpenAuthError> {
    if !options.set_ott_header_on_new_session {
        return Ok(response);
    }
    let Some(new_session) = current_new_session()? else {
        return Ok(response);
    };
    let Some(adapter) = context.adapter() else {
        return Err(OpenAuthError::InvalidConfig(
            "one-time-token plugin requires a database adapter".to_owned(),
        ));
    };

    let token = generate_and_store_token(
        adapter.as_ref(),
        context,
        &OneTimeTokenSession {
            session: new_session.session,
            user: new_session.user,
        },
        options,
    )
    .await?;
    response.headers_mut().insert(
        "set-ott",
        HeaderValue::from_str(&token).map_err(|error| OpenAuthError::Api(error.to_string()))?,
    );
    expose_set_ott_header(&mut response)?;
    Ok(response)
}

fn expose_set_ott_header(response: &mut ApiResponse) -> Result<(), OpenAuthError> {
    let exposed = response
        .headers()
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let mut headers = exposed
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !headers
        .iter()
        .any(|header| header.eq_ignore_ascii_case("set-ott"))
    {
        headers.push("set-ott".to_owned());
    }
    let value = HeaderValue::from_str(&headers.join(", "))
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    response
        .headers_mut()
        .insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, value);
    Ok(())
}
