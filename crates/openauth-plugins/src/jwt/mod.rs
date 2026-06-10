//! Server-side JWT and JWKS plugin.

mod adapter;
mod claims;
mod crypto;
mod endpoints;
mod keys;
mod options;
mod schema;
mod sign;
mod verify;

pub use claims::{to_exp_jwt, JwtClaims, TimeInput};
pub use keys::{Jwk, JwkAlgorithm, Jwks};
pub use options::{
    JwtAdapterOptions, JwtCreateJwkHandler, JwtDefinePayloadHandler, JwtGetJwksHandler,
    JwtGetSubjectHandler, JwtJwksOptions, JwtOptions, JwtSessionContext, JwtSignHandler,
    JwtSigningOptions,
};
pub use schema::JwtSchemaOptions;
pub use sign::sign_jwt;
pub use verify::{verify_jwt, verify_jwt_with_options};

use std::sync::Arc;

use http::header;
use openauth_core::context::request_state::{current_session, current_session_user};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{AuthPlugin, PluginAfterHookAction};

pub const UPSTREAM_PLUGIN_ID: &str = "jwt";

pub fn jwt() -> Result<AuthPlugin, OpenAuthError> {
    jwt_with(JwtOptions::default())
}

pub fn jwt_with(options: JwtOptions) -> Result<AuthPlugin, OpenAuthError> {
    options.validate()?;
    let options = Arc::new(options);
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_schema(schema::jwks_schema(&options.schema))
        .with_endpoint(endpoints::jwks_endpoint(Arc::clone(&options)))
        .with_endpoint(endpoints::token_endpoint(Arc::clone(&options)))
        .with_endpoint(endpoints::sign_jwt_endpoint(Arc::clone(&options)))
        .with_endpoint(endpoints::verify_jwt_endpoint(Arc::clone(&options)));

    if !options.disable_setting_jwt_header {
        let options_for_hook = Arc::clone(&options);
        plugin =
            plugin.with_async_after_hook("/get-session", move |context, _request, response| {
                let options = Arc::clone(&options_for_hook);
                Box::pin(async move {
                    let token = if let Some(current) = current_session()? {
                        endpoints::sign_session_token(
                            context,
                            &options,
                            current.session,
                            current.user,
                        )
                        .await?
                    } else {
                        let Some(user) = current_session_user()? else {
                            return Ok(PluginAfterHookAction::Continue(response));
                        };
                        let Some(user_id) = user
                            .get("id")
                            .and_then(|value| value.as_str())
                            .map(str::to_owned)
                        else {
                            return Ok(PluginAfterHookAction::Continue(response));
                        };
                        let mut claims = match user {
                            serde_json::Value::Object(map) => map,
                            _ => JwtClaims::new(),
                        };
                        claims.insert("sub".to_owned(), serde_json::Value::String(user_id));
                        sign::sign_jwt_with_options(context, claims, &options).await?
                    };
                    let mut response = response;
                    let token = header::HeaderValue::from_str(&token)
                        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
                    response.headers_mut().insert("set-auth-jwt", token);
                    expose_auth_jwt_header(response.headers_mut())?;
                    Ok(PluginAfterHookAction::Continue(response))
                })
            });
    }

    Ok(plugin)
}

fn expose_auth_jwt_header(headers: &mut header::HeaderMap) -> Result<(), OpenAuthError> {
    let current = headers
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let mut values = current
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if !values
        .iter()
        .any(|value| value.eq_ignore_ascii_case("set-auth-jwt"))
    {
        values.push("set-auth-jwt".to_owned());
    }
    let value = header::HeaderValue::from_str(&values.join(", "))
        .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, value);
    Ok(())
}
