use http::header;
use openauth_core::api::{ApiRequest, ApiResponse};
use openauth_core::auth::session::{GetSessionInput, SessionAuth};
use openauth_core::context::request_state::current_new_session;
use openauth_core::context::AuthContext;
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::{PluginAfterHookAction, PluginBeforeHookAction};
use std::sync::Arc;

use crate::linking::assign_organization_by_domain;
use crate::options::SsoOptions;
use crate::saml::state::{saml_session_by_id_key, SESSION_PREFIX};
use crate::state::SsoStateStore;

#[derive(Debug, Clone)]
struct SignOutSamlSession {
    session_id: String,
}

pub(crate) async fn capture_sign_out_session(
    context: &AuthContext,
    mut request: ApiRequest,
) -> Result<PluginBeforeHookAction, OpenAuthError> {
    let Some(adapter) = context.adapter.as_deref() else {
        return Ok(PluginBeforeHookAction::Continue(request));
    };
    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let Some(session_result) = SessionAuth::new(adapter, context)
        .get_session(GetSessionInput::new(cookie_header).disable_refresh())
        .await?
    else {
        return Ok(PluginBeforeHookAction::Continue(request));
    };
    if let Some(session) = session_result.session {
        request.extensions_mut().insert(SignOutSamlSession {
            session_id: session.id,
        });
    }
    Ok(PluginBeforeHookAction::Continue(request))
}

pub(crate) async fn cleanup_sign_out_session(
    context: &AuthContext,
    request: &ApiRequest,
    response: ApiResponse,
) -> Result<PluginAfterHookAction, OpenAuthError> {
    if response.status().is_success() {
        if let (Some(adapter), Some(session)) = (
            context.adapter.as_deref(),
            request.extensions().get::<SignOutSamlSession>(),
        ) {
            clear_saml_session_lookup_state(context, adapter, &session.session_id).await?;
        }
    }
    Ok(PluginAfterHookAction::Continue(response))
}

pub(crate) async fn assign_domain_organization_after_auth(
    context: &AuthContext,
    _request: &ApiRequest,
    response: ApiResponse,
    options: Arc<SsoOptions>,
) -> Result<PluginAfterHookAction, OpenAuthError> {
    if !response.status().is_success() {
        return Ok(PluginAfterHookAction::Continue(response));
    }
    let Some(adapter) = context.adapter.as_deref() else {
        return Ok(PluginAfterHookAction::Continue(response));
    };
    let Some(new_session) = current_new_session()? else {
        return Ok(PluginAfterHookAction::Continue(response));
    };
    assign_organization_by_domain(
        context,
        adapter,
        &options.organization_provisioning,
        &options.domain_verification,
        &new_session.user,
    )
    .await?;
    Ok(PluginAfterHookAction::Continue(response))
}

pub(crate) async fn clear_saml_session_lookup_state(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    session_id: &str,
) -> Result<(), OpenAuthError> {
    let state_store = SsoStateStore::new(context, adapter);
    let by_id_identifier = saml_session_by_id_key(session_id);
    let Some(by_id) = state_store.find(&by_id_identifier).await? else {
        return Ok(());
    };
    if by_id.value.starts_with(SESSION_PREFIX) {
        state_store.delete(&by_id.value).await?;
    }
    state_store.delete(&by_id_identifier).await
}
