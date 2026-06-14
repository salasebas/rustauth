use ::http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use serde::Deserialize;

use crate::organization::http;
use crate::organization::store::OrganizationStore;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetActiveBody {
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    organization_slug: Option<String>,
}

pub(super) fn set_active() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/set-active",
        Method::POST,
        super::metadata::options(
            "organizationSetActive",
            vec![
                super::metadata::optional_string("organizationId"),
                super::metadata::optional_string("organizationSlug"),
            ],
        ),
        |context, request| async move {
            let adapter = context.require_adapter()?;
            let store = OrganizationStore::new(adapter.as_ref());
            let session = match http::current_session(&context, &request, &store).await? {
                Some(session) => session,
                None => {
                    return http::error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized")
                }
            };
            let input: SetActiveBody = http::body(&request)?;
            let organization_id = match (input.organization_id, input.organization_slug) {
                (Some(id), _) => Some(id),
                (None, Some(slug)) => store.organization_by_slug(&slug).await?.map(|org| org.id),
                (None, None) => None,
            };
            if let Some(organization_id) = &organization_id {
                if store
                    .member_by_org_user(organization_id, &session.user.id)
                    .await?
                    .is_none()
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
                    );
                }
            }
            store
                .set_active_organization(&session.session.token, organization_id.as_deref())
                .await?;
            http::json_with_cookies(
                StatusCode::OK,
                &serde_json::json!({ "success": true }),
                http::refreshed_session_cookies(&context, &session.session, &session.user)?,
            )
        },
    )
}
