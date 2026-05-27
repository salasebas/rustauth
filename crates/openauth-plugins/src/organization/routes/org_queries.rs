use ::http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions};

use crate::organization::additional_fields;
use crate::organization::http;
use crate::organization::models::{FullOrganization, Organization};
use crate::organization::options::OrganizationOptions;
use crate::organization::store::OrganizationStore;

use super::validation::query_param;

pub(super) fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    vec![get_full(options.clone()), list(options)]
}

fn get_full(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/get-full-organization",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationGetFull"),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = match http::current_session(context, &request, &store).await? {
                    Some(session) => session,
                    None => {
                        return http::error(
                            StatusCode::UNAUTHORIZED,
                            "UNAUTHORIZED",
                            "Unauthorized",
                        )
                    }
                };
                let Some(organization_id) = resolve_organization_id(
                    &store,
                    &request,
                    session.active_organization_id.as_deref(),
                )
                .await?
                else {
                    return http::json(StatusCode::OK, &serde_json::Value::Null);
                };
                let Some(mut organization) = store.organization_by_id(&organization_id).await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                retain_returned_organization_fields(&mut organization, &options);
                if store
                    .member_by_org_user(&organization_id, &session.user.id)
                    .await?
                    .is_none()
                {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
                    );
                }
                let mut members = store.members(&organization_id).await?;
                if let Some(limit) = optional_usize_query(&request, "membersLimit") {
                    members.truncate(limit);
                }
                let teams = if options.teams.enabled {
                    store.teams_for_organization(&organization_id).await?
                } else {
                    Vec::new()
                };
                http::json(
                    StatusCode::OK,
                    &FullOrganization {
                        organization,
                        members,
                        invitations: store.invitations_for_organization(&organization_id).await?,
                        teams,
                    },
                )
            })
        },
    )
}

fn list(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/list",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationList"),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = match http::current_session(context, &request, &store).await? {
                    Some(session) => session,
                    None => {
                        return http::error(
                            StatusCode::UNAUTHORIZED,
                            "UNAUTHORIZED",
                            "Unauthorized",
                        )
                    }
                };
                let mut organizations = store.organizations_for_user(&session.user.id).await?;
                for organization in &mut organizations {
                    retain_returned_organization_fields(organization, &options);
                }
                http::json(StatusCode::OK, &organizations)
            })
        },
    )
}

fn retain_returned_organization_fields(
    organization: &mut Organization,
    options: &OrganizationOptions,
) {
    additional_fields::retain_returned(
        &mut organization.additional_fields,
        &options.schema.organization.additional_fields,
    );
}

async fn resolve_organization_id(
    store: &OrganizationStore<'_>,
    request: &openauth_core::api::ApiRequest,
    active_organization_id: Option<&str>,
) -> Result<Option<String>, openauth_core::error::OpenAuthError> {
    if let Some(slug) = query_param(request, "organizationSlug") {
        return match store.organization_by_slug(&slug).await? {
            Some(organization) => Ok(Some(organization.id)),
            None => Err(openauth_core::error::OpenAuthError::Api(
                "ORGANIZATION_NOT_FOUND".to_owned(),
            )),
        };
    }
    if let Some(id) = query_param(request, "organizationId") {
        return Ok(Some(id));
    }
    Ok(active_organization_id.map(str::to_owned))
}

fn optional_usize_query(request: &openauth_core::api::ApiRequest, name: &str) -> Option<usize> {
    query_param(request, name).and_then(|value| value.parse().ok())
}
