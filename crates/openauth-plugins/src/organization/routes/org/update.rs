use ::http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use serde::Deserialize;

use super::{json_body_error, retain_returned_organization_fields};
use crate::organization::additional_fields;
use crate::organization::hooks::{
    AfterUpdateOrganization, BeforeUpdateOrganization, OrganizationUpdateData,
};
use crate::organization::http;
use crate::organization::options::OrganizationOptions;
use crate::organization::permissions::{has_permission, OrganizationPermission};
use crate::organization::store::{OrganizationStore, OrganizationUpdate};

#[derive(Debug, Deserialize, Default)]
struct UpdateData {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    logo: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateBody {
    data: UpdateData,
    #[serde(default)]
    organization_id: Option<String>,
}

pub(super) fn update(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/update",
        Method::POST,
        super::super::metadata::options(
            "organizationUpdate",
            vec![
                super::super::metadata::object("data"),
                super::super::metadata::optional_string("organizationId"),
            ],
        ),
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
                        );
                    }
                };
                let body: serde_json::Value = http::body(&request)?;
                let input: UpdateBody =
                    serde_json::from_value(body.clone()).map_err(json_body_error)?;
                let additional_fields = body
                    .get("data")
                    .and_then(serde_json::Value::as_object)
                    .map(|data| {
                        additional_fields::update_values(
                            &options.schema.organization.additional_fields,
                            data,
                        )
                    })
                    .transpose()?
                    .unwrap_or_default();
                let Some(organization_id) = super::super::resolve_organization_id(
                    input.organization_id,
                    session.active_organization_id.as_deref(),
                ) else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                let Some(member) = store
                    .member_by_org_user(&organization_id, &session.user.id)
                    .await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
                    );
                };
                if !has_permission(
                    &member.role,
                    &options,
                    OrganizationPermission::OrganizationUpdate,
                ) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION",
                    );
                }
                let Some(existing_organization) =
                    store.organization_by_id(&organization_id).await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                let mut data = OrganizationUpdateData {
                    name: input.data.name,
                    slug: input.data.slug,
                    logo: input.data.logo,
                    metadata: input.data.metadata,
                };
                if let Some(hook) = &options.hooks.before_update_organization {
                    data = hook(&BeforeUpdateOrganization {
                        organization: existing_organization.clone(),
                        user: session.user.clone(),
                        data,
                    })?;
                }
                if let Some(slug) = &data.slug {
                    if slug.trim().is_empty() {
                        return super::super::validation::invalid_body();
                    }
                    if let Some(existing) = store.organization_by_slug(slug).await? {
                        if existing.id != organization_id {
                            return http::organization_error(
                                StatusCode::BAD_REQUEST,
                                "ORGANIZATION_SLUG_ALREADY_TAKEN",
                            );
                        }
                    }
                }
                if let Some(name) = &data.name {
                    if name.trim().is_empty() {
                        return super::super::validation::invalid_body();
                    }
                }
                let update = OrganizationUpdate {
                    name: data.name,
                    slug: data.slug,
                    logo: data.logo,
                    logo_set: true,
                    metadata: data.metadata,
                    metadata_set: true,
                    additional_fields,
                };
                match store.update_organization(&organization_id, update).await? {
                    Some(mut organization) => {
                        retain_returned_organization_fields(&mut organization, &options);
                        if let Some(hook) = &options.hooks.after_update_organization {
                            hook(&AfterUpdateOrganization {
                                organization: organization.clone(),
                                user: session.user,
                            })?;
                        }
                        http::json(StatusCode::OK, &organization)
                    }
                    None => {
                        http::organization_error(StatusCode::BAD_REQUEST, "ORGANIZATION_NOT_FOUND")
                    }
                }
            })
        },
    )
}
