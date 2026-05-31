use ::http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use openauth_core::error::OpenAuthError;
use serde::Deserialize;

use super::{json_body_error, retain_returned_organization_fields};
use crate::organization::additional_fields;
use crate::organization::hooks::{
    AfterAddMember, AfterCreateOrganization, BeforeAddMember, BeforeCreateOrganization,
    MemberHookData,
};
use crate::organization::http;
use crate::organization::models::FullOrganization;
use crate::organization::options::OrganizationOptions;
use crate::organization::store::OrganizationStore;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateBody {
    name: String,
    slug: String,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    logo: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    keep_current_active_organization: bool,
}

pub(super) fn create(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/create",
        Method::POST,
        super::super::metadata::options(
            "organizationCreate",
            vec![
                super::super::metadata::string("name"),
                super::super::metadata::string("slug"),
                super::super::metadata::optional_string("userId"),
                super::super::metadata::optional_string("logo"),
                super::super::metadata::optional_object("metadata"),
                super::super::metadata::optional_bool("keepCurrentActiveOrganization"),
            ],
        ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let body: serde_json::Value = http::body(&request)?;
                let input: CreateBody =
                    serde_json::from_value(body.clone()).map_err(json_body_error)?;
                let additional_fields = additional_fields::create_values(
                    &options.schema.organization.additional_fields,
                    body.as_object().ok_or_else(|| {
                        OpenAuthError::Api("request body must be an object".to_owned())
                    })?,
                )?;
                if input.name.trim().is_empty() || input.slug.trim().is_empty() {
                    return super::super::validation::invalid_body();
                }

                let session = http::current_session(context, &request, &store).await?;
                // `userId` lets a trusted server-side caller create an organization on
                // behalf of another user. It must never be honored for internet-facing
                // requests: an unauthenticated client could otherwise forge any `userId`
                // and provision organizations for arbitrary users (OPE-9). Mirrors
                // upstream `if (!session && (ctx.request || ctx.headers)) UNAUTHORIZED`.
                let user = match session.as_ref() {
                    Some(session) => session.user.clone(),
                    None if !http::request_is_external() => match input.user_id.as_deref() {
                        Some(user_id) => match store.user_by_id(user_id).await? {
                            Some(user) => user,
                            None => {
                                return http::error(
                                    StatusCode::UNAUTHORIZED,
                                    "UNAUTHORIZED",
                                    "Unauthorized",
                                );
                            }
                        },
                        None => {
                            return http::error(
                                StatusCode::UNAUTHORIZED,
                                "UNAUTHORIZED",
                                "Unauthorized",
                            );
                        }
                    },
                    None => {
                        return http::error(
                            StatusCode::UNAUTHORIZED,
                            "UNAUTHORIZED",
                            "Unauthorized",
                        );
                    }
                };

                if !options.allow_user_to_create_organization && session.is_some() {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION",
                    );
                }
                if let Some(limit) = options.organization_limit {
                    if store.organizations_for_user(&user.id).await?.len() >= limit {
                        return http::organization_error(
                            StatusCode::FORBIDDEN,
                            "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS",
                        );
                    }
                }
                if store.organization_by_slug(&input.slug).await?.is_some() {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_ALREADY_EXISTS",
                    );
                }

                if let Some(hook) = &options.hooks.before_create_organization {
                    hook(&BeforeCreateOrganization {
                        name: input.name.clone(),
                        slug: input.slug.clone(),
                        user: user.clone(),
                    })?;
                }

                let mut organization = store
                    .create_organization(
                        input.name,
                        input.slug,
                        input.logo,
                        input.metadata,
                        additional_fields,
                    )
                    .await?;
                retain_returned_organization_fields(&mut organization, &options);
                let mut creator_member = MemberHookData {
                    organization_id: organization.id.clone(),
                    user_id: user.id.clone(),
                    role: options.creator_role.clone(),
                };
                if let Some(hook) = &options.hooks.before_add_member {
                    creator_member = hook(&BeforeAddMember {
                        organization: organization.clone(),
                        user: user.clone(),
                        member: creator_member,
                    })?;
                }
                let member = store
                    .create_member(
                        &creator_member.organization_id,
                        &creator_member.user_id,
                        &creator_member.role,
                        openauth_core::db::DbRecord::new(),
                    )
                    .await?;
                if options.teams.enabled && options.teams.create_default_team {
                    let team = store
                        .create_team(
                            &organization.id,
                            "Default",
                            openauth_core::db::DbRecord::new(),
                        )
                        .await?;
                    store
                        .create_team_member(&team.id, &user.id, openauth_core::db::DbRecord::new())
                        .await?;
                }
                if let Some(hook) = &options.hooks.after_add_member {
                    hook(&AfterAddMember {
                        organization: organization.clone(),
                        member: member.clone(),
                        user: user.clone(),
                    })?;
                }
                if let Some(hook) = &options.hooks.after_create_organization {
                    hook(&AfterCreateOrganization {
                        organization: organization.clone(),
                        member: member.clone(),
                        user: user.clone(),
                    })?;
                }
                let cookies = if let Some(session) = &session {
                    if !input.keep_current_active_organization {
                        store
                            .set_active_organization(&session.session.token, Some(&organization.id))
                            .await?;
                        http::refreshed_session_cookies(context, &session.session, &session.user)?
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };

                http::json_with_cookies(
                    StatusCode::OK,
                    &FullOrganization {
                        organization,
                        members: vec![member],
                        invitations: Vec::new(),
                        teams: Vec::new(),
                    },
                    cookies,
                )
            })
        },
    )
}
