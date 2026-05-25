use ::http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions};
use openauth_core::db::{DbValue, SortDirection, WhereOperator};

use crate::organization::additional_fields;
use crate::organization::http;
use crate::organization::models::Member;
use crate::organization::options::OrganizationOptions;
use crate::organization::store::{MemberListQuery, OrganizationStore};

use super::validation::{query_param, require_session};

pub(super) fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    vec![
        get_active_member(options.clone()),
        list_members(options),
        get_active_member_role(),
    ]
}

fn get_active_member(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/get-active-member",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationGetActiveMember"),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let Some(organization_id) = session.active_organization_id else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                match store
                    .member_by_org_user(&organization_id, &session.user.id)
                    .await?
                {
                    Some(mut member) => {
                        retain_returned_member_fields(&mut member, &options);
                        http::json(StatusCode::OK, &member)
                    }
                    None => http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND"),
                }
            })
        },
    )
}

fn list_members(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/list-members",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationListMembers"),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let Some(organization_id) = resolve_organization_id(
                    &store,
                    &request,
                    session.active_organization_id.as_deref(),
                )
                .await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                if store
                    .member_by_org_user(&organization_id, &session.user.id)
                    .await?
                    .is_none()
                {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
                    );
                }
                let member_query = member_list_query(&request, organization_id.clone());
                let total = store
                    .count_members_matching(&organization_id, member_query.filters.clone())
                    .await?;
                let mut members = store.list_members(member_query).await?;
                for member in &mut members {
                    retain_returned_member_fields(member, &options);
                }
                http::json(
                    StatusCode::OK,
                    &serde_json::json!({ "members": members, "total": total }),
                )
            })
        },
    )
}

fn get_active_member_role() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/get-active-member-role",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationGetActiveMemberRole"),
        |context, request| {
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let Some(organization_id) = resolve_organization_id(
                    &store,
                    &request,
                    session.active_organization_id.as_deref(),
                )
                .await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                match store
                    .member_by_org_user(&organization_id, &session.user.id)
                    .await?
                {
                    Some(_) => {
                        let target_user_id = query_param(&request, "userId")
                            .unwrap_or_else(|| session.user.id.clone());
                        let Some(member) = store
                            .member_by_org_user(&organization_id, &target_user_id)
                            .await?
                        else {
                            return http::organization_error(
                                StatusCode::FORBIDDEN,
                                "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
                            );
                        };
                        http::json(StatusCode::OK, &serde_json::json!({ "role": member.role }))
                    }
                    None => http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
                    ),
                }
            })
        },
    )
}

fn retain_returned_member_fields(member: &mut Member, options: &OrganizationOptions) {
    additional_fields::retain_returned(
        &mut member.additional_fields,
        &options.schema.member.additional_fields,
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

fn member_list_query(
    request: &openauth_core::api::ApiRequest,
    organization_id: String,
) -> MemberListQuery {
    let mut query = MemberListQuery::new(organization_id);
    if let Some(field) = query_param(request, "filterField") {
        if let Some(value) = query_param(request, "filterValue") {
            let operator = filter_operator(
                query_param(request, "filterOperator")
                    .as_deref()
                    .unwrap_or("eq"),
            );
            query = query.filter(
                member_field_name(&field),
                filter_value(&value, operator),
                operator,
            );
        }
    }
    if let Some(limit) = query_param(request, "limit").and_then(|value| value.parse().ok()) {
        query = query.limit(limit);
    }
    if let Some(offset) = query_param(request, "offset").and_then(|value| value.parse().ok()) {
        query = query.offset(offset);
    }
    if let Some(sort_by) = query_param(request, "sortBy") {
        let direction = match query_param(request, "sortDirection").as_deref() {
            Some("desc") => SortDirection::Desc,
            _ => SortDirection::Asc,
        };
        query = query.sort(member_field_name(&sort_by), direction);
    }
    query
}

fn filter_operator(value: &str) -> WhereOperator {
    match value {
        "ne" => WhereOperator::Ne,
        "lt" => WhereOperator::Lt,
        "lte" => WhereOperator::Lte,
        "gt" => WhereOperator::Gt,
        "gte" => WhereOperator::Gte,
        "in" => WhereOperator::In,
        "not_in" | "notIn" => WhereOperator::NotIn,
        "contains" => WhereOperator::Contains,
        "starts_with" | "startsWith" => WhereOperator::StartsWith,
        "ends_with" | "endsWith" => WhereOperator::EndsWith,
        _ => WhereOperator::Eq,
    }
}

fn filter_value(value: &str, operator: WhereOperator) -> DbValue {
    match operator {
        WhereOperator::In | WhereOperator::NotIn => {
            DbValue::StringArray(value.split(',').map(str::to_owned).collect())
        }
        _ => value
            .parse::<i64>()
            .map(DbValue::Number)
            .unwrap_or_else(|_| DbValue::String(value.to_owned())),
    }
}

fn member_field_name(field: &str) -> String {
    match field {
        "organizationId" => "organization_id".to_owned(),
        "userId" => "user_id".to_owned(),
        "createdAt" => "created_at".to_owned(),
        value => value.to_owned(),
    }
}
