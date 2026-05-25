use http::StatusCode;
use openauth_core::context::AuthContext;
use openauth_core::db::{DbAdapter, DbValue, FindOne, Session, User, Where};
use openauth_core::error::OpenAuthError;

use crate::errors::StripeErrorCode;
use crate::options::{
    AuthorizeReferenceAction, AuthorizeReferenceInput, StripeOptions, SubscriptionOptions,
};

pub(super) struct ReferenceAuthorizationFailure {
    pub status: StatusCode,
    pub code: StripeErrorCode,
}

pub(super) struct ReferenceResolutionInput<'a> {
    pub context: &'a AuthContext,
    pub adapter: &'a dyn DbAdapter,
    pub options: &'a StripeOptions,
    pub subscription_options: &'a SubscriptionOptions,
    pub user: &'a User,
    pub session: &'a Session,
    pub session_token: &'a str,
    pub explicit_reference_id: Option<String>,
    pub customer_type: Option<&'a str>,
    pub action: AuthorizeReferenceAction,
}

pub(super) async fn authorize_reference(
    context: &AuthContext,
    subscription_options: &SubscriptionOptions,
    user: &User,
    session: &Session,
    explicit_reference_id: Option<String>,
    action: AuthorizeReferenceAction,
) -> Result<Result<String, ReferenceAuthorizationFailure>, OpenAuthError> {
    let Some(reference_id) = explicit_reference_id else {
        return Ok(Ok(user.id.clone()));
    };

    if reference_id == user.id {
        return Ok(Ok(reference_id));
    }

    let Some(authorize_reference) = &subscription_options.authorize_reference else {
        return Ok(Err(ReferenceAuthorizationFailure {
            status: StatusCode::BAD_REQUEST,
            code: StripeErrorCode::ReferenceIdNotAllowed,
        }));
    };

    let authorized = authorize_reference(
        AuthorizeReferenceInput {
            user_id: user.id.clone(),
            user: user.clone(),
            session: session.clone(),
            reference_id: reference_id.clone(),
            action,
        },
        context,
    )
    .await?;

    if authorized {
        Ok(Ok(reference_id))
    } else {
        Ok(Err(ReferenceAuthorizationFailure {
            status: StatusCode::UNAUTHORIZED,
            code: StripeErrorCode::Unauthorized,
        }))
    }
}

pub(super) async fn authorize_reference_for_customer_type(
    input: ReferenceResolutionInput<'_>,
) -> Result<Result<String, ReferenceAuthorizationFailure>, OpenAuthError> {
    match input.customer_type.unwrap_or("user") {
        "user" => {
            authorize_reference(
                input.context,
                input.subscription_options,
                input.user,
                input.session,
                input.explicit_reference_id,
                input.action,
            )
            .await
        }
        "organization" => {
            if !input
                .options
                .organization
                .as_ref()
                .is_some_and(|org| org.enabled)
            {
                return Ok(Err(ReferenceAuthorizationFailure {
                    status: StatusCode::BAD_REQUEST,
                    code: StripeErrorCode::OrganizationSubscriptionNotEnabled,
                }));
            }
            if input.subscription_options.authorize_reference.is_none() {
                return Ok(Err(ReferenceAuthorizationFailure {
                    status: StatusCode::BAD_REQUEST,
                    code: StripeErrorCode::AuthorizeReferenceRequired,
                }));
            }
            let reference_id = match input.explicit_reference_id {
                Some(reference_id) => reference_id,
                None => {
                    let Some(active_organization_id) =
                        active_organization_id(input.adapter, input.session_token).await?
                    else {
                        return Ok(Err(ReferenceAuthorizationFailure {
                            status: StatusCode::BAD_REQUEST,
                            code: StripeErrorCode::OrganizationReferenceIdRequired,
                        }));
                    };
                    active_organization_id
                }
            };
            authorize_reference(
                input.context,
                input.subscription_options,
                input.user,
                input.session,
                Some(reference_id),
                input.action,
            )
            .await
        }
        _ => Ok(Err(ReferenceAuthorizationFailure {
            status: StatusCode::BAD_REQUEST,
            code: StripeErrorCode::InvalidRequestBody,
        })),
    }
}

pub(super) async fn active_organization_id(
    adapter: &dyn DbAdapter,
    session_token: &str,
) -> Result<Option<String>, OpenAuthError> {
    Ok(adapter
        .find_one(FindOne::new("session").where_clause(Where::new(
            "token",
            DbValue::String(session_token.to_owned()),
        )))
        .await?
        .and_then(|record| {
            record
                .get("active_organization_id")
                .or_else(|| record.get("activeOrganizationId"))
                .and_then(|value| match value {
                    DbValue::String(value) => Some(value.clone()),
                    _ => None,
                })
        }))
}
