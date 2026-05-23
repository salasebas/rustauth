use ::http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use serde::Deserialize;

use crate::organization::http;
use crate::organization::store::OrganizationStore;

#[derive(Debug, Deserialize)]
struct CheckSlugBody {
    slug: String,
}

pub(super) fn check_slug() -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/check-slug",
        Method::POST,
        super::super::metadata::options(
            "organizationCheckSlug",
            vec![super::super::metadata::string("slug")],
        ),
        |context, request| {
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let input: CheckSlugBody = http::body(&request)?;
                if store.organization_by_slug(&input.slug).await?.is_some() {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_SLUG_ALREADY_TAKEN",
                    );
                }
                http::json(StatusCode::OK, &serde_json::json!({ "status": true }))
            })
        },
    )
}
