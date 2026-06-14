mod create;
mod delete;
mod query;
mod update;

use rustauth_core::api::AsyncAuthEndpoint;
use rustauth_core::error::RustAuthError;

use crate::organization::additional_fields;
use crate::organization::models::Organization;
use crate::organization::options::OrganizationOptions;

pub fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    vec![
        create::create(options.clone()),
        query::check_slug(),
        update::update(options.clone()),
        delete::delete(options),
    ]
}

pub(super) fn retain_returned_organization_fields(
    organization: &mut Organization,
    options: &OrganizationOptions,
) {
    let fields = &options.schema.organization.additional_fields;
    additional_fields::retain_returned(&mut organization.additional_fields, fields);
}

pub(super) fn json_body_error(error: serde_json::Error) -> RustAuthError {
    RustAuthError::Api(error.to_string())
}
