use openauth_scim::metadata::{
    resource_type, resource_types, schema, schemas, service_provider_config, SCIM_USER_SCHEMA_ID,
};

#[test]
fn service_provider_config_matches_upstream_support_flags() {
    let config = service_provider_config();

    assert!(config.patch.supported);
    assert!(!config.bulk.supported);
    assert!(config.filter.supported);
    assert!(!config.change_password.supported);
    assert!(!config.sort.supported);
    assert!(!config.etag.supported);
    assert_eq!(config.authentication_schemes[0].name, "OAuth Bearer Token");
    assert_eq!(config.authentication_schemes[0].type_, "oauthbearertoken");
    assert!(config.authentication_schemes[0].primary);
}

#[test]
fn schemas_list_resolves_user_schema_location() {
    let list = schemas("http://localhost:3000/api/auth");

    assert_eq!(list.total_results, 1);
    assert_eq!(list.start_index, 1);
    assert_eq!(list.items_per_page, 1);
    assert_eq!(list.resources[0].id, SCIM_USER_SCHEMA_ID);
    assert_eq!(
        list.resources[0].meta.location,
        "http://localhost:3000/api/auth/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
    );
}

#[test]
fn schema_lookup_rejects_unknown_schema_id() {
    let error = schema("http://localhost:3000", "unknown").expect_err("unknown schema");

    assert_eq!(error.status, http::StatusCode::NOT_FOUND);
    assert_eq!(error.detail.as_deref(), Some("Schema not found"));
}

#[test]
fn resource_type_lookup_returns_user_resource_type() {
    let list = resource_types("http://localhost:3000/api/auth");
    let user = resource_type("http://localhost:3000/api/auth", "User").expect("User type");

    assert_eq!(list.resources, vec![user.clone()]);
    assert_eq!(user.id, "User");
    assert_eq!(user.endpoint, "/Users");
    assert_eq!(user.schema, SCIM_USER_SCHEMA_ID);
}
