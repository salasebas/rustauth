use rustauth_scim::metadata::{
    resource_type, resource_types, schema, schemas, service_provider_config, SCIM_GROUP_SCHEMA_ID,
    SCIM_USER_SCHEMA_ID,
};

#[test]
fn service_provider_config_advertises_implemented_rfc_capabilities() {
    let config = service_provider_config();

    assert!(config.patch.supported);
    assert!(config.bulk.supported);
    assert_eq!(config.bulk.max_operations, Some(1000));
    assert_eq!(config.bulk.max_payload_size, Some(1_048_576));
    assert!(config.filter.supported);
    assert_eq!(config.filter.max_results, Some(200));
    assert!(!config.change_password.supported);
    assert!(config.sort.supported);
    assert!(config.etag.supported);
    assert_eq!(config.authentication_schemes[0].name, "OAuth Bearer Token");
    assert_eq!(config.authentication_schemes[0].type_, "oauthbearertoken");
    assert!(config.authentication_schemes[0].primary);
}

#[test]
fn schemas_list_resolves_user_group_and_enterprise_user_schemas() {
    let list = schemas("http://localhost:3000/api/auth");

    assert_eq!(list.total_results, 3);
    assert_eq!(list.start_index, 1);
    assert_eq!(list.items_per_page, 3);
    assert!(list
        .resources
        .iter()
        .any(|resource| resource.id == SCIM_USER_SCHEMA_ID));
    assert!(list
        .resources
        .iter()
        .any(|resource| resource.id == SCIM_GROUP_SCHEMA_ID));
    assert!(list
        .resources
        .iter()
        .any(|resource| resource.name == "EnterpriseUser"));

    let user = list
        .resources
        .iter()
        .find(|resource| resource.id == SCIM_USER_SCHEMA_ID)
        .expect("User schema");
    for attribute in [
        "nickName",
        "profileUrl",
        "title",
        "userType",
        "preferredLanguage",
        "locale",
        "timezone",
        "phoneNumbers",
        "ims",
        "photos",
        "addresses",
        "groups",
        "entitlements",
        "roles",
        "x509Certificates",
    ] {
        assert!(
            user.attributes.iter().any(|item| item.name == attribute),
            "missing User schema attribute {attribute}"
        );
    }

    let group = list
        .resources
        .iter()
        .find(|resource| resource.id == SCIM_GROUP_SCHEMA_ID)
        .expect("Group schema");
    let members = group
        .attributes
        .iter()
        .find(|attribute| attribute.name == "members")
        .expect("members attribute");
    assert!(members
        .sub_attributes
        .iter()
        .any(|attribute| attribute.name == "type"));
    assert_eq!(
        members.reference_types,
        vec!["User".to_owned(), "Group".to_owned()]
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
    let group = resource_type("http://localhost:3000/api/auth", "Group").expect("Group type");

    assert_eq!(list.resources, vec![user.clone(), group.clone()]);
    assert_eq!(user.id, "User");
    assert_eq!(user.endpoint, "/Users");
    assert_eq!(user.schema, SCIM_USER_SCHEMA_ID);
    assert_eq!(group.id, "Group");
    assert_eq!(group.endpoint, "/Groups");
    assert_eq!(group.schema, SCIM_GROUP_SCHEMA_ID);
}
