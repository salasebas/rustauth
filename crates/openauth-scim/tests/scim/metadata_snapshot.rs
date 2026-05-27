//! Stable structural snapshots for SCIM metadata (CI drift guard without golden files).

use openauth_scim::metadata::{
    resource_type, resource_types, schema, schemas, service_provider_config, SCIM_GROUP_SCHEMA_ID,
    SCIM_USER_SCHEMA_ID,
};
use serde_json::Value;

fn stable_json(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("metadata should serialize")
}

#[test]
fn service_provider_config_snapshot_matches_advertised_capabilities() {
    let value = stable_json(&service_provider_config());
    assert_eq!(value["patch"]["supported"], true);
    assert_eq!(value["bulk"]["supported"], true);
    assert_eq!(value["bulk"]["maxOperations"], 1000);
    assert_eq!(value["bulk"]["maxPayloadSize"], 1048576);
    assert_eq!(value["filter"]["supported"], true);
    assert_eq!(value["filter"]["maxResults"], 200);
    assert_eq!(value["sort"]["supported"], true);
    assert_eq!(value["etag"]["supported"], true);
    assert_eq!(value["changePassword"]["supported"], false);
    assert_eq!(
        value["authenticationSchemes"][0]["name"],
        "OAuth Bearer Token"
    );
}

#[test]
fn schemas_list_snapshot_includes_core_and_enterprise_ids() {
    let list = schemas("https://app.example.com/api/auth");
    let value = stable_json(&list);
    let ids = value["Resources"]
        .as_array()
        .expect("resources array")
        .iter()
        .map(|item| item["id"].as_str().expect("schema id"))
        .collect::<Vec<_>>();
    assert_eq!(value["totalResults"], 3);
    assert!(ids.contains(&SCIM_USER_SCHEMA_ID));
    assert!(ids.contains(&SCIM_GROUP_SCHEMA_ID));
    assert!(ids.iter().any(|id| id.contains("enterprise")));
}

#[test]
fn resource_types_snapshot_lists_user_and_group_endpoints() {
    let list = resource_types("https://app.example.com/api/auth");
    let value = stable_json(&list);
    let endpoints = value["Resources"]
        .as_array()
        .expect("resources array")
        .iter()
        .map(|item| {
            (
                item["id"].as_str().expect("id"),
                item["endpoint"].as_str().expect("endpoint"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(endpoints.len(), 2);
    assert!(endpoints.contains(&("User", "/Users")));
    assert!(endpoints.contains(&("Group", "/Groups")));
}

#[test]
fn user_schema_snapshot_includes_enterprise_profile_attributes() {
    let user = schema("https://app.example.com", SCIM_USER_SCHEMA_ID).expect("user schema");
    let names = user
        .attributes
        .iter()
        .map(|attribute| attribute.name.as_str())
        .collect::<Vec<_>>();
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
        assert!(names.contains(&attribute), "missing attribute {attribute}");
    }
}

#[test]
fn group_resource_type_snapshot_matches_list_entry() {
    let listed = resource_types("https://app.example.com")
        .resources
        .into_iter()
        .find(|resource| resource.id == "Group")
        .expect("group in list");
    let single = resource_type("https://app.example.com", "Group").expect("group lookup");
    assert_eq!(listed.endpoint, single.endpoint);
    assert_eq!(listed.schema, single.schema);
    assert_eq!(single.schema, SCIM_GROUP_SCHEMA_ID);
}
