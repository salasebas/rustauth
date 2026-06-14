use super::*;

#[tokio::test]
async fn service_provider_config_route_returns_scim_json() {
    let router = router().expect("router should build");

    let response = router
        .handle_async(request(Method::GET, "/scim/v2/ServiceProviderConfig"))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&http::HeaderValue::from_static("application/scim+json"))
    );
    let body = json_body(response);
    assert_eq!(body["patch"]["supported"], true);
    assert_eq!(body["bulk"]["supported"], true);
    assert_eq!(body["sort"]["supported"], true);
    assert_eq!(body["etag"]["supported"], true);
    assert_eq!(body["authenticationSchemes"][0]["type"], "oauthbearertoken");
}

#[tokio::test]
async fn schemas_route_resolves_user_schema_and_unknown_schema_errors() {
    let router = router().expect("router should build");

    let list = router
        .handle_async(request(Method::GET, "/scim/v2/Schemas"))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    let list = json_body(list);
    assert_eq!(list["totalResults"], 3);
    assert!(list["Resources"]
        .as_array()
        .expect("Resources")
        .iter()
        .any(|resource| resource["id"] == "urn:ietf:params:scim:schemas:core:2.0:User"));
    assert!(list["Resources"]
        .as_array()
        .expect("Resources")
        .iter()
        .any(|resource| resource["id"] == "urn:ietf:params:scim:schemas:core:2.0:Group"));

    let user = router
        .handle_async(request(
            Method::GET,
            "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
        ))
        .await
        .expect("request should succeed");
    assert_eq!(user.status(), StatusCode::OK);
    assert_eq!(json_body(user)["name"], "User");

    let missing = router
        .handle_async(request(Method::GET, "/scim/v2/Schemas/unknown"))
        .await
        .expect("request should succeed");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(missing)["schemas"][0],
        rustauth_scim::errors::SCIM_ERROR_SCHEMA
    );
}

#[tokio::test]
async fn resource_types_route_resolves_user_resource_type() {
    let router = router().expect("router should build");

    let list = router
        .handle_async(request(Method::GET, "/scim/v2/ResourceTypes"))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    let list = json_body(list);
    assert_eq!(list["totalResults"], 2);
    assert_eq!(list["Resources"][0]["name"], "User");
    assert_eq!(list["Resources"][1]["name"], "Group");

    let user = router
        .handle_async(request(Method::GET, "/scim/v2/ResourceTypes/User"))
        .await
        .expect("request should succeed");
    assert_eq!(user.status(), StatusCode::OK);
    assert_eq!(json_body(user)["endpoint"], "/Users");

    let group = router
        .handle_async(request(Method::GET, "/scim/v2/ResourceTypes/Group"))
        .await
        .expect("request should succeed");
    assert_eq!(group.status(), StatusCode::OK);
    assert_eq!(json_body(group)["endpoint"], "/Groups");
}

#[tokio::test]
async fn me_route_returns_rfc_compatible_not_implemented() {
    let router = router().expect("router should build");

    let response = router
        .handle_async(request(Method::GET, "/scim/v2/Me"))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = json_body(response);
    assert_eq!(body["schemas"][0], rustauth_scim::errors::SCIM_ERROR_SCHEMA);
    assert_eq!(body["status"], "501");
    assert_eq!(
        body["detail"],
        "/Me is not supported for provider-scoped SCIM tokens"
    );
}
