use super::*;

#[tokio::test]
async fn users_route_requires_valid_bearer_token() {
    let router = router().expect("router should build");

    let response = router
        .handle_async(request(Method::GET, "/scim/v2/Users"))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(response)["detail"], "SCIM token is required");

    let invalid = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", "not-base64"))
        .await
        .expect("request should succeed");
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(invalid)["detail"], "Invalid SCIM token");
}

#[tokio::test]
async fn all_user_routes_reject_missing_and_invalid_bearer_tokens() {
    let router = router().expect("router should build");
    let cases = [
        (Method::GET, "/scim/v2/Users", None),
        (
            Method::POST,
            "/scim/v2/Users",
            Some(r#"{"userName":"ada@example.com"}"#),
        ),
        (Method::GET, "/scim/v2/Users/user_1", None),
        (
            Method::PUT,
            "/scim/v2/Users/user_1",
            Some(r#"{"userName":"ada@example.com"}"#),
        ),
        (
            Method::PATCH,
            "/scim/v2/Users/user_1",
            Some(r#"{"Operations":[{"op":"replace","path":"name.formatted","value":"Ada"}]}"#),
        ),
        (Method::DELETE, "/scim/v2/Users/user_1", None),
    ];

    for (method, path, body) in cases {
        let missing = match body {
            Some(body) => json_request(method.clone(), path, body, None),
            None => request(method.clone(), path),
        };
        let missing = router
            .handle_async(missing)
            .await
            .expect("request should succeed");
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let invalid = match body {
            Some(body) => json_request(method.clone(), path, body, Some("not-base64")),
            None => auth_request(method, path, "not-base64"),
        };
        let invalid = router
            .handle_async(invalid)
            .await
            .expect("request should succeed");
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn users_route_accepts_case_insensitive_bearer_scheme_and_header_name() {
    let (adapter, router) = router_with_adapter().expect("router should build");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await
        .expect("provider should create");
    let token = encode_bearer_token("base-token", "okta", None);

    let response = router
        .handle_async(
            Request::builder()
                .method(Method::GET)
                .uri("/scim/v2/Users")
                .header("authorization", format!("bearer {token}"))
                .body(Vec::new())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn org_scoped_default_scim_requires_organization_plugin() {
    let (_adapter, router, _context) = router_with_context(ScimOptions {
        default_scim: vec![DefaultScimProvider {
            provider_id: "okta".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: Some("org_1".to_owned()),
        }],
        ..ScimOptions::default()
    })
    .expect("router should build");
    let token = encode_bearer_token("base-token", "okta", Some("org_1"));

    for (method, path, body) in [
        (Method::GET, "/scim/v2/Users", None),
        (
            Method::POST,
            "/scim/v2/Users/.search",
            Some(r#"{"filter":"userName sw \"a\""}"#),
        ),
        (Method::GET, "/scim/v2/Groups", None),
        (
            Method::POST,
            "/scim/v2/Bulk",
            Some(
                r#"{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[{"method":"GET","path":"/Users/user_1"}]
                }"#,
            ),
        ),
    ] {
        let request = match body {
            Some(body) => json_request(method, path, body, Some(&token)),
            None => auth_request(method, path, &token),
        };
        let response = router
            .handle_async(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response);
        assert_eq!(body["scimType"], "invalidValue");
        assert_eq!(
            body["detail"],
            "Organization plugin is required for organization-scoped SCIM providers"
        );
    }
}

#[tokio::test]
async fn org_scoped_persisted_scim_provider_requires_organization_plugin() {
    let (adapter, router, _context) =
        router_with_context(crate::scim_options_for_manual_provider_tokens())
            .expect("router should build");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: Some("org_1".to_owned()),
            user_id: None,
        })
        .await
        .expect("provider should create");
    let token = encode_bearer_token("base-token", "okta", Some("org_1"));

    for (method, path, body) in [
        (Method::GET, "/scim/v2/Users", None),
        (
            Method::POST,
            "/scim/v2/Users/.search",
            Some(r#"{"filter":"userName sw \"a\""}"#),
        ),
        (Method::GET, "/scim/v2/Groups", None),
        (
            Method::POST,
            "/scim/v2/Bulk",
            Some(
                r#"{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[{"method":"GET","path":"/Users/user_1"}]
                }"#,
            ),
        ),
    ] {
        let request = match body {
            Some(body) => json_request(method, path, body, Some(&token)),
            None => auth_request(method, path, &token),
        };
        let response = router
            .handle_async(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response)["scimType"], "invalidValue");
    }
}
