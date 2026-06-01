//! Regression tests for OPE-80: SCIM group routes must not expose or mutate
//! native organization teams that have no `scimGroupProfile` ownership marker.

use super::*;

async fn seed_native_team(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    team_id: &str,
    name: &str,
) {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("team")
                .data("id", DbValue::String(team_id.to_owned()))
                .data("name", DbValue::String(name.to_owned()))
                .data(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await
        .expect("native team should create");
}

async fn team_name(adapter: &dyn DbAdapter, team_id: &str) -> Option<String> {
    adapter
        .find_one(
            FindOne::new("team")
                .where_clause(Where::new("id", DbValue::String(team_id.to_owned()))),
        )
        .await
        .expect("find team should succeed")
        .and_then(|record| match record.get("name") {
            Some(DbValue::String(name)) => Some(name.clone()),
            _ => None,
        })
}

#[tokio::test]
async fn native_organization_team_is_invisible_and_immutable_via_scim_group_routes() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "native-owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;

    // A native organization team with no SCIM profile and a SCIM-managed group.
    seed_native_team(adapter.as_ref(), "org_1", "native_team_1", "Native Team").await;
    let scim_group_id = create_scim_group(&router, &token, "SCIM Group", "scim-group", &[]).await;

    // List must include only the SCIM-managed group.
    let listed = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Groups", &token))
        .await
        .expect("request should succeed");
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = json_body(listed);
    assert_eq!(listed["totalResults"], 1);
    assert_eq!(listed["Resources"][0]["id"], scim_group_id);

    // Item GET/PUT/PATCH/DELETE on the native team all return 404.
    let get = router
        .handle_async(auth_request(
            Method::GET,
            "/scim/v2/Groups/native_team_1",
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::NOT_FOUND);

    let put = router
        .handle_async(json_request(
            Method::PUT,
            "/scim/v2/Groups/native_team_1",
            r#"{"displayName":"Hijacked","members":[]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(put.status(), StatusCode::NOT_FOUND);

    let patch = router
        .handle_async(json_request(
            Method::PATCH,
            "/scim/v2/Groups/native_team_1",
            r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Hijacked"}]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(patch.status(), StatusCode::NOT_FOUND);

    let delete = router
        .handle_async(auth_request(
            Method::DELETE,
            "/scim/v2/Groups/native_team_1",
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(delete.status(), StatusCode::NOT_FOUND);

    // The native team is untouched: still present with its original name.
    assert_eq!(
        team_name(adapter.as_ref(), "native_team_1")
            .await
            .as_deref(),
        Some("Native Team")
    );

    // The SCIM-managed group still works.
    let scim_get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{scim_group_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(scim_get.status(), StatusCode::OK);
}

#[tokio::test]
async fn bulk_group_operations_reject_native_organization_team() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "native-bulk-owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    seed_native_team(adapter.as_ref(), "org_1", "native_team_1", "Native Team").await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations":[
                    {"method":"PUT","path":"/Groups/native_team_1","data":{"displayName":"Hijacked","members":[]}},
                    {"method":"PATCH","path":"/Groups/native_team_1","data":{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Hijacked"}]}},
                    {"method":"DELETE","path":"/Groups/native_team_1"}
                ]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    let operations = body["Operations"].as_array().expect("operations");
    assert_eq!(operations.len(), 3);
    for operation in operations {
        assert_eq!(operation["status"]["code"], 404);
    }

    // The native team survived every bulk mutation attempt.
    assert_eq!(
        team_name(adapter.as_ref(), "native_team_1")
            .await
            .as_deref(),
        Some("Native Team")
    );
}
