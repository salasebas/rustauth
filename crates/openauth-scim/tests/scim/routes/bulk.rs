use super::*;

#[tokio::test]
async fn bulk_route_executes_get_user_operations() {
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
    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"bulk@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[{{"method":"GET","path":"/Users/{user_id}"}}]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(
        body["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
    );
    assert_eq!(body["Operations"][0]["status"]["code"], 200);
    assert!(body["Operations"][0]["location"]
        .as_str()
        .expect("location")
        .ends_with(&format!("/scim/v2/Users/{user_id}")));
    assert!(body["Operations"][0]["version"].as_str().is_some());
    assert_eq!(
        body["Operations"][0]["response"]["userName"],
        "bulk@example.com"
    );
}

#[tokio::test]
async fn bulk_route_stops_on_first_error_when_fail_on_errors_is_zero() {
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
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "failOnErrors":0,
                "Operations":[
                    {"method":"POST","path":"/Users","data":{"userName":"missing-bulkid@example.com"}},
                    {"method":"GET","path":"/Users/never-runs"}
                ]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"].as_array().expect("ops").len(), 1);
    assert_eq!(body["Operations"][0]["status"]["code"], 400);
}

#[tokio::test]
async fn bulk_post_user_rejects_invalid_user_name_without_emails() {
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
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations":[
                    {
                        "method":"POST",
                        "path":"/Users",
                        "bulkId":"bad-user",
                        "data":{"userName":"not-an-email"}
                    }
                ]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 400);
    assert_eq!(
        body["Operations"][0]["response"]["detail"],
        "userName and emails.value must resolve to a valid email address"
    );
}

#[tokio::test]
async fn bulk_route_requires_bulk_id_for_post_and_respects_fail_on_errors() {
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
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "failOnErrors":1,
                "Operations":[
                    {"method":"POST","path":"/Users","data":{"userName":"missing-bulkid@example.com"}},
                    {"method":"GET","path":"/Users/never-runs"}
                ]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"].as_array().expect("ops").len(), 1);
    assert_eq!(body["Operations"][0]["status"]["code"], 400);
    assert_eq!(
        body["Operations"][0]["response"]["scimType"],
        "invalidValue"
    );
}

#[tokio::test]
async fn bulk_route_resolves_bulk_id_for_user_group_membership() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "bulk-owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations":[
                    {
                        "method":"POST",
                        "path":"/Users",
                        "bulkId":"user-1",
                        "data":{"userName":"bulk-created@example.com","name":{"formatted":"Bulk Created"}}
                    },
                    {
                        "method":"POST",
                        "path":"/Groups",
                        "bulkId":"group-1",
                        "data":{"displayName":"Bulk Team","members":[{"value":"bulkId:user-1"}]}
                    },
                    {"method":"GET","path":"bulkId:group-1"}
                ]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 201);
    assert_eq!(body["Operations"][1]["status"]["code"], 201);
    assert_eq!(body["Operations"][2]["status"]["code"], 200);
    assert_eq!(
        body["Operations"][2]["response"]["members"][0]["display"],
        "Bulk Created"
    );
}

#[tokio::test]
async fn bulk_route_executes_put_patch_and_delete_operations() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "bulk-mutate-owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let user_id = create_scim_user(&router, &token, "bulk-put@example.com", "Bulk Put").await;
    let group_id = create_scim_group(&router, &token, "Bulk Patch Team", "bulk-patch", &[]).await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[
                        {{
                            "method":"PUT",
                            "path":"/Users/{user_id}",
                            "data":{{"userName":"bulk-put-updated@example.com","title":"Updated"}}
                        }},
                        {{
                            "method":"PATCH",
                            "path":"/Groups/{group_id}",
                            "data":{{
                                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                "Operations":[{{"op":"replace","path":"displayName","value":"Bulk Patched Team"}}]
                            }}
                        }},
                        {{"method":"GET","path":"/Users/{user_id}"}},
                        {{"method":"GET","path":"/Groups/{group_id}"}},
                        {{"method":"DELETE","path":"/Groups/{group_id}"}},
                        {{"method":"DELETE","path":"/Users/{user_id}"}}
                    ]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 200);
    assert_eq!(body["Operations"][1]["status"]["code"], 200);
    assert_eq!(
        body["Operations"][2]["response"]["userName"],
        "bulk-put-updated@example.com"
    );
    assert_eq!(body["Operations"][2]["response"]["title"], "Updated");
    assert_eq!(
        body["Operations"][3]["response"]["displayName"],
        "Bulk Patched Team"
    );
    assert_eq!(body["Operations"][4]["status"]["code"], 204);
    assert_eq!(body["Operations"][5]["status"]["code"], 204);
}

#[tokio::test]
async fn bulk_route_executes_user_patch_operations() {
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
    let user_id =
        create_scim_user(&router, &token, "bulk-user-patch@example.com", "Bulk Patch").await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[
                        {{
                            "method":"PATCH",
                            "path":"/Users/{user_id}",
                            "data":{{
                                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                "Operations":[
                                    {{"op":"replace","path":"title","value":"Principal Engineer"}},
                                    {{"op":"add","path":"phoneNumbers","value":[{{"value":"+15551234567","type":"work"}}]}}
                                ]
                            }}
                        }},
                        {{"method":"GET","path":"/Users/{user_id}"}}
                    ]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 200);
    assert!(body["Operations"][0]["version"].as_str().is_some());
    assert_eq!(
        body["Operations"][1]["response"]["title"],
        "Principal Engineer"
    );
    assert_eq!(
        body["Operations"][1]["response"]["phoneNumbers"][0]["value"],
        "+15551234567"
    );
}

#[tokio::test]
async fn bulk_user_patch_remove_external_id_resets_account_id_to_user_name() {
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
    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"bulk-remove-external@example.com","externalId":"bulk-upstream"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[
                        {{
                            "method":"PATCH",
                            "path":"/Users/{user_id}",
                            "data":{{
                                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                "Operations":[{{"op":"remove","path":"externalId"}}]
                            }}
                        }}
                    ]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 200);
    assert_eq!(
        body["Operations"][0]["response"]["externalId"],
        "bulk-remove-external@example.com"
    );
}

#[tokio::test]
async fn bulk_delete_user_requires_provider_scope() {
    let (adapter, router) = router_with_adapter().expect("router should build");
    for (provider_id, token) in [("okta", "okta-token"), ("entra", "entra-token")] {
        ScimProviderStore::new(adapter.as_ref())
            .create(CreateScimProviderInput {
                provider_id: provider_id.to_owned(),
                scim_token: token.to_owned(),
                organization_id: None,
                user_id: None,
            })
            .await
            .expect("provider should create");
    }
    let okta_token = encode_bearer_token("okta-token", "okta", None);
    let entra_token = encode_bearer_token("entra-token", "entra", None);
    let user_id = create_scim_user(
        &router,
        &entra_token,
        "bulk-provider-scope@example.com",
        "Provider Scope",
    )
    .await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[{{"method":"DELETE","path":"/Users/{user_id}"}}]
                }}"#
            ),
            Some(&okta_token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 404);
    assert_eq!(
        body["Operations"][0]["response"]["detail"],
        "User not found"
    );

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &entra_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(fetched.status(), StatusCode::OK);
}

#[tokio::test]
async fn bulk_delete_user_requires_organization_scope() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "bulk-user-org-scope-owner@example.com",
    )
    .await
    .expect("owner session");
    for organization_id in ["org_1", "org_2"] {
        seed_organization(adapter.as_ref(), organization_id)
            .await
            .expect("org");
        seed_member(adapter.as_ref(), organization_id, &owner_id, "owner")
            .await
            .expect("owner member");
    }
    let org_one_token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let org_two_token = generate_scim_token(&router, &owner_cookie, "entra", Some("org_2")).await;
    let user_id = create_scim_user(
        &router,
        &org_two_token,
        "bulk-user-org-scope@example.com",
        "Org Scope",
    )
    .await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[{{"method":"DELETE","path":"/Users/{user_id}"}}]
                }}"#
            ),
            Some(&org_one_token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 404);
    assert_eq!(
        body["Operations"][0]["response"]["detail"],
        "User not found"
    );

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &org_two_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(fetched.status(), StatusCode::OK);
}

#[tokio::test]
async fn bulk_group_mutations_require_organization_scope() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "bulk-group-org-scope-owner@example.com",
    )
    .await
    .expect("owner session");
    for organization_id in ["org_1", "org_2"] {
        seed_organization(adapter.as_ref(), organization_id)
            .await
            .expect("org");
        seed_member(adapter.as_ref(), organization_id, &owner_id, "owner")
            .await
            .expect("owner member");
    }
    let org_one_token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let org_two_token = generate_scim_token(&router, &owner_cookie, "entra", Some("org_2")).await;
    let group_id =
        create_scim_group(&router, &org_two_token, "Scoped Group", "scoped-group", &[]).await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[
                        {{
                            "method":"PUT",
                            "path":"/Groups/{group_id}",
                            "data":{{"displayName":"Wrong Scope PUT"}}
                        }},
                        {{
                            "method":"PATCH",
                            "path":"/Groups/{group_id}",
                            "data":{{
                                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                                "Operations":[{{"op":"replace","path":"displayName","value":"Wrong Scope PATCH"}}]
                            }}
                        }},
                        {{"method":"DELETE","path":"/Groups/{group_id}"}}
                    ]
                }}"#
            ),
            Some(&org_one_token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 404);
    assert_eq!(body["Operations"][1]["status"]["code"], 404);
    assert_eq!(body["Operations"][2]["status"]["code"], 404);

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{group_id}"),
            &org_two_token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(fetched.status(), StatusCode::OK);
    assert_eq!(json_body(fetched)["displayName"], "Scoped Group");
}

#[tokio::test]
async fn bulk_group_post_and_put_reject_unknown_members() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "bulk-group-member-owner@example.com",
    )
    .await
    .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let group_id = create_scim_group(&router, &token, "Existing Group", "existing", &[]).await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[
                        {{
                            "method":"POST",
                            "path":"/Groups",
                            "bulkId":"unknown-member-group",
                            "data":{{"displayName":"Unknown Member","members":[{{"value":"missing-user"}}]}}
                        }},
                        {{
                            "method":"PUT",
                            "path":"/Groups/{group_id}",
                            "data":{{"displayName":"Unknown Put","members":[{{"value":"missing-user"}}]}}
                        }},
                        {{
                            "method":"POST",
                            "path":"/Groups",
                            "bulkId":"unresolved-member-group",
                            "data":{{"displayName":"Unresolved Member","members":[{{"value":"bulkId:missing-user"}}]}}
                        }}
                    ]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 400);
    assert_eq!(
        body["Operations"][0]["response"]["scimType"],
        "invalidValue"
    );
    assert_eq!(body["Operations"][1]["status"]["code"], 400);
    assert_eq!(
        body["Operations"][1]["response"]["scimType"],
        "invalidValue"
    );
    assert_eq!(body["Operations"][2]["status"]["code"], 400);
    assert_eq!(
        body["Operations"][2]["response"]["scimType"],
        "invalidValue"
    );
}

#[tokio::test]
async fn bulk_group_post_and_put_reject_empty_display_name() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "bulk-group-empty-name-owner@example.com",
    )
    .await
    .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let group_id = create_scim_group(&router, &token, "Existing Group", "existing", &[]).await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[
                        {{
                            "method":"POST",
                            "path":"/Groups",
                            "bulkId":"empty-name-group",
                            "data":{{"displayName":"   ","members":[]}}
                        }},
                        {{
                            "method":"PUT",
                            "path":"/Groups/{group_id}",
                            "data":{{"displayName":"   ","members":[]}}
                        }},
                        {{"method":"GET","path":"/Groups/{group_id}"}}
                    ]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 400);
    assert_eq!(
        body["Operations"][0]["response"]["scimType"],
        "invalidValue"
    );
    assert_eq!(body["Operations"][1]["status"]["code"], 400);
    assert_eq!(
        body["Operations"][1]["response"]["scimType"],
        "invalidValue"
    );
    assert_eq!(
        body["Operations"][2]["response"]["displayName"],
        "Existing Group"
    );
}

#[tokio::test]
async fn bulk_invalid_data_returns_operation_error_and_respects_fail_on_errors() {
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
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "failOnErrors":1,
                "Operations":[
                    {"method":"POST","path":"/Users","bulkId":"bad-user","data":{"title":"Missing userName"}},
                    {"method":"GET","path":"/Users/should-not-run"}
                ]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"].as_array().expect("ops").len(), 1);
    assert_eq!(body["Operations"][0]["status"]["code"], 400);
    assert_eq!(
        body["Operations"][0]["response"]["scimType"],
        "invalidValue"
    );
}

#[tokio::test]
async fn bulk_invalid_data_returns_operation_errors_for_all_mutations() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "bulk-invalid-all-owner@example.com",
    )
    .await
    .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let user_id = create_scim_user(
        &router,
        &token,
        "bulk-invalid-all@example.com",
        "Invalid All",
    )
    .await;
    let group_id =
        create_scim_group(&router, &token, "Invalid All Group", "invalid-all", &[]).await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[
                        {{"method":"POST","path":"/Users","bulkId":"bad-post-user","data":{{"title":"Missing userName"}}}},
                        {{"method":"PUT","path":"/Users/{user_id}","data":{{"title":"Missing userName"}}}},
                        {{"method":"PATCH","path":"/Users/{user_id}","data":{{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":"not an array"}}}},
                        {{"method":"POST","path":"/Groups","bulkId":"bad-post-group","data":{{"members":[]}}}},
                        {{"method":"PUT","path":"/Groups/{group_id}","data":{{"externalId":"missing-display-name"}}}},
                        {{"method":"PATCH","path":"/Groups/{group_id}","data":{{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":"not an array"}}}}
                    ]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    let operations = body["Operations"].as_array().expect("operations");
    assert_eq!(operations.len(), 6);
    for operation in operations {
        assert_eq!(operation["status"]["code"], 400);
        assert_eq!(operation["response"]["scimType"], "invalidValue");
    }
}

#[tokio::test]
async fn bulk_group_patch_requires_patch_op_schema() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) = session_cookie_with_user(
        adapter.as_ref(),
        &context,
        "bulk-patch-schema-owner@example.com",
    )
    .await
    .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let group_id = create_scim_group(&router, &token, "Patch Schema", "patch-schema", &[]).await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[{{
                        "method":"PATCH",
                        "path":"/Groups/{group_id}",
                        "data":{{"Operations":[{{"op":"replace","path":"displayName","value":"Missing Schema"}}]}}
                    }}]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 400);
    assert_eq!(
        body["Operations"][0]["response"]["scimType"],
        "invalidValue"
    );
}

#[tokio::test]
async fn bulk_route_rejects_stale_operation_version() {
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
    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"bulk-version@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[
                        {{
                            "method":"PUT",
                            "path":"/Users/{user_id}",
                            "version":"W/\"stale\"",
                            "data":{{"userName":"bulk-version-updated@example.com"}}
                        }}
                    ]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 412);
    assert_eq!(body["Operations"][0]["response"]["status"], "412");
}

#[tokio::test]
async fn bulk_route_rejects_unresolved_bulk_id_references() {
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
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations":[{"method":"GET","path":"bulkId:missing-user"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 400);
    assert_eq!(
        body["Operations"][0]["response"]["scimType"],
        "invalidValue"
    );
}

#[tokio::test]
async fn bulk_route_enforces_advertised_operation_limit() {
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
    let operations = (0..1001)
        .map(|index| format!(r#"{{"method":"GET","path":"/Users/missing-{index}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        r#"{{
            "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations":[{operations}]
        }}"#
    );

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &body,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response);
    assert_eq!(body["scimType"], "tooMany");
}

#[tokio::test]
async fn bulk_patch_user_succeeds_without_if_match_header() {
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
    let user_id = create_scim_user(&router, &token, "bulk-patch@example.com", "Bulk Patch").await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[{{
                        "method":"PATCH",
                        "path":"/Users/{user_id}",
                        "data":{{
                            "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                            "Operations":[{{"op":"replace","path":"title","value":"Bulk Title"}}]
                        }}
                    }}]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 200);

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(fetched)["title"], "Bulk Title");
}

#[tokio::test]
async fn bulk_patch_group_succeeds_without_if_match_header() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "bulk-group-patch@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let group_id =
        create_scim_group(&router, &token, "Bulk Patch Group", "bulk-patch-group", &[]).await;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                    "Operations":[{{
                        "method":"PATCH",
                        "path":"/Groups/{group_id}",
                        "data":{{
                            "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                            "Operations":[{{"op":"replace","path":"displayName","value":"Bulk Patched"}}]
                        }}
                    }}]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["Operations"][0]["status"]["code"], 200);
    assert_eq!(
        body["Operations"][0]["response"]["displayName"],
        "Bulk Patched"
    );
}

#[tokio::test]
async fn bulk_route_enforces_advertised_payload_limit() {
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
    let oversized_body = "x".repeat(1_048_577);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Bulk",
            &oversized_body,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response);
    assert_eq!(body["scimType"], "tooMany");
}
