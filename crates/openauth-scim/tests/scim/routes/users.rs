use super::*;

#[tokio::test]
async fn users_route_accepts_default_provider_without_database_row() {
    let router = router_with_context(ScimOptions {
        default_scim: vec![DefaultScimProvider {
            provider_id: "default-okta".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: None,
        }],
        ..ScimOptions::default()
    })
    .expect("router")
    .1;
    let token = encode_bearer_token("base-token", "default-okta", None);

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"default@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(create.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn users_route_default_provider_uses_plain_token_when_database_storage_is_hashed() {
    let router = router_with_context(ScimOptions {
        default_scim: vec![DefaultScimProvider {
            provider_id: "default-okta".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: None,
        }],
        token_storage: ScimTokenStorage::Hashed,
        ..ScimOptions::default()
    })
    .expect("router")
    .1;
    let token = encode_bearer_token("base-token", "default-okta", None);

    let response = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &token))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn users_route_creates_and_lists_scim_user() {
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

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{
                "userName":"Ada@Example.com",
                "name":{"formatted":"Ada Lovelace"},
                "emails":[{"value":"ada@example.com","primary":true}],
                "externalId":"idp-ada"
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(create.status(), StatusCode::CREATED);
    let created = json_body(create);
    assert_eq!(created["userName"], "ada@example.com");
    assert_eq!(created["externalId"], "idp-ada");
    assert_eq!(created["name"]["formatted"], "Ada Lovelace");

    let list = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &token))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    let list = json_body(list);
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["userName"], "ada@example.com");
}

#[tokio::test]
async fn users_route_rejects_duplicate_provider_account() {
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

    for expected_status in [StatusCode::CREATED, StatusCode::CONFLICT] {
        let response = router
            .handle_async(json_request(
                Method::POST,
                "/scim/v2/Users",
                r#"{"userName":"ada","externalId":"idp-ada","emails":[{"value":"ada@example.com"}]}"#,
                Some(&token),
            ))
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), expected_status);
        if expected_status == StatusCode::CONFLICT {
            let body = json_body(response);
            assert_eq!(body["detail"], "User already exists");
            assert_eq!(body["status"], "409");
            assert_eq!(body["scimType"], "uniqueness");
        }
    }
}

#[tokio::test]
async fn users_route_rejects_invalid_json_body() {
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
            "/scim/v2/Users",
            r#"{"userName":"ada""#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(json_body(response)["detail"]
        .as_str()
        .expect("detail should be string")
        .contains("invalid JSON request body"));
}

#[tokio::test]
async fn users_route_create_sets_location_header() {
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

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"ada@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(create.status(), StatusCode::CREATED);
    let location = create
        .headers()
        .get(header::LOCATION)
        .expect("location header should be set")
        .to_str()
        .expect("location should be string")
        .to_owned();
    let created = json_body(create);
    assert_eq!(location, created["meta"]["location"]);
}

#[tokio::test]
async fn users_route_rejects_invalid_email_values() {
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

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"ada","emails":[{"value":"not-an-email"}]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(create.status(), StatusCode::BAD_REQUEST);
    let body = json_body(create);
    assert_eq!(body["scimType"], "invalidValue");
    assert_eq!(body["detail"], "emails.value must be a valid email address");
}

#[tokio::test]
async fn users_route_rejects_invalid_user_name_without_emails() {
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

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"ada","name":{"formatted":"Ada Lovelace"}}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(create.status(), StatusCode::BAD_REQUEST);
    let body = json_body(create);
    assert_eq!(body["scimType"], "invalidValue");
    assert_eq!(
        body["detail"],
        "userName and emails.value must resolve to a valid email address"
    );
}

#[tokio::test]
async fn users_route_rejects_empty_user_name() {
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

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"   "}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(create.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(create)["detail"], "userName is required");
}

#[tokio::test]
async fn users_route_list_supports_user_name_co_filter() {
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

    for user_name in ["ada-filter@example.com", "grace-filter@example.com"] {
        let body = format!(r#"{{"userName":"{user_name}"}}"#);
        let create = router
            .handle_async(json_request(
                Method::POST,
                "/scim/v2/Users",
                &body,
                Some(&token),
            ))
            .await
            .expect("request should succeed");
        assert_eq!(create.status(), StatusCode::CREATED);
    }

    let filtered = router
        .handle_async(auth_request(
            Method::GET,
            "/scim/v2/Users?filter=userName%20co%20%22ada-filter%22",
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(filtered.status(), StatusCode::OK);
    let body = json_body(filtered);
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["userName"], "ada-filter@example.com");
}

#[tokio::test]
async fn users_route_rejects_reserved_profile_attributes_on_create_and_put() {
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

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"reserved-create@example.com","active":false}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(create.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(create)["scimType"], "mutability");

    let user_id =
        create_scim_user(&router, &token, "reserved-put@example.com", "Reserved Put").await;
    let put = router
        .handle_async(json_request(
            Method::PUT,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{"userName":"reserved-put@example.com","schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"emails":[{"value":"reserved-put@example.com"}],"meta":{"resourceType":"User"}}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(put.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(put)["scimType"], "mutability");
}

#[tokio::test]
async fn user_patch_replaces_valid_emails_and_rejects_invalid_email_values() {
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
    let user_id = create_scim_user(&router, &token, "email-patch@example.com", "Email Patch").await;

    let patch = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"replace","path":"emails","value":[{"value":"patched-email@example.com","primary":true}]}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(patch.status(), StatusCode::NO_CONTENT);

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    let body = json_body(fetched);
    assert_eq!(body["userName"], "patched-email@example.com");
    assert_eq!(body["emails"][0]["value"], "patched-email@example.com");

    let invalid = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"replace","path":"emails","value":[{"value":"not-an-email"}]}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(invalid)["scimType"], "invalidValue");

    let multiple_primary = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"replace","path":"emails","value":[
                    {"value":"one@example.com","primary":true},
                    {"value":"two@example.com","primary":true}
                ]}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(multiple_primary.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(multiple_primary)["scimType"], "invalidValue");

    let invalid_user_name = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"replace","path":"userName","value":"not-an-email"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(invalid_user_name.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(invalid_user_name)["detail"],
        "userName and emails.value must resolve to a valid email address"
    );
}

#[tokio::test]
async fn users_route_uses_user_name_as_external_id_fallback_and_lists_only_provider_users() {
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
    DbUserStore::new(adapter.as_ref())
        .create_user(CreateUserInput::new("Local User", "local@example.com").email_verified(true))
        .await
        .expect("local user should create");
    let token = encode_bearer_token("base-token", "okta", None);

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"the-idp-user","emails":[{"value":"idp@example.com"}]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(create.status(), StatusCode::CREATED);
    assert_eq!(json_body(create)["externalId"], "the-idp-user");

    let list = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &token))
        .await
        .expect("request should succeed");
    let list = json_body(list);
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["userName"], "idp@example.com");
}

#[tokio::test]
async fn users_route_lowercases_user_name_before_external_id_fallback() {
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

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"MixedCase@Example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(create.status(), StatusCode::CREATED);
    let body = json_body(create);
    assert_eq!(body["userName"], "mixedcase@example.com");
    assert_eq!(body["externalId"], "mixedcase@example.com");
}

#[tokio::test]
async fn users_route_filter_matches_user_name_eq() {
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

    for (user_name, email) in [("ada", "ada@example.com"), ("grace", "grace@example.com")] {
        let body = format!(r#"{{"userName":"{user_name}","emails":[{{"value":"{email}"}}]}}"#);
        router
            .handle_async(json_request(
                Method::POST,
                "/scim/v2/Users",
                &body,
                Some(&token),
            ))
            .await
            .expect("request should succeed");
    }

    let filtered = router
        .handle_async(auth_request(
            Method::GET,
            "/scim/v2/Users?filter=userName%20eq%20%22ada@example.com%22",
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(filtered.status(), StatusCode::OK);
    let filtered = json_body(filtered);
    assert_eq!(filtered["totalResults"], 1);
    assert_eq!(filtered["Resources"][0]["userName"], "ada@example.com");
}

#[tokio::test]
async fn users_route_supports_sort_and_pagination_parameters() {
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

    for email in [
        "charlie@example.com",
        "ada@example.com",
        "grace@example.com",
    ] {
        let body = format!(r#"{{"userName":"{email}"}}"#);
        router
            .handle_async(json_request(
                Method::POST,
                "/scim/v2/Users",
                &body,
                Some(&token),
            ))
            .await
            .expect("request should succeed");
    }

    let response = router
        .handle_async(auth_request(
            Method::GET,
            "/scim/v2/Users?sortBy=userName&sortOrder=ascending&startIndex=2&count=1",
            &token,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["totalResults"], 3);
    assert_eq!(body["startIndex"], 2);
    assert_eq!(body["itemsPerPage"], 1);
    assert_eq!(body["Resources"][0]["userName"], "charlie@example.com");
}

#[tokio::test]
async fn users_route_rejects_invalid_pagination_and_sort_order_inputs() {
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
    create_scim_user(
        &router,
        &token,
        "query-validation@example.com",
        "Query Validation",
    )
    .await;

    for path in [
        "/scim/v2/Users?startIndex=0",
        "/scim/v2/Users?startIndex=abc",
        "/scim/v2/Users?count=abc",
        "/scim/v2/Users?sortBy=userName&sortOrder=sideways",
    ] {
        let response = router
            .handle_async(auth_request(Method::GET, path, &token))
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(json_body(response)["scimType"], "invalidValue", "{path}");
    }
}

#[tokio::test]
async fn users_route_caps_items_per_page_to_advertised_filter_max_results() {
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

    for index in 0..201 {
        let body = format!(r#"{{"userName":"max-results-{index}@example.com"}}"#);
        let response = router
            .handle_async(json_request(
                Method::POST,
                "/scim/v2/Users",
                &body,
                Some(&token),
            ))
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let response = router
        .handle_async(auth_request(
            Method::GET,
            "/scim/v2/Users?count=999",
            &token,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["totalResults"], 201);
    assert_eq!(body["itemsPerPage"], 200);
    assert_eq!(body["Resources"].as_array().expect("resources").len(), 200);
}

#[tokio::test]
async fn users_route_put_replaces_scim_user_fields() {
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

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"ada@example.com","name":{"formatted":"Ada Lovelace"}}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let created = json_body(create);
    let id = created["id"].as_str().expect("id should be string");

    let put = router
        .handle_async(json_request(
            Method::PUT,
            &format!("/scim/v2/Users/{id}"),
            r#"{
                "userName":"ignored-for-email",
                "externalId":"external-ada",
                "name":{"formatted":"Countess Lovelace"},
                "emails":[{"value":"countess@example.com"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(put.status(), StatusCode::OK);
    let put = json_body(put);
    assert_eq!(put["externalId"], "external-ada");
    assert_eq!(put["userName"], "countess@example.com");
    assert_eq!(put["name"]["formatted"], "Countess Lovelace");
}

#[tokio::test]
async fn user_routes_emit_etag_and_reject_stale_if_match() {
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
            r#"{"userName":"etag@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(fetched.status(), StatusCode::OK);
    assert!(fetched.headers().get(header::ETAG).is_some());

    let stale = Request::builder()
        .method(Method::PUT)
        .uri(format!("/scim/v2/Users/{user_id}"))
        .header(header::CONTENT_TYPE, "application/scim+json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::IF_MATCH, r#"W/"stale""#)
        .body(br#"{"userName":"etag@example.com"}"#.to_vec())
        .expect("request should build");
    let stale = router
        .handle_async(stale)
        .await
        .expect("request should succeed");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(json_body(stale)["status"], "412");

    let stale_patch = router
        .handle_async(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/scim/v2/Users/{user_id}"))
                .header(header::CONTENT_TYPE, "application/scim+json")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::IF_MATCH, r#"W/"stale""#)
                .body(
                    br#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"title","value":"Updated"}]}"#
                        .to_vec(),
                )
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");
    assert_eq!(stale_patch.status(), StatusCode::PRECONDITION_FAILED);

    let stale_delete = router
        .handle_async(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/scim/v2/Users/{user_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::IF_MATCH, r#"W/"stale""#)
                .body(Vec::new())
                .expect("request should build"),
        )
        .await
        .expect("request should succeed");
    assert_eq!(stale_delete.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn get_user_applies_attributes_projection() {
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
            r#"{"userName":"projected@example.com","name":{"formatted":"Projected User"}}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let response = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}?attributes=userName"),
            &token,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["userName"], "projected@example.com");
    assert!(body.get("emails").is_none());
    assert!(body.get("displayName").is_none());
    assert!(body.get("meta").is_some());
}

#[tokio::test]
async fn get_user_projection_supports_subattributes_and_extension_paths() {
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
    let enterprise_schema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:schemas:core:2.0:User","{enterprise_schema}"],
                    "userName":"projection-path@example.com",
                    "phoneNumbers":[{{"value":"+15550000003","type":"work"}}],
                    "{enterprise_schema}":{{"department":"Identity","employeeNumber":"E-456"}}
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let response = router
        .handle_async(auth_request(
            Method::GET,
            &format!(
                "/scim/v2/Users/{user_id}?attributes=phoneNumbers.value,{enterprise_schema}:department"
            ),
            &token,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["phoneNumbers"][0]["value"], "+15550000003");
    assert!(body["phoneNumbers"][0].get("type").is_none());
    assert_eq!(body[enterprise_schema]["department"], "Identity");
    assert!(body[enterprise_schema].get("employeeNumber").is_none());
    assert!(body.get("userName").is_none());
}

#[tokio::test]
async fn get_user_excluded_attributes_supports_subattributes_and_extension_paths() {
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
    let enterprise_schema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            &format!(
                r#"{{
                    "userName":"excluded-subattrs@example.com",
                    "title":"Senior Engineer",
                    "phoneNumbers":[{{"value":"+15551234567","type":"work"}}],
                    "{enterprise_schema}":{{"department":"Engineering","division":"Platform"}}
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let response = router
        .handle_async(auth_request(
            Method::GET,
            &format!(
                "/scim/v2/Users/{user_id}?excludedAttributes=title,phoneNumbers.value,{enterprise_schema}:department"
            ),
            &token,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert!(body.get("title").is_none());
    assert!(body["phoneNumbers"][0].get("value").is_none());
    assert_eq!(body["phoneNumbers"][0]["type"], "work");
    assert!(body[enterprise_schema].get("department").is_none());
    assert_eq!(body[enterprise_schema]["division"], "Platform");
}

#[tokio::test]
async fn list_and_search_users_apply_projection_and_extended_filters() {
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

    for (email, title) in [
        ("ada-filter@example.com", "Engineer"),
        ("grace-filter@example.com", "Scientist"),
    ] {
        let response = router
            .handle_async(json_request(
                Method::POST,
                "/scim/v2/Users",
                &format!(r#"{{"userName":"{email}","title":"{title}"}}"#),
                Some(&token),
            ))
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let list = router
        .handle_async(auth_request(
            Method::GET,
            "/scim/v2/Users?attributes=userName,title&filter=title%20co%20%22gine%22",
            &token,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(list.status(), StatusCode::OK);
    let body = json_body(list);
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["userName"], "ada-filter@example.com");
    assert_eq!(body["Resources"][0]["title"], "Engineer");
    assert!(body["Resources"][0].get("displayName").is_none());

    let search = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users/.search",
            r#"{"filter":"title eq \"Scientist\"","attributes":["userName","title"]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(search.status(), StatusCode::OK);
    let body = json_body(search);
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["userName"], "grace-filter@example.com");
    assert!(body["Resources"][0].get("emails").is_none());
}

#[tokio::test]
async fn users_route_rejects_invalid_list_filter_with_scim_error() {
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
        .handle_async(auth_request(
            Method::GET,
            "/scim/v2/Users?filter=userName%20eq",
            &token,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response);
    assert_eq!(body["scimType"], "invalidFilter");
    assert_eq!(body["status"], "400");
}

#[tokio::test]
async fn users_search_route_rejects_invalid_filter_with_scim_error() {
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
            "/scim/v2/Users/.search",
            r#"{"filter":"userName eq"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response);
    assert_eq!(body["scimType"], "invalidFilter");
    assert_eq!(body["status"], "400");
}

#[tokio::test]
async fn users_route_accepts_valid_extended_filter_after_validation() {
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

    for (email, department) in [
        ("identity@example.com", "Identity"),
        ("billing@example.com", "Billing"),
    ] {
        let response = router
            .handle_async(json_request(
                Method::POST,
                "/scim/v2/Users",
                &format!(
                    r#"{{"userName":"{email}","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{{"department":"{department}"}}}}"#
                ),
                Some(&token),
            ))
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let response = router
        .handle_async(auth_request(
            Method::GET,
            "/scim/v2/Users?filter=urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department%20eq%20%22Identity%22",
            &token,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["userName"], "identity@example.com");
}

#[tokio::test]
async fn user_resource_includes_read_only_group_memberships() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "groups-owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let user_id = create_scim_user(&router, &token, "member@example.com", "Team Member").await;
    let group_id = create_scim_group(&router, &token, "Identity", "identity", &[&user_id]).await;

    let response = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response);
    assert_eq!(body["groups"][0]["value"], group_id);
    assert_eq!(body["groups"][0]["display"], "Identity");
    assert!(body["groups"][0]["$ref"]
        .as_str()
        .expect("$ref")
        .ends_with(&format!("/scim/v2/Groups/{group_id}")));
}

#[tokio::test]
async fn user_extended_and_enterprise_attributes_are_persisted() {
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
    let enterprise_schema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:schemas:core:2.0:User","{enterprise_schema}"],
                    "userName":"extended@example.com",
                    "title":"Principal Engineer",
                    "preferredLanguage":"en-US",
                    "phoneNumbers":[{{"value":"+15555550123","type":"work"}}],
                    "{enterprise_schema}":{{"department":"Identity","employeeNumber":"E-123"}}
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = json_body(created);
    assert_eq!(created["title"], "Principal Engineer");
    let user_id = created["id"].as_str().expect("id").to_owned();

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(fetched.status(), StatusCode::OK);
    let fetched = json_body(fetched);
    assert_eq!(fetched["title"], "Principal Engineer");
    assert_eq!(fetched["preferredLanguage"], "en-US");
    assert_eq!(fetched["phoneNumbers"][0]["value"], "+15555550123");
    assert_eq!(fetched[enterprise_schema]["department"], "Identity");
    assert_eq!(fetched[enterprise_schema]["employeeNumber"], "E-123");
}

#[tokio::test]
async fn user_patch_persists_extended_and_enterprise_attributes() {
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
    let enterprise_schema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"patch-extended@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let patch = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            &format!(
                r#"{{
                    "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations":[
                        {{"op":"replace","path":"title","value":"Director"}},
                        {{"op":"replace","path":"{enterprise_schema}:department","value":"Security"}}
                    ]
                }}"#
            ),
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(patch.status(), StatusCode::NO_CONTENT);

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    let fetched = json_body(fetched);
    assert_eq!(fetched["title"], "Director");
    assert_eq!(fetched[enterprise_schema]["department"], "Security");

    let remove = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"remove","path":"title"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(remove.status(), StatusCode::NO_CONTENT);

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert!(json_body(fetched).get("title").is_none());
}

#[tokio::test]
async fn user_patch_replaces_and_removes_multivalued_attributes() {
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
            r#"{"userName":"multi-patch@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let patch = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[
                    {
                        "op":"replace",
                        "path":"phoneNumbers",
                        "value":[
                            {"value":"+15550000001","type":"work","primary":true},
                            {"value":"+15550000002","type":"mobile"}
                        ]
                    },
                    {"op":"remove","path":"phoneNumbers[value eq \"+15550000002\"]"}
                ]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(patch.status(), StatusCode::NO_CONTENT);

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    let body = json_body(fetched);
    assert_eq!(body["phoneNumbers"].as_array().expect("phones").len(), 1);
    assert_eq!(body["phoneNumbers"][0]["value"], "+15550000001");
}

#[tokio::test]
async fn user_patch_remove_external_id_resets_account_id_to_user_name() {
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
            r#"{"userName":"remove-external@example.com","externalId":"upstream-123"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let patch = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"remove","path":"externalId"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(patch.status(), StatusCode::NO_CONTENT);

    let fetched = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(
        json_body(fetched)["externalId"],
        "remove-external@example.com"
    );
}

#[tokio::test]
async fn user_patch_rejects_read_only_attributes_with_mutability_error() {
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
            r#"{"userName":"readonly-patch@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let user_id = json_body(created)["id"].as_str().expect("id").to_owned();

    let response = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"replace","path":"id","value":"new-id"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response);
    assert_eq!(body["scimType"], "mutability");
}

#[tokio::test]
async fn users_route_rejects_multiple_primary_multivalued_attributes() {
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
            "/scim/v2/Users",
            r#"{
                "userName":"primary@example.com",
                "emails":[
                    {"value":"one@example.com","primary":true},
                    {"value":"two@example.com","primary":true}
                ]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)["scimType"], "invalidValue");
}

#[tokio::test]
async fn users_route_gets_patches_and_deletes_scim_user() {
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

    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"ada@example.com","name":{"formatted":"Ada Lovelace"}}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let created = json_body(create);
    let id = created["id"].as_str().expect("id should be string");

    let get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(json_body(get)["id"], id);

    let patch = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"replace","path":"name.formatted","value":"Countess Lovelace"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(patch.status(), StatusCode::NO_CONTENT);

    let updated = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(updated)["name"]["formatted"], "Countess Lovelace");

    let delete = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Users/{id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let missing = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn users_route_delete_removes_scim_profile_and_team_memberships() {
    let (adapter, router, context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    let (owner_cookie, owner_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "cleanup-owner@example.com")
            .await
            .expect("owner session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &owner_id, "owner")
        .await
        .expect("owner member");
    let token = generate_scim_token(&router, &owner_cookie, "okta", Some("org_1")).await;
    let user_id =
        create_scim_user(&router, &token, "cleanup-user@example.com", "Cleanup User").await;
    let group_id = create_scim_group(
        &router,
        &token,
        "Cleanup Group",
        "cleanup-group",
        &[&user_id],
    )
    .await;

    let delete = router
        .handle_async(auth_request(
            Method::DELETE,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);

    let profiles = adapter.records("scimUserProfile").await;
    assert!(
        profiles.iter().all(|record| {
            !matches!(record.get("userId"), Some(DbValue::String(value)) if value == &user_id)
        }),
        "deleted users must not leave SCIM user profiles"
    );
    let memberships = adapter.records("team_member").await;
    assert!(
        memberships.iter().all(|record| {
            !matches!(record.get("user_id"), Some(DbValue::String(value)) if value == &user_id)
        }),
        "deleted users must not leave team memberships"
    );
    let group = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{group_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert!(json_body(group).get("members").is_none());
}

#[tokio::test]
async fn users_route_patch_requires_patch_op_schema() {
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
    let create = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"patch-schema@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    let created = json_body(create);
    let id = created["id"].as_str().expect("id should be string");

    let patch = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{id}"),
            r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"Operations":[{"op":"replace","path":"name.formatted","value":"Invalid"}]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(patch.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(patch)["detail"], "Invalid schemas for PatchOp");
}

#[tokio::test]
async fn users_route_patch_rejects_unknown_operation_with_invalid_syntax() {
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
    let user_id = create_scim_user(&router, &token, "invalid-op@example.com", "Invalid Op").await;

    let response = router
        .handle_async(json_request(
            Method::PATCH,
            &format!("/scim/v2/Users/{user_id}"),
            r#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations":[{"op":"multiply","path":"title","value":"Nope"}]
            }"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response)["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn users_route_returns_not_found_for_missing_user_on_item_routes() {
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
    let cases = [
        (Method::GET, None),
        (Method::PUT, Some(r#"{"userName":"missing@example.com"}"#)),
        (
            Method::PATCH,
            Some(
                r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.formatted","value":"Missing"}]}"#,
            ),
        ),
        (Method::DELETE, None),
    ];

    for (method, body) in cases {
        let response = match body {
            Some(body) => json_request(method, "/scim/v2/Users/missing-user", body, Some(&token)),
            None => auth_request(method, "/scim/v2/Users/missing-user", &token),
        };
        let response = router
            .handle_async(response)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
