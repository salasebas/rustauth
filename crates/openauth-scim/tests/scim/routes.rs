use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::db::{Create, DbAdapter, DbValue, Delete, FindOne, MemoryAdapter, Where};
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::{CreateUserInput, DbUserStore};
use openauth_plugins::organization::{organization_with_options, OrganizationOptions};
use openauth_scim::store::{CreateScimProviderInput, ScimProviderStore};
use openauth_scim::token::encode_bearer_token;
use openauth_scim::{scim, DefaultScimProvider, ScimHookError, ScimOptions, ScimTokenStorage};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

const SECRET: &str = "secret-a-at-least-32-chars-long!!";

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
    assert_eq!(body["bulk"]["supported"], false);
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
    assert_eq!(list["totalResults"], 1);
    assert_eq!(
        list["Resources"][0]["id"],
        "urn:ietf:params:scim:schemas:core:2.0:User"
    );

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
        openauth_scim::errors::SCIM_ERROR_SCHEMA
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
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["name"], "User");

    let user = router
        .handle_async(request(Method::GET, "/scim/v2/ResourceTypes/User"))
        .await
        .expect("request should succeed");
    assert_eq!(user.status(), StatusCode::OK);
    assert_eq!(json_body(user)["endpoint"], "/Users");

    let missing = router
        .handle_async(request(Method::GET, "/scim/v2/ResourceTypes/Group"))
        .await
        .expect("request should succeed");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

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
            Some(r#"{"userName":"ada"}"#),
        ),
        (Method::GET, "/scim/v2/Users/user_1", None),
        (
            Method::PUT,
            "/scim/v2/Users/user_1",
            Some(r#"{"userName":"ada"}"#),
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

    for expected_status in [StatusCode::CREATED, StatusCode::BAD_REQUEST] {
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
        if expected_status == StatusCode::BAD_REQUEST {
            assert_eq!(json_body(response)["detail"], "User already exists");
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
            r#"{"userName":"ada","name":{"formatted":"Ada Lovelace"}}"#,
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

#[tokio::test]
async fn management_generate_token_requires_session_and_token_can_provision_users() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");

    let anonymous = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            "",
        ))
        .await
        .expect("request should succeed");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");
    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"scim-user","emails":[{"value":"scim@example.com"}]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn management_hashed_token_storage_can_authenticate_generated_token() {
    generated_token_can_provision_user_with_options(ScimOptions {
        token_storage: ScimTokenStorage::Hashed,
        ..ScimOptions::default()
    })
    .await;
}

#[tokio::test]
async fn management_encrypted_token_storage_can_authenticate_generated_token() {
    generated_token_can_provision_user_with_options(ScimOptions {
        token_storage: ScimTokenStorage::Encrypted,
        ..ScimOptions::default()
    })
    .await;
}

#[tokio::test]
async fn management_custom_hash_token_storage_can_authenticate_generated_token() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        token_storage: ScimTokenStorage::custom_hash(|token| {
            Box::pin(async move { Ok(format!("{token}:hashed")) })
        }),
        ..ScimOptions::default()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();
    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed")
        .expect("provider should exist");
    assert!(provider.scim_token.ends_with(":hashed"));

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"custom-hash@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn management_custom_encryption_token_storage_can_authenticate_generated_token() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        token_storage: ScimTokenStorage::custom_encryption(
            |token| Box::pin(async move { Ok(token.chars().rev().collect()) }),
            |token| Box::pin(async move { Ok(token.chars().rev().collect()) }),
        ),
        ..ScimOptions::default()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"custom-encryption@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn management_before_token_hook_failure_aborts_persistence() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_hook = Arc::clone(&calls);
    let (adapter, router, context) = router_with_context(ScimOptions {
        before_token_generated: Some(Arc::new(move |input| {
            let calls = Arc::clone(&calls_for_hook);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(input.user.email, "owner@example.com");
                assert!(input.member.is_none());
                assert!(!input.scim_token.is_empty());
                Err(ScimHookError::forbidden("blocked by hook"))
            })
        })),
        ..ScimOptions::default()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response)["message"], "blocked by hook");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed");
    assert!(provider.is_none());
}

#[tokio::test]
async fn management_before_token_hook_failure_preserves_existing_provider() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        before_token_generated: Some(Arc::new(|_input| {
            Box::pin(async { Err(ScimHookError::forbidden("blocked replacement")) })
        })),
        ..ScimOptions::default()
    })
    .expect("router");
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "existing-token".to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await
        .expect("provider should create");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed")
        .expect("existing provider should be preserved");
    assert_eq!(provider.scim_token, "existing-token");
}

#[tokio::test]
async fn management_after_token_hook_receives_persisted_provider_and_returned_token() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_hook = Arc::clone(&calls);
    let seen_token = Arc::new(std::sync::Mutex::new(String::new()));
    let seen_token_for_hook = Arc::clone(&seen_token);
    let (adapter, router, context) = router_with_context(ScimOptions {
        after_token_generated: Some(Arc::new(move |input| {
            let calls = Arc::clone(&calls_for_hook);
            let seen_token = Arc::clone(&seen_token_for_hook);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(input.provider.provider_id, "okta");
                assert_eq!(input.user.email, "owner@example.com");
                assert!(!input.provider.scim_token.is_empty());
                *seen_token.lock().expect("token mutex should lock") = input.scim_token;
                Ok(())
            })
        })),
        ..ScimOptions::default()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::CREATED);
    let returned_token = json_body(response)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        seen_token.lock().expect("token mutex should lock").as_str(),
        returned_token
    );
}

#[tokio::test]
async fn management_lists_gets_and_deletes_provider_connections() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        provider_ownership: openauth_scim::ProviderOwnershipOptions { enabled: true },
        ..ScimOptions::default()
    })
    .expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    let list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    let list = json_body(list);
    assert_eq!(list["providers"][0]["providerId"], "okta");
    assert!(list["providers"][0].get("scimToken").is_none());

    let get = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=okta",
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(json_body(get)["providerId"], "okta");

    let delete = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/delete-provider-connection",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(delete.status(), StatusCode::OK);
    assert_eq!(json_body(delete)["success"], true);

    let list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(list)["providers"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn management_unknown_provider_get_and_delete_return_not_found() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let get = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=missing",
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::NOT_FOUND);

    let delete = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/delete-provider-connection",
            r#"{"providerId":"missing"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(delete.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn management_token_replacement_invalidates_previous_token() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let first = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_token = json_body(first)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let second = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(second.status(), StatusCode::CREATED);
    let second_token = json_body(second)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();
    assert_ne!(first_token, second_token);

    let old_token_response = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &first_token))
        .await
        .expect("request should succeed");
    assert_eq!(old_token_response.status(), StatusCode::UNAUTHORIZED);

    let new_token_response = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &second_token))
        .await
        .expect("request should succeed");
    assert_eq!(new_token_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn management_generate_token_rejects_provider_ids_with_colons() {
    let (adapter, router, context) = router_with_context(ScimOptions::default()).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta:tenant"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn management_provider_ownership_blocks_other_users() {
    let (adapter, router, context) = router_with_context(ScimOptions {
        provider_ownership: openauth_scim::ProviderOwnershipOptions { enabled: true },
        ..ScimOptions::default()
    })
    .expect("router");
    let owner_cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("owner session cookie should create");
    let other_cookie = session_cookie(adapter.as_ref(), &context, "other@example.com")
        .await
        .expect("other session cookie should create");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &owner_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);

    let get = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=okta",
            &other_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::FORBIDDEN);

    let regenerate = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &other_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(regenerate.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn org_scoped_management_requires_admin_or_owner_and_provisions_membership() {
    let (adapter, router, context) =
        router_with_context_and_organization(ScimOptions::default()).expect("router");
    let (admin_cookie, admin_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "admin@example.com")
            .await
            .expect("admin session");
    let (member_cookie, _member_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "member@example.com")
            .await
            .expect("member session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &admin_id, "admin")
        .await
        .expect("admin member");
    seed_member(adapter.as_ref(), "org_1", &_member_id, "member")
        .await
        .expect("regular member");

    let denied = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let member_list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(member_list.status(), StatusCode::OK);
    assert_eq!(
        json_body(member_list)["providers"]
            .as_array()
            .expect("providers should be array")
            .len(),
        0
    );

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"new-org-user","emails":[{"value":"new-org-user@example.com"}]}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
    let user_id = json_body(created)["id"]
        .as_str()
        .expect("id should be string")
        .to_owned();

    let member = adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String("org_1".to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id))),
        )
        .await
        .expect("member lookup should succeed");
    assert!(member.is_some());
}

#[tokio::test]
async fn org_scoped_user_lists_are_isolated_by_organization() {
    let (adapter, router, context) =
        router_with_context_and_organization(ScimOptions::default()).expect("router");
    let (admin_cookie, admin_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "admin@example.com")
            .await
            .expect("admin session");
    for org_id in ["org_a", "org_b"] {
        seed_organization(adapter.as_ref(), org_id)
            .await
            .expect("org should seed");
        seed_member(adapter.as_ref(), org_id, &admin_id, "admin")
            .await
            .expect("admin member should seed");
    }

    let token_a = generate_scim_token(&router, &admin_cookie, "provider-a", Some("org_a")).await;
    let token_b = generate_scim_token(&router, &admin_cookie, "provider-b", Some("org_b")).await;

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"org-a-user@example.com"}"#,
            Some(&token_a),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);

    let org_a = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &token_a))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(org_a)["totalResults"], 1);

    let org_b = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &token_b))
        .await
        .expect("request should succeed");
    assert_eq!(json_body(org_b)["totalResults"], 0);
}

#[tokio::test]
async fn org_scoped_provider_cannot_be_replaced_by_omitting_organization_id() {
    let (adapter, router, context) =
        router_with_context_and_organization(ScimOptions::default()).expect("router");
    let (admin_cookie, admin_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "admin@example.com")
            .await
            .expect("admin session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &admin_id, "admin")
        .await
        .expect("admin member");

    let org_token = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(org_token.status(), StatusCode::CREATED);

    let personal_replace = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(personal_replace.status(), StatusCode::FORBIDDEN);

    let provider = ScimProviderStore::new(adapter.as_ref())
        .find_by_provider_id("okta")
        .await
        .expect("provider lookup should succeed")
        .expect("provider should still exist");
    assert_eq!(provider.organization_id.as_deref(), Some("org_1"));
}

#[tokio::test]
async fn org_scoped_provider_creator_loses_access_after_member_removal() {
    let (adapter, router, context) =
        router_with_context_and_organization(ScimOptions::default()).expect("router");
    let (admin_cookie, admin_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "admin@example.com")
            .await
            .expect("admin session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &admin_id, "admin")
        .await
        .expect("admin member");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);

    remove_member(adapter.as_ref(), "org_1", &admin_id)
        .await
        .expect("member should remove");

    let get = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=okta",
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::FORBIDDEN);

    let list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &admin_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(
        json_body(list)["providers"]
            .as_array()
            .expect("providers should be array")
            .len(),
        0
    );
}

#[tokio::test]
async fn org_scoped_management_allows_any_member_when_required_role_is_empty() {
    let (adapter, router, context) = router_with_context_and_organization(ScimOptions {
        required_role: Some(Vec::new()),
        ..ScimOptions::default()
    })
    .expect("router");
    let (member_cookie, member_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "member@example.com")
            .await
            .expect("member session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &member_id, "member")
        .await
        .expect("regular member");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &member_cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(generated.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn org_scoped_management_accepts_custom_required_role_from_comma_separated_member_roles() {
    let (adapter, router, context) = router_with_context_and_organization(ScimOptions {
        required_role: Some(vec!["scim-admin".to_owned()]),
        ..ScimOptions::default()
    })
    .expect("router");
    let (member_cookie, member_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "scim-admin@example.com")
            .await
            .expect("member session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &member_id, "viewer, scim-admin")
        .await
        .expect("member");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);

    let list = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &member_cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    assert_eq!(json_body(list)["providers"][0]["providerId"], "okta");
}

#[tokio::test]
async fn org_scoped_management_uses_custom_organization_creator_role_by_default() {
    let (adapter, router, context) = router_with_context_and_organization_options(
        ScimOptions::default(),
        OrganizationOptions::builder()
            .creator_role("creator")
            .build(),
    )
    .expect("router");
    let (creator_cookie, creator_id) =
        session_cookie_with_user(adapter.as_ref(), &context, "creator@example.com")
            .await
            .expect("creator session");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    seed_member(adapter.as_ref(), "org_1", &creator_id, "creator")
        .await
        .expect("creator member");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta","organizationId":"org_1"}"#,
            &creator_cookie,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(generated.status(), StatusCode::CREATED);
}

fn router() -> Result<AuthRouter, openauth_core::error::OpenAuthError> {
    router_with_adapter().map(|(_adapter, router)| router)
}

fn router_with_adapter(
) -> Result<(Arc<MemoryAdapter>, AuthRouter), openauth_core::error::OpenAuthError> {
    router_with_context(ScimOptions::default()).map(|(adapter, router, _context)| (adapter, router))
}

fn router_with_context(
    options: ScimOptions,
) -> Result<
    (
        Arc<MemoryAdapter>,
        AuthRouter,
        openauth_core::context::AuthContext,
    ),
    openauth_core::error::OpenAuthError,
> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            secret: Some(SECRET.to_owned()),
            plugins: vec![scim(options)],
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context.clone(),
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router, context))
}

fn router_with_context_and_organization(
    options: ScimOptions,
) -> Result<
    (
        Arc<MemoryAdapter>,
        AuthRouter,
        openauth_core::context::AuthContext,
    ),
    openauth_core::error::OpenAuthError,
> {
    router_with_context_and_organization_options(options, OrganizationOptions::default())
}

fn router_with_context_and_organization_options(
    options: ScimOptions,
    organization_options: OrganizationOptions,
) -> Result<
    (
        Arc<MemoryAdapter>,
        AuthRouter,
        openauth_core::context::AuthContext,
    ),
    openauth_core::error::OpenAuthError,
> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("https://app.example.com".to_owned()),
            secret: Some(SECRET.to_owned()),
            plugins: vec![
                organization_with_options(organization_options),
                scim(options),
            ],
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let router = AuthRouter::with_async_endpoints(
        context.clone(),
        Vec::new(),
        core_auth_async_endpoints(adapter.clone()),
    )?;
    Ok((adapter, router, context))
}

fn request(method: Method, path: &str) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .body(Vec::new())
        .expect("request should build")
}

fn auth_request(method: Method, path: &str, token: &str) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Vec::new())
        .expect("request should build")
}

fn session_request(method: Method, path: &str, cookie: &str) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie)
        .body(Vec::new())
        .expect("request should build")
}

fn json_request(method: Method, path: &str, body: &str, token: Option<&str>) -> Request<Vec<u8>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/scim+json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder
        .body(body.as_bytes().to_vec())
        .expect("request should build")
}

fn session_json_request(method: Method, path: &str, body: &str, cookie: &str) -> Request<Vec<u8>> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .body(body.as_bytes().to_vec())
        .expect("request should build")
}

async fn session_cookie(
    adapter: &MemoryAdapter,
    context: &openauth_core::context::AuthContext,
    email: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    session_cookie_with_user(adapter, context, email)
        .await
        .map(|(cookie, _user_id)| cookie)
}

async fn session_cookie_with_user(
    adapter: &MemoryAdapter,
    context: &openauth_core::context::AuthContext,
    email: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let user = DbUserStore::new(adapter)
        .create_user(CreateUserInput::new("Session User", email).email_verified(true))
        .await?;
    let user_id = user.id.clone();
    let session = DbSessionStore::new(adapter)
        .create_session(CreateSessionInput::new(
            user.id,
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions::default(),
    )?;
    Ok((cookie_header(&cookies), user_id))
}

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn seed_organization(
    adapter: &dyn DbAdapter,
    id: &str,
) -> Result<(), openauth_core::error::OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String(id.to_owned()))
                .data("name", DbValue::String("Test Org".to_owned()))
                .data("slug", DbValue::String(id.to_owned()))
                .data("logo", DbValue::Null)
                .data("metadata", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Null)
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

async fn seed_member(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user_id: &str,
    role: &str,
) -> Result<(), openauth_core::error::OpenAuthError> {
    adapter
        .create(
            Create::new("member")
                .data(
                    "id",
                    DbValue::String(format!("member_{organization_id}_{user_id}")),
                )
                .data(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("role", DbValue::String(role.to_owned()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}

async fn remove_member(
    adapter: &dyn DbAdapter,
    organization_id: &str,
    user_id: &str,
) -> Result<(), openauth_core::error::OpenAuthError> {
    adapter
        .delete(
            Delete::new("member")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
        )
        .await
}

async fn generated_token_can_provision_user_with_options(options: ScimOptions) {
    let (adapter, router, context) = router_with_context(options).expect("router");
    let cookie = session_cookie(adapter.as_ref(), &context, "owner@example.com")
        .await
        .expect("session cookie should create");

    let generated = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            r#"{"providerId":"okta"}"#,
            &cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(generated.status(), StatusCode::CREATED);
    let token = json_body(generated)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned();

    let created = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users",
            r#"{"userName":"storage-mode@example.com"}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(created.status(), StatusCode::CREATED);
}

async fn generate_scim_token(
    router: &AuthRouter,
    cookie: &str,
    provider_id: &str,
    organization_id: Option<&str>,
) -> String {
    let body = match organization_id {
        Some(organization_id) => {
            format!(r#"{{"providerId":"{provider_id}","organizationId":"{organization_id}"}}"#)
        }
        None => format!(r#"{{"providerId":"{provider_id}"}}"#),
    };
    let response = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/generate-token",
            &body,
            cookie,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response)["scimToken"]
        .as_str()
        .expect("token should be string")
        .to_owned()
}

fn json_body(response: http::Response<Vec<u8>>) -> Value {
    serde_json::from_slice(response.body()).expect("response should be JSON")
}
