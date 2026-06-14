//! Regression tests for OPE-111: SCIM user/group projections must respect the
//! same org/provider boundary as `/Groups` routes.

use super::*;

async fn org_scim_token(adapter: &MemoryAdapter, organization_id: &str) -> String {
    ScimProviderStore::new(adapter)
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: Some(organization_id.to_owned()),
            user_id: None,
        })
        .await
        .expect("provider should create");
    encode_bearer_token("base-token", "okta", Some(organization_id))
}

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

async fn seed_team_member(adapter: &dyn DbAdapter, team_id: &str, user_id: &str) {
    adapter
        .create(
            Create::new("team_member")
                .data("id", DbValue::String(format!("tm_{team_id}_{user_id}")))
                .data("team_id", DbValue::String(team_id.to_owned()))
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .force_allow_id(),
        )
        .await
        .expect("team member should create");
}

async fn seed_native_org_user(
    adapter: &MemoryAdapter,
    organization_id: &str,
    email: &str,
    name: &str,
) -> String {
    let user = DbUserStore::new(adapter)
        .create_user(CreateUserInput::new(name, email).email_verified(true))
        .await
        .expect("native user should create");
    seed_member(adapter, organization_id, &user.id, "member")
        .await
        .expect("native org member should create");
    user.id
}

fn user_groups(body: &Value) -> Vec<&str> {
    body["groups"]
        .as_array()
        .map(|groups| {
            groups
                .iter()
                .filter_map(|group| group["value"].as_str())
                .collect()
        })
        .unwrap_or_default()
}

fn group_member_ids(body: &Value) -> Vec<&str> {
    body["members"]
        .as_array()
        .map(|members| {
            members
                .iter()
                .filter_map(|member| member["value"].as_str())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn user_groups_omit_native_organization_teams() {
    let (adapter, router, _context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    let token = org_scim_token(adapter.as_ref(), "org_1").await;
    let user_id = create_scim_user(&router, &token, "member@example.com", "SCIM Member").await;
    let scim_group_id =
        create_scim_group(&router, &token, "SCIM Group", "scim-group", &[&user_id]).await;

    seed_native_team(adapter.as_ref(), "org_1", "native_team_1", "Native Team").await;
    seed_team_member(adapter.as_ref(), "native_team_1", &user_id).await;

    let get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Users/{user_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::OK);
    let get = json_body(get);
    assert_eq!(user_groups(&get), vec![scim_group_id.as_str()]);
    assert!(!user_groups(&get).contains(&"native_team_1"));

    let list = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &token))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    let list = json_body(list);
    assert_eq!(list["totalResults"], 1);
    assert_eq!(
        user_groups(&list["Resources"][0]),
        vec![scim_group_id.as_str()]
    );

    let search = router
        .handle_async(json_request(
            Method::POST,
            "/scim/v2/Users/.search",
            r#"{"filter":"userName eq \"member@example.com\""}"#,
            Some(&token),
        ))
        .await
        .expect("request should succeed");
    assert_eq!(search.status(), StatusCode::OK);
    let search = json_body(search);
    assert_eq!(
        user_groups(&search["Resources"][0]),
        vec![scim_group_id.as_str()]
    );
}

#[tokio::test]
async fn group_members_omit_non_provider_scim_users() {
    let (adapter, router, _context) =
        router_with_context_and_organization(crate::scim_options_for_manual_provider_tokens())
            .expect("router");
    seed_organization(adapter.as_ref(), "org_1")
        .await
        .expect("org");
    let token = org_scim_token(adapter.as_ref(), "org_1").await;
    let scim_user_id =
        create_scim_user(&router, &token, "scim-member@example.com", "SCIM Member").await;
    let group_id = create_scim_group(
        &router,
        &token,
        "SCIM Group",
        "scim-group",
        &[&scim_user_id],
    )
    .await;
    let native_user_id = seed_native_org_user(
        adapter.as_ref(),
        "org_1",
        "native-member@example.com",
        "Native Member",
    )
    .await;
    seed_team_member(adapter.as_ref(), &group_id, &native_user_id).await;

    let get = router
        .handle_async(auth_request(
            Method::GET,
            &format!("/scim/v2/Groups/{group_id}"),
            &token,
        ))
        .await
        .expect("request should succeed");
    assert_eq!(get.status(), StatusCode::OK);
    let get = json_body(get);
    assert_eq!(group_member_ids(&get), vec![scim_user_id.as_str()]);
    assert!(!group_member_ids(&get).contains(&native_user_id.as_str()));

    let list = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Groups", &token))
        .await
        .expect("request should succeed");
    assert_eq!(list.status(), StatusCode::OK);
    let list = json_body(list);
    let listed_group = list["Resources"]
        .as_array()
        .and_then(|resources| resources.iter().find(|resource| resource["id"] == group_id))
        .expect("SCIM group should be listed");
    assert_eq!(group_member_ids(listed_group), vec![scim_user_id.as_str()]);
}
