use openauth_core::db::MemoryAdapter;
use openauth_scim::store::{CreateScimProviderInput, ScimProviderStore};

#[tokio::test]
async fn provider_store_creates_finds_lists_and_deletes_provider() {
    let adapter = MemoryAdapter::new();
    let store = ScimProviderStore::new(&adapter);

    let created = store
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "token-secret".to_owned(),
            organization_id: Some("org_1".to_owned()),
            user_id: Some("user_1".to_owned()),
        })
        .await
        .expect("provider should create");

    assert_eq!(created.provider_id, "okta");
    assert_eq!(created.organization_id.as_deref(), Some("org_1"));

    let found = store
        .find_by_provider_id("okta")
        .await
        .expect("lookup should succeed")
        .expect("provider should exist");
    assert_eq!(found.id, created.id);

    let providers = store.list().await.expect("list should succeed");
    assert_eq!(providers.len(), 1);

    store.delete("okta").await.expect("delete should succeed");
    let found = store
        .find_by_provider_id("okta")
        .await
        .expect("lookup should succeed");
    assert!(found.is_none());
}

#[tokio::test]
async fn provider_store_lists_by_owner_and_organization() {
    let adapter = MemoryAdapter::new();
    let store = ScimProviderStore::new(&adapter);

    store
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "token-secret".to_owned(),
            organization_id: Some("org_1".to_owned()),
            user_id: Some("user_1".to_owned()),
        })
        .await
        .expect("provider should create");
    store
        .create(CreateScimProviderInput {
            provider_id: "entra".to_owned(),
            scim_token: "token-secret-2".to_owned(),
            organization_id: Some("org_2".to_owned()),
            user_id: Some("user_2".to_owned()),
        })
        .await
        .expect("provider should create");

    let by_user = store
        .list_by_user("user_1")
        .await
        .expect("list by user should succeed");
    assert_eq!(by_user.len(), 1);
    assert_eq!(by_user[0].provider_id, "okta");

    let by_org = store
        .find_by_organization_id("org_2")
        .await
        .expect("find by org should succeed")
        .expect("provider should exist");
    assert_eq!(by_org.provider_id, "entra");
}

#[tokio::test]
async fn provider_store_upsert_updates_existing_provider_without_changing_id() {
    let adapter = MemoryAdapter::new();
    let store = ScimProviderStore::new(&adapter);

    let created = store
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "token-secret".to_owned(),
            organization_id: Some("org_1".to_owned()),
            user_id: Some("user_1".to_owned()),
        })
        .await
        .expect("provider should create");

    let rotated = store
        .upsert(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "token-secret-rotated".to_owned(),
            organization_id: Some("org_1".to_owned()),
            user_id: Some("user_2".to_owned()),
        })
        .await
        .expect("provider should upsert");

    assert_eq!(rotated.id, created.id);
    assert_eq!(rotated.scim_token, "token-secret-rotated");
    assert_eq!(rotated.user_id.as_deref(), Some("user_2"));
}
