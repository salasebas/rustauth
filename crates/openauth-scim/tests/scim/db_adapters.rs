use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use openauth_core::cookies::{set_session_cookie, SessionCookieOptions};
use openauth_core::db::{Create, DbAdapter, DbValue, FindMany, FindOne, Where, WhereOperator};
use openauth_core::options::{AdvancedOptions, OpenAuthOptions, RateLimitOptions};
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::{CreateOAuthAccountInput, CreateUserInput, DbUserStore};
use openauth_deadpool_postgres::DeadpoolPostgresAdapter;
use openauth_plugins::organization::organization;
use openauth_scim::store::{CreateScimProviderInput, ScimProviderStore};
use openauth_scim::token::encode_bearer_token;
use openauth_scim::{scim, ScimBulkMode, ScimOptions, ScimTokenStorage};
use openauth_sqlx::{MySqlAdapter, PostgresAdapter, SqliteAdapter};
use openauth_tokio_postgres::TokioPostgresAdapter;
use serde_json::Value;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

const SECRET: &str = "secret-a-at-least-32-chars-long!!";
static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);
static POSTGRES_ADAPTER_TEST_LOCK: Mutex<()> = Mutex::const_new(());

#[tokio::test]
async fn sqlite_schema_and_provider_store_work() -> Result<(), Box<dyn std::error::Error>> {
    let context = scim_context()?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let adapter = Arc::new(SqliteAdapter::with_schema(
        pool.clone(),
        context.db_schema.clone(),
    ));

    adapter.create_schema(&context.db_schema, None).await?;

    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'scim_providers'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(table_count, 1);

    let columns =
        sqlx::query_scalar::<_, String>("SELECT name FROM pragma_table_info('scim_providers')")
            .fetch_all(&pool)
            .await?;
    assert!(columns.iter().any(|column| column == "provider_id"));
    assert!(columns.iter().any(|column| column == "scim_token"));
    assert!(columns.iter().any(|column| column == "organization_id"));
    assert!(columns
        .iter()
        .all(|column| !column.contains(char::is_uppercase)));

    provider_store_contract(adapter.clone()).await?;
    Ok(())
}

#[tokio::test]
async fn sqlite_run_migrations_adds_scim_tables_to_existing_core_schema(
) -> Result<(), Box<dyn std::error::Error>> {
    let base_context = create_auth_context(base_options())?;
    let scim_context = create_auth_context(scim_only_options())?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let adapter = Arc::new(SqliteAdapter::with_schema(
        pool.clone(),
        scim_context.db_schema.clone(),
    ));

    adapter.run_migrations(&base_context.db_schema).await?;
    assert!(!sqlite_table_exists(&pool, "scim_providers").await?);

    adapter.run_migrations(&scim_context.db_schema).await?;
    assert!(sqlite_table_exists(&pool, "scim_providers").await?);
    assert!(sqlite_table_exists(&pool, "scim_user_profiles").await?);
    assert!(sqlite_table_exists(&pool, "scim_group_profiles").await?);
    assert_scim_tables_queryable(adapter.as_ref()).await?;
    Ok(())
}

#[tokio::test]
async fn sqlite_management_routes_do_not_touch_organization_tables_without_plugin(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(scim_only_options())?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let adapter = Arc::new(SqliteAdapter::with_schema(pool, context.db_schema.clone()));
    adapter.run_migrations(&context.db_schema).await?;
    let router_adapter: Arc<dyn DbAdapter> = adapter.clone();
    let context = create_auth_context_with_adapter(scim_only_options(), router_adapter.clone())?;
    let router = AuthRouter::with_async_endpoints(
        context.clone(),
        Vec::new(),
        core_auth_async_endpoints(router_adapter),
    )?;
    let cookie = session_cookie(
        adapter.as_ref(),
        &context,
        "manual-org-provider@example.com",
    )
    .await?;
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "manual_org".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: Some("org_missing_plugin".to_owned()),
            user_id: None,
        })
        .await?;

    let listed = router
        .handle_async(session_request(
            Method::GET,
            "/scim/list-provider-connections",
            &cookie,
        )?)
        .await?;
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(
        json_body(listed)?["providers"]
            .as_array()
            .expect("providers")
            .len(),
        0
    );

    let fetched = router
        .handle_async(session_request(
            Method::GET,
            "/scim/get-provider-connection?providerId=manual_org",
            &cookie,
        )?)
        .await?;
    assert_eq!(fetched.status(), StatusCode::FORBIDDEN);

    let deleted = router
        .handle_async(session_json_request(
            Method::POST,
            "/scim/delete-provider-connection",
            r#"{"providerId":"manual_org"}"#,
            &cookie,
        )?)
        .await?;
    assert_eq!(deleted.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn sqlite_atomic_bulk_rolls_back_when_a_later_operation_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = OpenAuthOptions {
        base_url: Some("https://app.example.com".to_owned()),
        secret: Some(SECRET.to_owned()),
        plugins: vec![scim(ScimOptions {
            bulk_mode: ScimBulkMode::Atomic,
            token_storage: ScimTokenStorage::Plain,
            ..ScimOptions::default()
        })],
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        rate_limit: test_rate_limit_options(),
        ..OpenAuthOptions::default()
    };
    let context = create_auth_context(options.clone())?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let adapter = Arc::new(SqliteAdapter::with_schema(
        pool.clone(),
        context.db_schema.clone(),
    ));
    adapter.run_migrations(&context.db_schema).await?;
    let router_adapter: Arc<dyn DbAdapter> = adapter.clone();
    let context = create_auth_context_with_adapter(options, router_adapter.clone())?;
    let router = AuthRouter::with_async_endpoints(
        context.clone(),
        Vec::new(),
        core_auth_async_endpoints(router_adapter),
    )?;
    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: "okta".to_owned(),
            scim_token: "base-token".to_owned(),
            organization_id: None,
            user_id: None,
        })
        .await?;
    let token = encode_bearer_token("base-token", "okta", None);

    let request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Bulk")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/scim+json")
        .body(
            br#"{
                "schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                "Operations":[
                    {
                        "method":"POST",
                        "path":"/Users",
                        "bulkId":"user-a",
                        "data":{"userName":"sqlite-atomic@example.com"}
                    },
                    {"method":"DELETE","path":"/Users/missing-user-id"}
                ]
            }"#
            .to_vec(),
        )?;
    let response = router.handle_async(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["Operations"][0]["status"]["code"], 412);
    assert_eq!(body["Operations"][1]["status"]["code"], 404);

    let users = adapter
        .find_many(FindMany::new("user").select(["id"]))
        .await?;
    assert!(users.is_empty());
    Ok(())
}

#[tokio::test]
async fn postgres_schema_and_provider_store_work_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("OPENAUTH_TEST_POSTGRES_URL").ok() else {
        return Ok(());
    };
    let context = scim_context()?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    let adapter = Arc::new(PostgresAdapter::with_schema(
        pool,
        context.db_schema.clone(),
    ));

    let _guard = POSTGRES_ADAPTER_TEST_LOCK.lock().await;
    adapter.create_schema(&context.db_schema, None).await?;
    provider_store_contract(adapter.clone()).await?;
    Ok(())
}

#[tokio::test]
async fn postgres_run_migrations_adds_scim_tables_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("OPENAUTH_TEST_POSTGRES_URL").ok() else {
        return Ok(());
    };
    let base_context = create_auth_context(base_options())?;
    let scim_context = create_auth_context(scim_only_options())?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    let adapter = Arc::new(PostgresAdapter::with_schema(
        pool.clone(),
        scim_context.db_schema.clone(),
    ));

    let _guard = POSTGRES_ADAPTER_TEST_LOCK.lock().await;
    adapter.run_migrations(&base_context.db_schema).await?;
    adapter.run_migrations(&scim_context.db_schema).await?;
    assert!(postgres_table_exists(&pool, "scim_providers").await?);
    assert!(postgres_table_exists(&pool, "scim_user_profiles").await?);
    assert!(postgres_table_exists(&pool, "scim_group_profiles").await?);
    assert_scim_tables_queryable(adapter.as_ref()).await?;
    Ok(())
}

#[tokio::test]
async fn mysql_schema_and_provider_store_work_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("OPENAUTH_TEST_MYSQL_URL").ok() else {
        return Ok(());
    };
    let context = scim_context()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    let adapter = Arc::new(MySqlAdapter::with_schema(pool, context.db_schema.clone()));

    adapter.create_schema(&context.db_schema, None).await?;
    provider_store_contract(adapter.clone()).await?;
    Ok(())
}

#[tokio::test]
async fn mysql_run_migrations_adds_scim_tables_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("OPENAUTH_TEST_MYSQL_URL").ok() else {
        return Ok(());
    };
    let base_context = create_auth_context(base_options())?;
    let scim_context = create_auth_context(scim_only_options())?;
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    let adapter = Arc::new(MySqlAdapter::with_schema(
        pool.clone(),
        scim_context.db_schema.clone(),
    ));

    adapter.run_migrations(&base_context.db_schema).await?;
    adapter.run_migrations(&scim_context.db_schema).await?;
    assert!(mysql_table_exists(&pool, "scim_providers").await?);
    assert!(mysql_table_exists(&pool, "scim_user_profiles").await?);
    assert!(mysql_table_exists(&pool, "scim_group_profiles").await?);
    assert_scim_tables_queryable(adapter.as_ref()).await?;
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_run_migrations_adds_scim_tables_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("OPENAUTH_TEST_POSTGRES_URL").ok() else {
        return Ok(());
    };
    let base_context = create_auth_context(base_options())?;
    let scim_context = create_auth_context(scim_only_options())?;
    let adapter = Arc::new(
        DeadpoolPostgresAdapter::connect_with_schema(&database_url, scim_context.db_schema.clone())
            .await?,
    );

    let _guard = POSTGRES_ADAPTER_TEST_LOCK.lock().await;
    adapter.run_migrations(&base_context.db_schema).await?;
    adapter.run_migrations(&scim_context.db_schema).await?;
    assert_scim_tables_queryable(adapter.as_ref()).await?;
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_run_migrations_adds_scim_tables_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("OPENAUTH_TEST_POSTGRES_URL").ok() else {
        return Ok(());
    };
    let base_context = create_auth_context(base_options())?;
    let scim_context = create_auth_context(scim_only_options())?;
    let adapter = Arc::new(
        TokioPostgresAdapter::connect_with_schema(&database_url, scim_context.db_schema.clone())
            .await?,
    );

    let _guard = POSTGRES_ADAPTER_TEST_LOCK.lock().await;
    adapter.run_migrations(&base_context.db_schema).await?;
    adapter.run_migrations(&scim_context.db_schema).await?;
    assert_scim_tables_queryable(adapter.as_ref()).await?;
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_schema_and_provider_store_work_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("OPENAUTH_TEST_POSTGRES_URL").ok() else {
        return Ok(());
    };
    let context = scim_context()?;
    let adapter = Arc::new(
        DeadpoolPostgresAdapter::connect_with_schema(&database_url, context.db_schema.clone())
            .await?,
    );

    let _guard = POSTGRES_ADAPTER_TEST_LOCK.lock().await;
    adapter.create_schema(&context.db_schema, None).await?;
    provider_store_contract(adapter.clone()).await?;
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_schema_and_provider_store_work_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("OPENAUTH_TEST_POSTGRES_URL").ok() else {
        return Ok(());
    };
    let context = scim_context()?;
    let adapter = Arc::new(
        TokioPostgresAdapter::connect_with_schema(&database_url, context.db_schema.clone()).await?,
    );

    let _guard = POSTGRES_ADAPTER_TEST_LOCK.lock().await;
    adapter.create_schema(&context.db_schema, None).await?;
    provider_store_contract(adapter.clone()).await?;
    Ok(())
}

fn scim_context() -> Result<openauth_core::context::AuthContext, openauth_core::error::OpenAuthError>
{
    create_auth_context(scim_options())
}

fn scim_context_with_adapter(
    adapter: Arc<dyn DbAdapter>,
) -> Result<openauth_core::context::AuthContext, openauth_core::error::OpenAuthError> {
    create_auth_context_with_adapter(scim_options(), adapter)
}

fn test_rate_limit_options() -> RateLimitOptions {
    RateLimitOptions {
        enabled: Some(false),
        ..RateLimitOptions::default()
    }
}

fn scim_options() -> OpenAuthOptions {
    OpenAuthOptions {
        base_url: Some("https://app.example.com".to_owned()),
        secret: Some(SECRET.to_owned()),
        plugins: vec![
            organization(),
            scim(crate::scim_options_for_manual_provider_tokens()),
        ],
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        rate_limit: test_rate_limit_options(),
        ..OpenAuthOptions::default()
    }
}

fn scim_only_options() -> OpenAuthOptions {
    OpenAuthOptions {
        base_url: Some("https://app.example.com".to_owned()),
        secret: Some(SECRET.to_owned()),
        plugins: vec![scim(crate::scim_options_for_manual_provider_tokens())],
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        rate_limit: test_rate_limit_options(),
        ..OpenAuthOptions::default()
    }
}

fn base_options() -> OpenAuthOptions {
    OpenAuthOptions {
        base_url: Some("https://app.example.com".to_owned()),
        secret: Some(SECRET.to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        rate_limit: test_rate_limit_options(),
        ..OpenAuthOptions::default()
    }
}

async fn sqlite_table_exists(pool: &sqlx::SqlitePool, table: &str) -> Result<bool, sqlx::Error> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(table)
            .fetch_one(pool)
            .await?;
    Ok(count == 1)
}

async fn postgres_table_exists(pool: &sqlx::PgPool, table: &str) -> Result<bool, sqlx::Error> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = $1
        )",
    )
    .bind(table)
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

async fn mysql_table_exists(pool: &sqlx::MySqlPool, table: &str) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables
         WHERE table_schema = DATABASE() AND table_name = ?",
    )
    .bind(table)
    .fetch_one(pool)
    .await?;
    Ok(count == 1)
}

async fn assert_scim_tables_queryable(
    adapter: &dyn DbAdapter,
) -> Result<(), Box<dyn std::error::Error>> {
    adapter
        .find_many(FindMany::new("scimProvider").select(["id"]))
        .await?;
    adapter
        .find_many(FindMany::new("scimUserProfile").select(["id"]))
        .await?;
    adapter
        .find_many(FindMany::new("scimGroupProfile").select(["id"]))
        .await?;
    Ok(())
}

async fn provider_store_contract<A>(adapter: Arc<A>) -> Result<(), Box<dyn std::error::Error>>
where
    A: DbAdapter + 'static,
{
    let store = ScimProviderStore::new(adapter.as_ref());
    let provider_id = unique_provider_id();
    let created = store
        .create(CreateScimProviderInput {
            provider_id: provider_id.clone(),
            scim_token: format!("token-{provider_id}"),
            organization_id: Some(format!("org-{provider_id}")),
            user_id: None,
        })
        .await?;

    let found = store
        .find_by_provider_id(&provider_id)
        .await?
        .ok_or("provider should exist")?;
    assert_eq!(found.id, created.id);
    assert_eq!(found.organization_id, created.organization_id);
    let provider_record = adapter
        .find_one(
            FindOne::new("scimProvider")
                .where_clause(Where::new(
                    "providerId",
                    DbValue::String(provider_id.clone()),
                ))
                .select(["id", "providerId", "scimToken", "organizationId"]),
        )
        .await?
        .ok_or("provider row should exist")?;
    assert!(matches!(
        provider_record.get("scimToken"),
        Some(DbValue::String(token)) if token == &format!("token-{provider_id}")
    ));

    assert!(
        store
            .create(CreateScimProviderInput {
                provider_id: provider_id.clone(),
                scim_token: format!("token-duplicate-{provider_id}"),
                organization_id: None,
                user_id: None,
            })
            .await
            .is_err(),
        "duplicate provider IDs must be rejected by the database"
    );

    let second_provider_id = format!("{provider_id}_second");
    store
        .create(CreateScimProviderInput {
            provider_id: second_provider_id.clone(),
            scim_token: format!("token-{second_provider_id}"),
            organization_id: Some(format!("org-{second_provider_id}")),
            user_id: None,
        })
        .await?;
    let in_results = adapter
        .find_many(
            FindMany::new("scimProvider").where_clause(
                Where::new(
                    "providerId",
                    DbValue::StringArray(vec![provider_id.clone(), second_provider_id.clone()]),
                )
                .operator(WhereOperator::In),
            ),
        )
        .await?;
    assert_eq!(in_results.len(), 2);

    let rollback_provider_id = format!("{provider_id}_rollback");
    let rollback_result = adapter
        .transaction(Box::new({
            let rollback_provider_id = rollback_provider_id.clone();
            move |transaction| {
                Box::pin(async move {
                    ScimProviderStore::new(transaction.as_ref())
                        .create(CreateScimProviderInput {
                            provider_id: rollback_provider_id,
                            scim_token: "token-rollback".to_owned(),
                            organization_id: None,
                            user_id: None,
                        })
                        .await?;
                    Err(openauth_core::error::OpenAuthError::Adapter(
                        "rollback requested".to_owned(),
                    ))
                })
            }
        }))
        .await;
    assert!(rollback_result.is_err());
    assert!(store
        .find_by_provider_id(&rollback_provider_id)
        .await?
        .is_none());

    store.delete(&provider_id).await?;
    assert!(store.find_by_provider_id(&provider_id).await?.is_none());
    store.delete(&second_provider_id).await?;
    assert!(store
        .find_by_provider_id(&second_provider_id)
        .await?
        .is_none());
    user_and_member_timestamps_contract(adapter.as_ref(), &provider_id).await?;
    org_member_filtering_route_contract(adapter).await?;
    Ok(())
}

async fn user_and_member_timestamps_contract(
    adapter: &dyn DbAdapter,
    provider_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let users = DbUserStore::new(adapter);
    let user = users
        .create_user(
            CreateUserInput::new(
                "Timestamp User",
                format!("{provider_id}-timestamps@example.com"),
            )
            .email_verified(true),
        )
        .await?;
    assert!(user.updated_at >= user.created_at);

    let account = users
        .link_account(CreateOAuthAccountInput {
            id: None,
            provider_id: provider_id.to_owned(),
            account_id: format!("{provider_id}-timestamps-account"),
            user_id: user.id.clone(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
        })
        .await?;
    assert!(account.updated_at >= account.created_at);

    let organization_id = format!("{provider_id}_timestamps_org");
    seed_organization(adapter, &organization_id).await?;
    seed_member(adapter, &organization_id, &user.id, "member").await?;

    let member = adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id),
                ))
                .where_clause(Where::new("user_id", DbValue::String(user.id)))
                .select(["id", "created_at"]),
        )
        .await?
        .ok_or("member row should exist")?;
    assert!(matches!(
        member.get("created_at"),
        Some(DbValue::Timestamp(created_at)) if *created_at <= OffsetDateTime::now_utc()
    ));
    Ok(())
}

async fn org_member_filtering_route_contract<A>(
    adapter: Arc<A>,
) -> Result<(), Box<dyn std::error::Error>>
where
    A: DbAdapter + 'static,
{
    let adapter_for_context: Arc<dyn DbAdapter> = adapter.clone();
    let context = scim_context_with_adapter(adapter_for_context.clone())?;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter_for_context),
    )?;

    let provider_id = unique_provider_id();
    let organization_id = format!("{provider_id}_org_filter");
    let token = format!("token-{provider_id}");
    let bearer_token = encode_bearer_token(&token, &provider_id, Some(&organization_id));

    ScimProviderStore::new(adapter.as_ref())
        .create(CreateScimProviderInput {
            provider_id: provider_id.clone(),
            scim_token: token,
            organization_id: Some(organization_id.clone()),
            user_id: None,
        })
        .await?;
    seed_organization(adapter.as_ref(), &organization_id).await?;

    let users = DbUserStore::new(adapter.as_ref());
    let included = users
        .create_user(
            CreateUserInput::new(
                "Included User",
                format!("{provider_id}-included@example.com"),
            )
            .email_verified(true),
        )
        .await?;
    let excluded = users
        .create_user(
            CreateUserInput::new(
                "Excluded User",
                format!("{provider_id}-excluded@example.com"),
            )
            .email_verified(true),
        )
        .await?;
    for user in [&included, &excluded] {
        users
            .link_account(CreateOAuthAccountInput {
                id: None,
                provider_id: provider_id.clone(),
                account_id: user.email.clone(),
                user_id: user.id.clone(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
            })
            .await?;
    }
    seed_member(adapter.as_ref(), &organization_id, &included.id, "member").await?;

    let response = router
        .handle_async(auth_request(Method::GET, "/scim/v2/Users", &bearer_token)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response)?;
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["id"], included.id);
    Ok(())
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

fn auth_request(method: Method, path: &str, token: &str) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Vec::new())
}

fn session_request(
    method: Method,
    path: &str,
    cookie: &str,
) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie)
        .body(Vec::new())
}

fn session_json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: &str,
) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .body(body.as_bytes().to_vec())
}

async fn session_cookie(
    adapter: &dyn DbAdapter,
    context: &openauth_core::context::AuthContext,
    email: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let user = DbUserStore::new(adapter)
        .create_user(CreateUserInput::new("Session User", email).email_verified(true))
        .await?;
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
    Ok(cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; "))
}

fn json_body(response: http::Response<Vec<u8>>) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(response.body())
}

fn unique_provider_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("scim_{millis}_{counter}")
}
