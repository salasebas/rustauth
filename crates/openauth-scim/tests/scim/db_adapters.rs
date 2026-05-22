use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use openauth_core::db::{Create, DbAdapter, DbValue, FindMany, FindOne, Where, WhereOperator};
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_core::user::{CreateOAuthAccountInput, CreateUserInput, DbUserStore};
use openauth_deadpool_postgres::DeadpoolPostgresAdapter;
use openauth_plugins::organization::organization;
use openauth_scim::store::{CreateScimProviderInput, ScimProviderStore};
use openauth_scim::token::encode_bearer_token;
use openauth_scim::{scim, ScimOptions};
use openauth_sqlx::{MySqlAdapter, PostgresAdapter, SqliteAdapter};
use openauth_tokio_postgres::TokioPostgresAdapter;
use serde_json::Value;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
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

fn scim_options() -> OpenAuthOptions {
    OpenAuthOptions {
        base_url: Some("https://app.example.com".to_owned()),
        secret: Some(SECRET.to_owned()),
        plugins: vec![organization(), scim(ScimOptions::default())],
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    }
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
