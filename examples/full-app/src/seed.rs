use std::collections::HashMap;

use rustauth::db::{
    Create, DbAdapter, DbFieldType, DbRecord, DbSchema, DbTable, DbValue, Delete,
    TransactionCallback, Where,
};
use rustauth::error::RustAuthError;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

use crate::ExampleError;

const SEED_USER_ID: &str = "seed_user_demo";
const SEED_EMAIL: &str = "seed@example.com";
const SEED_ACCOUNT_ID: &str = "seed_account_demo";
const SEED_SESSION_ID: &str = "seed_session_demo";
const SEED_SESSION_TOKEN: &str = "seed_session_token_demo";
const SEED_VERIFICATION_ID: &str = "seed_verification_demo";
const SEED_ORG_ID: &str = "seed_org_demo";
const SEED_MEMBER_ID: &str = "seed_member_demo";
const SEED_TEAM_ID: &str = "seed_team_demo";
const SEED_TEAM_MEMBER_ID: &str = "seed_team_member_demo";
const SEED_INVITATION_ID: &str = "seed_invitation_demo";
const SEED_ORG_ROLE_ID: &str = "seed_org_role_demo";
const SEED_API_KEY_ID: &str = "seed_api_key_demo";
const SEED_TWO_FACTOR_ID: &str = "seed_two_factor_demo";
const SEED_DEVICE_CODE_ID: &str = "seed_device_code_demo";
const SEED_PASSKEY_ID: &str = "seed_passkey_demo";
const SEED_JWKS_ID: &str = "seed_jwks_demo";
const SEED_OAUTH_CLIENT_ROW_ID: &str = "seed_oauth_client_demo";
const SEED_OAUTH_CLIENT_ID: &str = "seed-example-client";
const SEED_OAUTH_REFRESH_ID: &str = "seed_oauth_refresh_demo";
const SEED_OAUTH_ACCESS_ID: &str = "seed_oauth_access_demo";
const SEED_OAUTH_CONSENT_ID: &str = "seed_oauth_consent_demo";
const SEED_SSO_PROVIDER_ID: &str = "seed_sso_provider_demo";
const SEED_SCIM_PROVIDER_ID: &str = "seed_scim_provider_demo";
const SEED_SCIM_USER_PROFILE_ID: &str = "seed_scim_user_profile_demo";
const SEED_SCIM_GROUP_PROFILE_ID: &str = "seed_scim_group_profile_demo";
const SEED_STRIPE_EVENT_ID: &str = "seed_stripe_event_demo";
const SEED_SUBSCRIPTION_ID: &str = "seed_subscription_demo";
const SEED_RATE_LIMIT_KEY: &str = "seed:/sign-in/email";

#[derive(Clone, Debug)]
struct SeedContext {
    now: OffsetDateTime,
    expires: OffsetDateTime,
    password_hash: String,
}

impl SeedContext {
    fn new(password_hash: impl Into<String>) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            now,
            expires: now + Duration::days(30),
            password_hash: password_hash.into(),
        }
    }

    fn id(&self, suffix: &str) -> String {
        format!("seed_{suffix}")
    }
}

#[derive(Debug, Serialize)]
pub struct SeedSummary {
    pub tables_seeded: usize,
    pub rows_inserted: u64,
    pub tables: Vec<SeedTableResult>,
}

#[derive(Debug, Serialize)]
pub struct SeedTableResult {
    pub table: String,
    pub inserted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn seed_database(
    adapter: &dyn DbAdapter,
    schema: &DbSchema,
    password_hash: &str,
) -> Result<SeedSummary, ExampleError> {
    let ctx = SeedContext::new(password_hash);
    let schema = schema.clone();
    let summary = std::sync::Arc::new(tokio::sync::Mutex::new(None));
    let summary_slot = std::sync::Arc::clone(&summary);
    let callback: TransactionCallback<'_> = Box::new(move |tx| {
        let schema = schema.clone();
        let ctx = ctx.clone();
        let summary_slot = std::sync::Arc::clone(&summary_slot);
        Box::pin(async move {
            let seeded = seed_database_tables(&tx, &schema, &ctx).await?;
            *summary_slot.lock().await = Some(seeded);
            Ok(())
        })
    });
    adapter
        .transaction(callback)
        .await
        .map_err(ExampleError::from)?;
    let seeded = summary.lock().await.take();
    seeded.ok_or_else(|| ExampleError::InvalidConfig("seed transaction did not run".to_owned()))
}

async fn seed_database_tables(
    adapter: &dyn DbAdapter,
    schema: &DbSchema,
    ctx: &SeedContext,
) -> Result<SeedSummary, RustAuthError> {
    let mut tables = schema.tables().collect::<Vec<_>>();
    tables.sort_by_key(|(_, table)| table.order.unwrap_or(999));

    let mut summary = SeedSummary {
        tables_seeded: 0,
        rows_inserted: 0,
        tables: Vec::new(),
    };

    for (logical_name, table) in tables {
        let logical_name = logical_name.to_owned();
        let result = match seed_table(adapter, &logical_name, table, ctx).await {
            Ok(inserted) => SeedTableResult {
                table: logical_name.clone(),
                inserted,
                error: None,
            },
            Err(error) => SeedTableResult {
                table: logical_name.clone(),
                inserted: false,
                error: Some(error.to_string()),
            },
        };
        if result.inserted {
            summary.tables_seeded += 1;
            summary.rows_inserted += 1;
        }
        summary.tables.push(result);
    }

    Ok(summary)
}

async fn seed_table(
    adapter: &dyn DbAdapter,
    logical_name: &str,
    table: &DbTable,
    ctx: &SeedContext,
) -> Result<bool, RustAuthError> {
    let record = match logical_name {
        "user" => seed_user(ctx),
        "account" => seed_account(ctx),
        "session" => seed_session(ctx),
        "verification" => seed_verification(ctx),
        "rate_limit" => seed_rate_limit(ctx),
        "organization" => seed_organization(ctx),
        "member" => seed_member(ctx),
        "team" => seed_team(ctx),
        "team_member" => seed_team_member(ctx),
        "invitation" => seed_invitation(ctx),
        "organization_role" => seed_organization_role(ctx),
        "api_key" => seed_api_key(ctx),
        "two_factor" => seed_two_factor(ctx),
        "device_code" => seed_device_code(ctx),
        "passkey" => seed_passkey(ctx),
        "jwks" => seed_jwks(ctx),
        "oauth_client" => seed_oauth_client(ctx),
        "oauth_refresh_token" => seed_oauth_refresh_token(ctx),
        "oauth_access_token" => seed_oauth_access_token(ctx),
        "oauth_consent" => seed_oauth_consent(ctx),
        "sso_provider" => seed_sso_provider(ctx),
        "scim_provider" => seed_scim_provider(ctx),
        "scim_user_profile" => seed_scim_user_profile(ctx),
        "scim_group_profile" => seed_scim_group_profile(ctx),
        "stripe_webhook_event" => seed_stripe_webhook_event(ctx),
        "subscription" => seed_subscription(ctx),
        "wallet_address" => seed_wallet_address(ctx),
        other => generic_seed_record(other, table, ctx),
    };

    let Some(record) = record else {
        return Ok(false);
    };

    let record = fill_missing_table_fields(record, logical_name, table, ctx);
    let record = filter_record_for_table(record, table);

    prepare_seed_row(adapter, logical_name, &record).await?;

    let mut query = Create::new(logical_name);
    if record.contains_key("id") {
        query = query.force_allow_id();
    }
    adapter
        .create(
            record
                .into_iter()
                .fold(query, |query, (field, value)| query.data(field, value)),
        )
        .await?;
    Ok(true)
}

async fn prepare_seed_row(
    adapter: &dyn DbAdapter,
    logical_name: &str,
    record: &DbRecord,
) -> Result<(), RustAuthError> {
    if let Some(DbValue::String(id)) = record.get("id") {
        adapter
            .delete(
                Delete::new(logical_name)
                    .where_clause(Where::new("id", DbValue::String(id.clone()))),
            )
            .await?;
        return Ok(());
    }
    if logical_name == "rate_limit" {
        if let Some(DbValue::String(key)) = record.get("key") {
            adapter
                .delete(
                    Delete::new(logical_name)
                        .where_clause(Where::new("key", DbValue::String(key.clone()))),
                )
                .await?;
        }
        return Ok(());
    }
    if logical_name == "wallet_address" {
        if let Some(DbValue::String(user_id)) = record.get("user_id") {
            adapter
                .delete(
                    Delete::new(logical_name)
                        .where_clause(Where::new("user_id", DbValue::String(user_id.clone()))),
                )
                .await?;
        }
    }
    Ok(())
}

fn seed_user(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(SEED_USER_ID.to_owned()));
    record.insert(
        "name".to_owned(),
        DbValue::String("Seed Demo User".to_owned()),
    );
    record.insert("email".to_owned(), DbValue::String(SEED_EMAIL.to_owned()));
    record.insert("email_verified".to_owned(), DbValue::Boolean(true));
    record.insert("image".to_owned(), DbValue::Null);
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("is_anonymous".to_owned(), DbValue::Boolean(false));
    record.insert("two_factor_enabled".to_owned(), DbValue::Boolean(true));
    record.insert(
        "username".to_owned(),
        DbValue::String("seed_demo".to_owned()),
    );
    record.insert(
        "display_username".to_owned(),
        DbValue::String("Seed Demo".to_owned()),
    );
    Some(record)
}

fn seed_account(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(SEED_ACCOUNT_ID.to_owned()));
    record.insert(
        "provider_id".to_owned(),
        DbValue::String("credential".to_owned()),
    );
    record.insert(
        "account_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert("access_token".to_owned(), DbValue::Null);
    record.insert("refresh_token".to_owned(), DbValue::Null);
    record.insert("id_token".to_owned(), DbValue::Null);
    record.insert("access_token_expires_at".to_owned(), DbValue::Null);
    record.insert("refresh_token_expires_at".to_owned(), DbValue::Null);
    record.insert("scope".to_owned(), DbValue::Null);
    record.insert(
        "password".to_owned(),
        DbValue::String(ctx.password_hash.clone()),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(ctx.now));
    Some(record)
}

fn seed_session(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(SEED_SESSION_ID.to_owned()));
    record.insert("expires_at".to_owned(), DbValue::Timestamp(ctx.expires));
    record.insert(
        "token".to_owned(),
        DbValue::String(SEED_SESSION_TOKEN.to_owned()),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert(
        "ip_address".to_owned(),
        DbValue::String("127.0.0.1".to_owned()),
    );
    record.insert(
        "user_agent".to_owned(),
        DbValue::String("rustauth-example-seed".to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    Some(record)
}

fn seed_verification(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_VERIFICATION_ID.to_owned()),
    );
    record.insert(
        "identifier".to_owned(),
        DbValue::String(SEED_EMAIL.to_owned()),
    );
    record.insert("value".to_owned(), DbValue::String("123456".to_owned()));
    record.insert("expires_at".to_owned(), DbValue::Timestamp(ctx.expires));
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(ctx.now));
    Some(record)
}

fn seed_rate_limit(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "key".to_owned(),
        DbValue::String(SEED_RATE_LIMIT_KEY.to_owned()),
    );
    record.insert("count".to_owned(), DbValue::Number(1));
    record.insert(
        "last_request".to_owned(),
        DbValue::Number(ctx.now.unix_timestamp()),
    );
    Some(record)
}

fn seed_organization(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(SEED_ORG_ID.to_owned()));
    record.insert(
        "name".to_owned(),
        DbValue::String("Seed Organization".to_owned()),
    );
    record.insert("slug".to_owned(), DbValue::String("seed-org".to_owned()));
    record.insert("logo".to_owned(), DbValue::Null);
    record.insert(
        "metadata".to_owned(),
        DbValue::Json(serde_json::json!({ "seed": true })),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(ctx.now));
    Some(record)
}

fn seed_member(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(SEED_MEMBER_ID.to_owned()));
    record.insert(
        "organization_id".to_owned(),
        DbValue::String(SEED_ORG_ID.to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert("role".to_owned(), DbValue::String("owner".to_owned()));
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    Some(record)
}

fn seed_team(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(SEED_TEAM_ID.to_owned()));
    record.insert("name".to_owned(), DbValue::String("Seed Team".to_owned()));
    record.insert(
        "organization_id".to_owned(),
        DbValue::String(SEED_ORG_ID.to_owned()),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(ctx.now));
    Some(record)
}

fn seed_team_member(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_TEAM_MEMBER_ID.to_owned()),
    );
    record.insert(
        "team_id".to_owned(),
        DbValue::String(SEED_TEAM_ID.to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    Some(record)
}

fn seed_invitation(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_INVITATION_ID.to_owned()),
    );
    record.insert(
        "organization_id".to_owned(),
        DbValue::String(SEED_ORG_ID.to_owned()),
    );
    record.insert(
        "email".to_owned(),
        DbValue::String("invite@example.com".to_owned()),
    );
    record.insert("role".to_owned(), DbValue::String("member".to_owned()));
    record.insert("status".to_owned(), DbValue::String("pending".to_owned()));
    record.insert("expires_at".to_owned(), DbValue::Timestamp(ctx.expires));
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert(
        "inviter_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert(
        "team_id".to_owned(),
        DbValue::String(SEED_TEAM_ID.to_owned()),
    );
    Some(record)
}

fn seed_organization_role(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_ORG_ROLE_ID.to_owned()),
    );
    record.insert(
        "organization_id".to_owned(),
        DbValue::String(SEED_ORG_ID.to_owned()),
    );
    record.insert("role".to_owned(), DbValue::String("admin".to_owned()));
    record.insert(
        "permission".to_owned(),
        DbValue::Json(serde_json::json!({ "project": ["create", "read"] })),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(ctx.now));
    Some(record)
}

fn seed_api_key(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(SEED_API_KEY_ID.to_owned()));
    record.insert(
        "config_id".to_owned(),
        DbValue::String("default".to_owned()),
    );
    record.insert(
        "name".to_owned(),
        DbValue::String("Seed API key".to_owned()),
    );
    record.insert("start".to_owned(), DbValue::String("seed".to_owned()));
    record.insert("prefix".to_owned(), DbValue::String("seed".to_owned()));
    record.insert(
        "key".to_owned(),
        DbValue::String("seed_api_key_value".to_owned()),
    );
    record.insert(
        "reference_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert("enabled".to_owned(), DbValue::Boolean(true));
    record.insert("rate_limit_enabled".to_owned(), DbValue::Boolean(false));
    record.insert("request_count".to_owned(), DbValue::Number(0));
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(ctx.now));
    Some(record)
}

fn seed_two_factor(_ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_TWO_FACTOR_ID.to_owned()),
    );
    record.insert(
        "secret".to_owned(),
        DbValue::String("SEED2FASECRET".to_owned()),
    );
    record.insert(
        "backup_codes".to_owned(),
        DbValue::String("111111,222222".to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert("verified".to_owned(), DbValue::Boolean(true));
    Some(record)
}

fn seed_device_code(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_DEVICE_CODE_ID.to_owned()),
    );
    record.insert(
        "device_code".to_owned(),
        DbValue::String("seed-device-code".to_owned()),
    );
    record.insert(
        "user_code".to_owned(),
        DbValue::String("SEED-USER".to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert("expires_at".to_owned(), DbValue::Timestamp(ctx.expires));
    record.insert("status".to_owned(), DbValue::String("pending".to_owned()));
    record.insert("polling_interval".to_owned(), DbValue::Number(5));
    record.insert(
        "client_id".to_owned(),
        DbValue::String(SEED_OAUTH_CLIENT_ID.to_owned()),
    );
    record.insert("scope".to_owned(), DbValue::String("openid".to_owned()));
    Some(record)
}

fn seed_passkey(_ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(SEED_PASSKEY_ID.to_owned()));
    record.insert(
        "name".to_owned(),
        DbValue::String("Seed Passkey".to_owned()),
    );
    record.insert(
        "public_key".to_owned(),
        DbValue::String("seed-public-key".to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert(
        "credential_id".to_owned(),
        DbValue::String("seed-credential-id".to_owned()),
    );
    record.insert("counter".to_owned(), DbValue::Number(0));
    record.insert(
        "device_type".to_owned(),
        DbValue::String("singleDevice".to_owned()),
    );
    record.insert("backed_up".to_owned(), DbValue::Boolean(false));
    record.insert(
        "transports".to_owned(),
        DbValue::String("internal".to_owned()),
    );
    record.insert(
        "webauthn_credential".to_owned(),
        DbValue::Json(serde_json::json!({ "seed": true })),
    );
    Some(record)
}

fn seed_jwks(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(SEED_JWKS_ID.to_owned()));
    record.insert(
        "public_key".to_owned(),
        DbValue::String("seed-public-jwk".to_owned()),
    );
    record.insert(
        "private_key".to_owned(),
        DbValue::String("seed-private-jwk".to_owned()),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("alg".to_owned(), DbValue::String("EdDSA".to_owned()));
    Some(record)
}

fn seed_oauth_client(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_OAUTH_CLIENT_ROW_ID.to_owned()),
    );
    record.insert(
        "client_id".to_owned(),
        DbValue::String(SEED_OAUTH_CLIENT_ID.to_owned()),
    );
    record.insert(
        "client_secret".to_owned(),
        DbValue::String("seed-client-secret".to_owned()),
    );
    record.insert("disabled".to_owned(), DbValue::Boolean(false));
    record.insert("skip_consent".to_owned(), DbValue::Boolean(true));
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("updated_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert(
        "name".to_owned(),
        DbValue::String("Seed OAuth client".to_owned()),
    );
    record.insert(
        "redirect_uris".to_owned(),
        DbValue::StringArray(vec!["http://127.0.0.1:3000/".to_owned()]),
    );
    record.insert("public".to_owned(), DbValue::Boolean(true));
    Some(record)
}

fn seed_oauth_refresh_token(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_OAUTH_REFRESH_ID.to_owned()),
    );
    record.insert(
        "token".to_owned(),
        DbValue::String("seed-refresh-token".to_owned()),
    );
    record.insert(
        "client_id".to_owned(),
        DbValue::String(SEED_OAUTH_CLIENT_ID.to_owned()),
    );
    record.insert(
        "session_id".to_owned(),
        DbValue::String(SEED_SESSION_ID.to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert("expires_at".to_owned(), DbValue::Timestamp(ctx.expires));
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert(
        "scopes".to_owned(),
        DbValue::StringArray(vec!["openid".to_owned(), "profile".to_owned()]),
    );
    Some(record)
}

fn seed_oauth_access_token(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_OAUTH_ACCESS_ID.to_owned()),
    );
    record.insert(
        "token".to_owned(),
        DbValue::String("seed-access-token".to_owned()),
    );
    record.insert(
        "client_id".to_owned(),
        DbValue::String(SEED_OAUTH_CLIENT_ID.to_owned()),
    );
    record.insert(
        "session_id".to_owned(),
        DbValue::String(SEED_SESSION_ID.to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert(
        "refresh_id".to_owned(),
        DbValue::String(SEED_OAUTH_REFRESH_ID.to_owned()),
    );
    record.insert("expires_at".to_owned(), DbValue::Timestamp(ctx.expires));
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert(
        "scopes".to_owned(),
        DbValue::StringArray(vec!["openid".to_owned()]),
    );
    Some(record)
}

fn seed_oauth_consent(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_OAUTH_CONSENT_ID.to_owned()),
    );
    record.insert(
        "client_id".to_owned(),
        DbValue::String(SEED_OAUTH_CLIENT_ID.to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert(
        "scopes".to_owned(),
        DbValue::StringArray(vec!["openid".to_owned(), "profile".to_owned()]),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    Some(record)
}

fn seed_sso_provider(_ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_SSO_PROVIDER_ID.to_owned()),
    );
    record.insert(
        "issuer".to_owned(),
        DbValue::String("https://seed.example.com".to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert(
        "provider_id".to_owned(),
        DbValue::String("seed-sso".to_owned()),
    );
    record.insert(
        "organization_id".to_owned(),
        DbValue::String(SEED_ORG_ID.to_owned()),
    );
    record.insert(
        "domain".to_owned(),
        DbValue::String("seed.example.com".to_owned()),
    );
    Some(record)
}

fn seed_scim_provider(_ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_SCIM_PROVIDER_ID.to_owned()),
    );
    record.insert(
        "provider_id".to_owned(),
        DbValue::String("seed-scim".to_owned()),
    );
    record.insert(
        "scim_token".to_owned(),
        DbValue::String("seed-scim-token".to_owned()),
    );
    record.insert(
        "organization_id".to_owned(),
        DbValue::String(SEED_ORG_ID.to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    Some(record)
}

fn seed_scim_user_profile(_ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_SCIM_USER_PROFILE_ID.to_owned()),
    );
    record.insert(
        "provider_id".to_owned(),
        DbValue::String("seed-scim".to_owned()),
    );
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert(
        "external_id".to_owned(),
        DbValue::String("seed-external-user".to_owned()),
    );
    record.insert(
        "attributes".to_owned(),
        DbValue::Json(serde_json::json!({ "userName": "seed@example.com" })),
    );
    record.insert("version".to_owned(), DbValue::String("1".to_owned()));
    Some(record)
}

fn seed_scim_group_profile(_ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_SCIM_GROUP_PROFILE_ID.to_owned()),
    );
    record.insert(
        "provider_id".to_owned(),
        DbValue::String("seed-scim".to_owned()),
    );
    record.insert(
        "organization_id".to_owned(),
        DbValue::String(SEED_ORG_ID.to_owned()),
    );
    record.insert(
        "team_id".to_owned(),
        DbValue::String(SEED_TEAM_ID.to_owned()),
    );
    record.insert(
        "external_id".to_owned(),
        DbValue::String("seed-external-group".to_owned()),
    );
    record.insert(
        "attributes".to_owned(),
        DbValue::Json(serde_json::json!({ "members": [SEED_USER_ID] })),
    );
    record.insert("version".to_owned(), DbValue::String("1".to_owned()));
    Some(record)
}

fn seed_stripe_webhook_event(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_STRIPE_EVENT_ID.to_owned()),
    );
    record.insert(
        "event_type".to_owned(),
        DbValue::String("customer.subscription.created".to_owned()),
    );
    record.insert("created_at".to_owned(), DbValue::Timestamp(ctx.now));
    Some(record)
}

fn seed_subscription(ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "id".to_owned(),
        DbValue::String(SEED_SUBSCRIPTION_ID.to_owned()),
    );
    record.insert("plan".to_owned(), DbValue::String("seed-plan".to_owned()));
    record.insert(
        "reference_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert(
        "stripe_customer_id".to_owned(),
        DbValue::String("cus_seed".to_owned()),
    );
    record.insert(
        "stripe_subscription_id".to_owned(),
        DbValue::String("sub_seed".to_owned()),
    );
    record.insert("status".to_owned(), DbValue::String("active".to_owned()));
    record.insert("period_start".to_owned(), DbValue::Timestamp(ctx.now));
    record.insert("period_end".to_owned(), DbValue::Timestamp(ctx.expires));
    Some(record)
}

fn seed_wallet_address(_ctx: &SeedContext) -> Option<DbRecord> {
    let mut record = DbRecord::new();
    record.insert(
        "user_id".to_owned(),
        DbValue::String(SEED_USER_ID.to_owned()),
    );
    record.insert(
        "address".to_owned(),
        DbValue::String("0x000000000000000000000000000000000000seed".to_owned()),
    );
    record.insert("chain_id".to_owned(), DbValue::Number(1));
    record.insert("is_primary".to_owned(), DbValue::Boolean(true));
    Some(record)
}

fn filter_record_for_table(record: DbRecord, table: &DbTable) -> DbRecord {
    record
        .into_iter()
        .filter(|(field, _)| table.fields.contains_key(field))
        .collect()
}

fn seed_reference_ids() -> HashMap<String, String> {
    let mut references = HashMap::new();
    references.insert("user_id".to_owned(), SEED_USER_ID.to_owned());
    references.insert("organization_id".to_owned(), SEED_ORG_ID.to_owned());
    references.insert("team_id".to_owned(), SEED_TEAM_ID.to_owned());
    references.insert("session_id".to_owned(), SEED_SESSION_ID.to_owned());
    references.insert("inviter_id".to_owned(), SEED_USER_ID.to_owned());
    references.insert("client_id".to_owned(), SEED_OAUTH_CLIENT_ID.to_owned());
    references.insert("provider_id".to_owned(), "seed-scim".to_owned());
    references.insert("reference_id".to_owned(), SEED_USER_ID.to_owned());
    references
}

fn default_seed_value(
    field_name: &str,
    field: &rustauth::db::DbField,
    logical_name: &str,
    ctx: &SeedContext,
    references: &HashMap<String, String>,
) -> DbValue {
    match field.field_type {
        DbFieldType::String => {
            if field_name == "id" {
                DbValue::String(ctx.id(logical_name))
            } else if let Some(reference) = references.get(field_name) {
                DbValue::String(reference.clone())
            } else if field_name.ends_with("_id") {
                DbValue::String(ctx.id(field_name))
            } else {
                DbValue::String(format!("seed-{logical_name}-{field_name}"))
            }
        }
        DbFieldType::Number => DbValue::Number(1),
        DbFieldType::Boolean => DbValue::Boolean(false),
        DbFieldType::Timestamp => DbValue::Timestamp(ctx.now),
        DbFieldType::Json => DbValue::Json(serde_json::json!({ "seed": logical_name })),
        DbFieldType::StringArray => DbValue::StringArray(vec![format!("seed-{logical_name}")]),
        DbFieldType::NumberArray => DbValue::NumberArray(vec![1]),
    }
}

fn fill_missing_table_fields(
    mut record: DbRecord,
    logical_name: &str,
    table: &DbTable,
    ctx: &SeedContext,
) -> DbRecord {
    let references = seed_reference_ids();
    for (field_name, field) in &table.fields {
        if record.contains_key(field_name) || !field.required {
            continue;
        }
        record.insert(
            field_name.clone(),
            default_seed_value(field_name, field, logical_name, ctx, &references),
        );
    }
    record
}

fn generic_seed_record(logical_name: &str, table: &DbTable, ctx: &SeedContext) -> Option<DbRecord> {
    let references = seed_reference_ids();
    let mut record = DbRecord::new();

    for (field_name, field) in &table.fields {
        if !field.input {
            continue;
        }
        record.insert(
            field_name.clone(),
            default_seed_value(field_name, field, logical_name, ctx, &references),
        );
    }

    if record.is_empty() {
        None
    } else {
        Some(record)
    }
}

pub fn seed_password_hash() -> Result<String, ExampleError> {
    #[cfg(debug_assertions)]
    {
        rustauth_core::test_utils::fast_hash_password("password123456").map_err(ExampleError::from)
    }
    #[cfg(not(debug_assertions))]
    {
        rustauth::crypto::password::hash_password("password123456").map_err(ExampleError::from)
    }
}
