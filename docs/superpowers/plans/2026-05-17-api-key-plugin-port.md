# API Key Plugin Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the server-only Better Auth API key plugin port as `openauth_plugins::api_key`, preserving observable upstream behavior while keeping Rust APIs, schema names, storage contracts, and tests idiomatic.

**Architecture:** The plugin lives inside `crates/openauth-plugins/src/api_key` and is split by responsibility: options, models, schema, storage, hashing, permissions, rate limiting, organization authorization, cleanup, and route files. Cross-plugin capabilities that are not API-key specific live in `openauth-core`, including secondary storage and background task runner hooks. HTTP JSON stays Better Auth-compatible with camelCase, while Rust fields and database physical names stay snake_case.

**Tech Stack:** Rust workspace crates, `openauth-core` plugin/router/db contracts, `openauth-plugins`, `serde`, `serde_json`, `sha2`, `base64`, `time`, `tokio` tests, in-memory adapter tests, and existing OpenAPI helpers.

---

## File Structure

- `crates/openauth-core/src/options/storage.rs`: global `SecondaryStorage` trait with string values and optional TTL.
- `crates/openauth-core/src/options/advanced.rs`: `BackgroundTaskRunner` hook for deferred plugin updates.
- `crates/openauth-core/src/options/root.rs`: global secondary storage option.
- `crates/openauth-core/src/context.rs`: exposes secondary storage and background task runner to plugins.
- `crates/openauth-core/src/api/schema.rs`: request body schema validation behavior.
- `crates/openauth-plugins/src/api_key/mod.rs`: plugin assembly, constants, exports, routes, schema registration, session hook.
- `crates/openauth-plugins/src/api_key/options.rs`: public options/configuration enums and serde behavior.
- `crates/openauth-plugins/src/api_key/models.rs`: record/public/create response models and DB conversion.
- `crates/openauth-plugins/src/api_key/schema.rs`: `api_keys` table and snake_case DB fields.
- `crates/openauth-plugins/src/api_key/hashing.rs`: key generation and SHA-256 base64url hashing.
- `crates/openauth-plugins/src/api_key/storage.rs`: database/secondary-storage/fallback storage adapter.
- `crates/openauth-plugins/src/api_key/rate_limit.rs`: API-key local quota/rate-limit state calculation.
- `crates/openauth-plugins/src/api_key/permissions.rs`: permission matching.
- `crates/openauth-plugins/src/api_key/organization.rs`: organization-owned API key authorization.
- `crates/openauth-plugins/src/api_key/cleanup.rs`: expired key cleanup.
- `crates/openauth-plugins/src/api_key/routes/*.rs`: individual endpoint handlers.
- `crates/openauth-plugins/tests/api_key/`: focused behavior tests by area; this directory must remain split to avoid one large test file.
- `crates/openauth-plugins/tests/open_api/mod.rs`: generated OpenAPI audit includes API key routes.
- `crates/openauth-plugins/tests/plugins.rs`: plugin id registry includes `api-key`.
- `crates/openauth/src/lib.rs`: public reexports.

---

### Task 1: Core Secondary Storage And Background Hooks

**Files:**
- Create: `crates/openauth-core/src/options/storage.rs`
- Modify: `crates/openauth-core/src/options.rs`
- Modify: `crates/openauth-core/src/options/advanced.rs`
- Modify: `crates/openauth-core/src/options/root.rs`
- Modify: `crates/openauth-core/src/context.rs`
- Modify: `crates/openauth-core/src/context/builder.rs`
- Modify: `crates/openauth/src/lib.rs`

- [x] **Step 1: Add secondary storage trait**

```rust
pub type SecondaryStorageFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, OpenAuthError>> + Send + 'a>>;

pub trait SecondaryStorage: Send + Sync + 'static {
    fn get<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>>;
    fn set<'a>(&'a self, key: &'a str, value: String, ttl_seconds: Option<u64>)
        -> SecondaryStorageFuture<'a, ()>;
    fn delete<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, ()>;
}
```

- [x] **Step 2: Add background task runner hook**

```rust
pub type BackgroundTaskFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

pub trait BackgroundTaskRunner: Send + Sync + 'static {
    fn spawn(&self, task: BackgroundTaskFuture);
}
```

- [x] **Step 3: Wire storage and runner into `OpenAuthOptions` and `AuthContext`**

```rust
pub secondary_storage: Option<Arc<dyn SecondaryStorage>>;
pub background_tasks: Option<Arc<dyn BackgroundTaskRunner>>;
```

- [x] **Step 4: Verify core still passes**

Run: `cargo test -p openauth-core`
Expected: all core tests pass.

---

### Task 2: API Key Module Skeleton And Public Surface

**Files:**
- Create: `crates/openauth-plugins/src/api_key/mod.rs`
- Create: `crates/openauth-plugins/src/api_key/options.rs`
- Create: `crates/openauth-plugins/src/api_key/errors.rs`
- Create: `crates/openauth-plugins/src/api_key/schema.rs`
- Modify: `crates/openauth-plugins/src/lib.rs`
- Modify: `crates/openauth-plugins/tests/plugins.rs`

- [x] **Step 1: Export plugin constructors and constants**

```rust
pub const UPSTREAM_PLUGIN_ID: &str = "api-key";
pub const API_KEY_MODEL: &str = "api_key";
pub const API_KEY_TABLE: &str = "api_keys";

pub fn api_key() -> AuthPlugin;
pub fn api_key_with_options(options: ApiKeyOptions) -> AuthPlugin;
pub fn api_key_with_configurations(
    configurations: Vec<ApiKeyConfiguration>,
) -> Result<AuthPlugin, ApiKeyOptionsError>;
```

- [x] **Step 2: Register Better Auth-compatible endpoint paths**

```text
POST /api-key/create
POST /api-key/verify
GET  /api-key/get
POST /api-key/update
POST /api-key/delete
GET  /api-key/list
POST /api-key/delete-all-expired-api-keys
```

- [x] **Step 3: Verify plugin id registry**

Run: `cargo test -p openauth-plugins plugin_ids_expose_supported_server_plugins`
Expected: `api-key` appears in the plugin id list.

---

### Task 3: Schema, Models, Hashing, Storage, And CRUD

**Files:**
- Create: `crates/openauth-plugins/src/api_key/models.rs`
- Create: `crates/openauth-plugins/src/api_key/hashing.rs`
- Create: `crates/openauth-plugins/src/api_key/storage.rs`
- Create: `crates/openauth-plugins/src/api_key/routes/create.rs`
- Create: `crates/openauth-plugins/src/api_key/routes/get.rs`
- Create: `crates/openauth-plugins/src/api_key/routes/list.rs`
- Create: `crates/openauth-plugins/src/api_key/routes/update.rs`
- Create: `crates/openauth-plugins/src/api_key/routes/delete.rs`
- Test: `crates/openauth-plugins/tests/api_key/`

- [x] **Step 1: Add failing schema test**

```rust
assert_eq!(context.db_schema.table_name(API_KEY_MODEL)?, "api_keys");
assert_eq!(context.db_schema.field_name(API_KEY_MODEL, "config_id")?, "config_id");
assert!(context.db_schema.field(API_KEY_MODEL, "reference_id")?.index);
assert!(context.db_schema.field(API_KEY_MODEL, "key")?.index);
```

- [x] **Step 2: Implement DB table and snake_case fields**

```rust
PluginSchemaContribution::table(
    API_KEY_MODEL,
    TableOptions::default()
        .with_name(API_KEY_TABLE)
        .with_field("config_id", DbField::new("config_id", DbFieldType::String).indexed())
        .with_field("reference_id", DbField::new("reference_id", DbFieldType::String).indexed())
        .with_field("key", DbField::new("key", DbFieldType::String).indexed()),
)
```

- [x] **Step 3: Add CRUD test**

```rust
let created = request_json(&router, Method::POST, "/api/auth/api-key/create", json!({"name":"deploy"}), Some(&cookie), None).await?;
let key = created.body["key"].as_str().ok_or("missing key")?;
let verified = request_json(&router, Method::POST, "/api/auth/api-key/verify", json!({"key": key}), None, None).await?;
assert_eq!(verified.body["valid"], true);
assert!(verified.body["key"]["key"].is_null());
```

- [x] **Step 4: Implement CRUD and plaintext-key-on-create behavior**

```rust
let hashed = if options.disable_key_hashing {
    key.clone()
} else {
    default_key_hasher(&key)
};
json(StatusCode::OK, &ApiKeyCreateRecord { record: created.public(), key })
```

- [x] **Step 5: Verify focused tests**

Run: `cargo test -p openauth-plugins api_key`
Expected: API key CRUD and schema tests pass.

---

### Task 4: Verification, Quotas, Rate Limits, Refill, Deferred Updates

**Files:**
- Create: `crates/openauth-plugins/src/api_key/rate_limit.rs`
- Create: `crates/openauth-plugins/src/api_key/permissions.rs`
- Modify: `crates/openauth-plugins/src/api_key/routes/verify.rs`
- Test: `crates/openauth-plugins/tests/api_key/`

- [x] **Step 1: Add verification quota tests**

```rust
let created = request_json(&router, Method::POST, "/api/auth/api-key/create", json!({"name":"limited","userId": user_id, "remaining":1}), None, None).await?;
let key = created.body["key"].as_str().ok_or("missing key")?;
assert_eq!(first.body["key"]["remaining"], 0);
assert_eq!(second.body["valid"], false);
assert_eq!(second.body["error"]["code"], "USAGE_EXCEEDED");
```

- [x] **Step 2: Add rate-limit window test**

```rust
json!({"name": "burst", "userId": user.user_id, "rateLimitMax": 1, "rateLimitTimeWindow": 60_000})
assert_eq!(second.body["valid"], false);
assert_eq!(second.body["error"]["code"], RATE_LIMIT_EXCEEDED);
```

- [x] **Step 3: Add refill test**

```rust
json!({"name": "refill", "userId": user.user_id, "remaining": 1, "refillAmount": 2, "refillInterval": 1})
tokio::time::sleep(std::time::Duration::from_millis(2)).await;
assert_eq!(second.body["valid"], true);
assert_eq!(second.body["key"]["remaining"], 1);
```

- [x] **Step 4: Implement state updates only during verify**

```rust
api_key.remaining = remaining;
api_key.last_refill_at = last_refill_at;
api_key.last_request = Some(now);
api_key.request_count = request_count;
api_key.updated_at = now;
store.update(&api_key).await?;
```

- [x] **Step 5: Implement deferred update runner fallback**

```rust
if options.defer_updates {
    if !context.run_background_task(Box::pin(async move {
        let _ = ApiKeyStore::new(&task_context, &options).update(&updated).await;
    })) {
        store.update(&api_key).await?;
    }
}
```

- [x] **Step 6: Verify**

Run: `cargo test -p openauth-plugins api_key`
Expected: quota, refill, rate limit, and deferred-update tests pass.

---

### Task 5: Organization-Owned API Keys

**Files:**
- Create: `crates/openauth-plugins/src/api_key/organization.rs`
- Modify: `crates/openauth-plugins/src/api_key/routes/create.rs`
- Modify: `crates/openauth-plugins/src/api_key/routes/list.rs`
- Modify: `crates/openauth-plugins/src/api_key/routes/update.rs`
- Modify: `crates/openauth-plugins/src/api_key/routes/delete.rs`
- Test: `crates/openauth-plugins/tests/api_key/`

- [x] **Step 1: Add org key behavior test**

```rust
let api_key_plugin = api_key_with_configurations(vec![ApiKeyConfiguration {
    config_id: Some("org".to_owned()),
    reference: ApiKeyReference::Organization,
    enable_session_for_api_keys: true,
    ..ApiKeyConfiguration::default()
}])?;
let router = test_router_with_plugins(adapter, vec![organization(), api_key_plugin])?;
```

- [x] **Step 2: Deny non-member management**

```rust
let denied = request_json(&router, Method::POST, "/api/auth/api-key/create", json!({
    "configId":"org",
    "organizationId": organization_id,
    "name":"outsider"
}), Some(&outsider.cookie), None).await?;
assert_eq!(denied.status, StatusCode::FORBIDDEN);
```

- [x] **Step 3: Verify org keys do not mock user sessions**

```rust
let session = request_json(&router, Method::GET, "/api/auth/get-session", Value::Null, None, Some(("x-api-key", key))).await?;
assert!(session.body.is_null());
```

- [x] **Step 4: Implement owner/admin permission checks**

```rust
match member.role.as_str() {
    "owner" => Ok(()),
    "admin" if action == ApiKeyAction::Read => Ok(()),
    "api_key_admin" | "apiKeyAdmin" => Ok(()),
    "api_key_reader" | "apiKeyReader" if action == ApiKeyAction::Read => Ok(()),
    _ => Err(OpenAuthError::Api(errors::message(errors::INSUFFICIENT_API_KEY_PERMISSIONS).to_owned())),
}
```

- [x] **Step 5: Verify**

Run: `cargo test -p openauth-plugins organization_owned_keys_require_membership_and_do_not_mock_sessions`
Expected: test passes.

---

### Task 6: Secondary Storage And Fallback

**Files:**
- Modify: `crates/openauth-plugins/src/api_key/storage.rs`
- Test: `crates/openauth-plugins/tests/api_key/`

- [x] **Step 1: Add secondary-only test**

```rust
let storage = Arc::new(TestSecondaryStorage::default());
let router = test_router(adapter.clone(), api_key_with_options(ApiKeyOptions {
    configuration: ApiKeyConfiguration {
        storage: ApiKeyStorageMode::SecondaryStorage,
        custom_storage: Some(storage),
        ..ApiKeyConfiguration::default()
    },
}))?;
assert_eq!(adapter.records(API_KEY_MODEL).await.len(), 0);
```

- [x] **Step 2: Implement upstream key shapes**

```rust
fn storage_key_by_hash(hashed_key: &str) -> String { format!("api-key:{hashed_key}") }
fn storage_key_by_id(id: &str) -> String { format!("api-key:by-id:{id}") }
fn storage_key_by_reference(reference_id: &str) -> String { format!("api-key:by-ref:{reference_id}") }
```

- [x] **Step 3: Implement fallback-to-database cache population**

```rust
if let Some(api_key) = self.get_database("key", hashed_key).await? {
    self.set_secondary(&api_key).await?;
    return Ok(Some(api_key));
}
```

- [x] **Step 4: Add fallback cache invalidation test**

```rust
let storage = Arc::new(TestSecondaryStorage::default());
let router = test_router(adapter.clone(), api_key_with_options(ApiKeyOptions {
    configuration: ApiKeyConfiguration {
        storage: ApiKeyStorageMode::SecondaryStorage,
        fallback_to_database: true,
        custom_storage: Some(storage.clone()),
        ..ApiKeyConfiguration::default()
    },
}))?;
let listed = request_json(&router, Method::GET, "/api/auth/api-key/list", Value::Null, Some(&user.cookie), None).await?;
assert_eq!(listed.body["total"], 1);
assert!(storage.deleted_keys().iter().any(|key| key.starts_with("api-key:by-ref:")));
```

- [x] **Step 5: Implement observable storage operation tracking in the test helper**

```rust
#[derive(Default)]
struct TestSecondaryStorage {
    values: Mutex<BTreeMap<String, String>>,
    deleted: Mutex<Vec<String>>,
    ttl: Mutex<BTreeMap<String, Option<u64>>>,
}
```

- [x] **Step 6: Verify**

Run: `cargo test -p openauth-plugins fallback_cache_invalidation`
Expected: test passes and fallback mode deletes the ref-list cache instead of mutating it directly.

---

### Task 7: OpenAPI And Public Option Serialization

**Files:**
- Modify: `crates/openauth-plugins/src/api_key/routes/mod.rs`
- Modify: `crates/openauth-plugins/src/api_key/options.rs`
- Modify: `crates/openauth-plugins/tests/open_api/mod.rs`
- Test: `crates/openauth-plugins/tests/api_key/`

- [x] **Step 1: Add endpoint metadata test**

```rust
assert_eq!(endpoint.options.operation_id.as_deref(), Some("createApiKey"));
assert!(endpoint.options.openapi.is_some());
```

- [x] **Step 2: Add OpenAPI audit coverage**

```rust
assert_eq!(
    body["paths"]["/api-key/create"]["post"]["operationId"],
    "createApiKey"
);
```

- [x] **Step 3: Add serde camelCase test**

```rust
let value = serde_json::to_value(ApiKeyConfiguration {
    storage: ApiKeyStorageMode::SecondaryStorage,
    reference: ApiKeyReference::Organization,
    default_key_length: 48,
    enable_session_for_api_keys: true,
    ..ApiKeyConfiguration::default()
})?;
assert_eq!(value["defaultKeyLength"], 48);
assert_eq!(value["storage"], "secondaryStorage");
```

- [x] **Step 4: Implement route metadata and body schemas**

```rust
AuthEndpointOptions::new()
    .operation_id("createApiKey")
    .openapi(OpenApiOperation::new("createApiKey").tag("API Key").response("200", openapi_object_response("API key response")))
    .allowed_media_types(["application/json"])
    .body_schema(create_api_key_body_schema())
```

- [x] **Step 5: Implement serde derives**

```rust
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ApiKeyConfiguration {
    #[serde(skip)]
    pub custom_storage: Option<Arc<dyn SecondaryStorage>>,
}
```

- [x] **Step 6: Verify**

Run: `cargo test -p openauth-plugins open_api`
Expected: OpenAPI tests pass with API key included in generated schema.

---

### Task 8: Split API Key Tests Into Focused Files

**Files:**
- Create: `crates/openauth-plugins/tests/api_key/helpers.rs`
- Create: `crates/openauth-plugins/tests/api_key/surface.rs`
- Create: `crates/openauth-plugins/tests/api_key/schema.rs`
- Create: `crates/openauth-plugins/tests/api_key/lifecycle.rs`
- Create: `crates/openauth-plugins/tests/api_key/verify.rs`
- Create: `crates/openauth-plugins/tests/api_key/storage.rs`
- Create: `crates/openauth-plugins/tests/api_key/metadata.rs`
- Create: `crates/openauth-plugins/tests/api_key/configurations.rs`
- Create: `crates/openauth-plugins/tests/api_key/sessions.rs`
- Create: `crates/openauth-plugins/tests/api_key/organization.rs`
- Modify: `crates/openauth-plugins/tests/api_key/mod.rs`

- [x] **Step 1: Move shared test support into `helpers.rs`**

```rust
pub struct TestResponse {
    pub status: StatusCode,
    pub body: Value,
    pub set_cookie: Option<String>,
}

pub struct SignedUp {
    pub cookie: String,
    pub user_id: String,
}

pub fn test_router(
    adapter: Arc<MemoryAdapter>,
    plugin: openauth_core::plugin::AuthPlugin,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    test_router_with_plugins(adapter, vec![plugin])
}
```

- [x] **Step 2: Keep `mod.rs` as module registry only**

```rust
mod configurations;
mod helpers;
mod lifecycle;
mod metadata;
mod organization;
mod schema;
mod sessions;
mod storage;
mod surface;
mod verify;
```

- [x] **Step 3: Move surface/openapi/serde tests to `surface.rs`**

```rust
#[test]
fn exposes_api_key_plugin_surface() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(UPSTREAM_PLUGIN_ID, "api-key");
    assert_eq!(API_KEY_MODEL, "api_key");
    assert_eq!(API_KEY_TABLE, "api_keys");
    Ok(())
}
```

- [x] **Step 4: Move schema test to `schema.rs`**

```rust
#[test]
fn api_key_schema_uses_plural_table_and_snake_case_fields() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(OpenAuthOptions {
        plugins: vec![api_key()],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    }, adapter)?;
    assert_eq!(context.db_schema.table_name(API_KEY_MODEL)?, "api_keys");
    Ok(())
}
```

- [x] **Step 5: Move behavior tests into focused files**

```rust
// lifecycle.rs: create/get/list/update/delete/pagination
// verify.rs: remaining, permissions, rate limit, refill, deferred updates
// storage.rs: secondary-only and fallback cache invalidation
// metadata.rs: metadata enablement
// configurations.rs: config validation
// sessions.rs: user API-key session mocking
// organization.rs: org ownership and no session mocking
```

- [x] **Step 6: Verify focused tests**

Run: `cargo test -p openauth-plugins api_key`
Expected: all API key tests pass after the split.

---

### Task 9: Final Verification And Review

**Files:**
- Review all modified files from `git status --short`

- [x] **Step 1: Run formatting**

Run: `cargo fmt`
Expected: no output and exit 0.

- [x] **Step 2: Run core tests**

Run: `cargo test -p openauth-core`
Expected: all tests pass.

- [x] **Step 3: Run plugin tests**

Run: `cargo test -p openauth-plugins`
Expected: all tests pass.

- [x] **Step 4: Run public crate plugin feature tests**

Run: `cargo test -p openauth --features plugins`
Expected: all tests pass.

- [x] **Step 5: Scan production code for panic helpers**

Run: `rg "unwrap\\(|expect\\(" crates/openauth-plugins/src/api_key crates/openauth-core/src/options/storage.rs crates/openauth-core/src/context.rs crates/openauth-core/src/options/advanced.rs crates/openauth-core/src/options/root.rs crates/openauth-core/src/api/schema.rs`
Expected: no matches in production API-key/core changes.

---

## Self-Review

- [x] **Spec coverage:** The plan covers server-only public API, schema/table naming, routes, verification behavior, organization keys, secondary storage, deferred updates, OpenAPI, and tests.
- [x] **Placeholder scan:** The plan contains concrete paths, code snippets, commands, and expected results. It avoids unresolved placeholders.
- [x] **Type consistency:** Public names match implemented Rust types: `ApiKeyConfiguration`, `ApiKeyOptions`, `ApiKeyStorageMode`, `ApiKeyReference`, `ApiKeyRecord`, `ApiKeyPublicRecord`, and route request structs.

---

### Task 10: Upstream Re-Analysis Gap Closure

**Upstream sources re-read:**
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/index.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/types.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/routes/*.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/adapter.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/org-authorization.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/error-codes.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/api-key.test.ts`
- `upstream/better-auth/1.6.9/repository/packages/api-key/src/org-api-key.test.ts`

- [x] Default key generation should use letters only (`a-z`, `A-Z`) after the optional prefix; current Rust generator delegates to the core random helper.
- [x] `ApiKeyConfiguration` is missing Rust equivalents for upstream `customKeyGenerator`, `customAPIKeyGetter`, and `customAPIKeyValidator`.
- [x] `verifyApiKey` should call the custom validator before hashing/storage lookup and return upstream-compatible invalid-key response on rejection.
- [x] API-key session hook should support custom key getter/validator and keep org-key session mocking blocked.
- [x] `updateApiKey` is missing server-only field rejection for client/session calls.
- [x] `updateApiKey` does not validate `expiresIn` against min/max days and `disableCustomExpiresTime` parity is only partial.
- [x] `updateApiKey` metadata behavior differs when metadata is disabled; upstream does not write metadata and ends as `NO_VALUES_TO_UPDATE` when metadata is the only patch.
- [x] `listApiKeys` without `configId` should merge all configurations for the requested user/org reference, deduplicate by id, filter by reference type, then paginate.
- [x] Fallback secondary-storage list should read an existing ref-list cache first, then fall back to DB and populate cache.
- [x] Secondary-storage list/populate should use bounded concurrent fetch/populate instead of fully sequential operations.
- [x] More upstream scenarios need focused Rust tests: `disableKeyHashing`, `startingCharactersConfig.shouldStore=false`, custom `charactersLength`, default prefix, default permissions, update server-only rejection, update expiration bounds, custom storage precedence, secondary fallback read-first behavior, and multi-config list without `configId`.
- [x] Explicit JSON `null` semantics remain partial in update bodies (`expiresIn: null`, `permissions: null`) because Rust `Option<T>` currently collapses missing and null.
- [x] API-key session hook still silently continues on too-short keys instead of surfacing upstream's forbidden `INVALID_API_KEY` response on protected paths.
- [x] Organization authorization is still a simplified Rust approximation; upstream delegates to organization `hasPermission` for `apiKey: ["create", "read", "update", "delete"]`.

**Second pass closeout:**
- [x] **Step 7: Add and pass tests for remaining parity gaps**

```rust
// explicit null update semantics, short session hook keys,
// custom org apiKey permissions, secondary-storage concurrent list fetches
```

- [x] **Step 8: Implement remaining parity gaps**

```rust
// UpdateField<T>, creator/custom/dynamic org permission checks,
// bounded storage future polling, forbidden short-key response
```

**Implementation order:**
- [x] **Step 1: Add failing tests for high-impact parity gaps**

```rust
// generator/custom hooks, update validation, list-all-configs, fallback read-first
```

- [x] **Step 2: Implement generator and custom hook options**

```rust
pub custom_key_generator: Option<ApiKeyGenerator>;
pub custom_api_key_getter: Option<ApiKeyGetter>;
pub custom_api_key_validator: Option<ApiKeyValidator>;
```

- [x] **Step 3: Harden update route parity**

```rust
// reject server-only fields from session/client calls
// validate expiresIn min/max days
// preserve upstream metadata-disabled behavior
```

- [x] **Step 4: Implement list-all-configs and fallback cache read-first**

```rust
// no configId => query every configuration/storage group and merge/dedupe
// fallback secondary storage => use ref-list cache before DB fallback
```

- [x] **Step 5: Add remaining focused tests**

```rust
// disable hashing, starting chars, default prefix, default permissions,
// custom storage precedence, org permission follow-ups
```

- [x] **Step 6: Re-run verification**

Run:
- `cargo fmt`
- `cargo test -p openauth-plugins api_key`
- `cargo test -p openauth-core`
- `cargo test -p openauth --features plugins`
