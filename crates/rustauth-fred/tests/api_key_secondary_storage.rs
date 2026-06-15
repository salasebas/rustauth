use std::sync::Arc;
use std::time::Duration as StdDuration;

use http::{header, Method, StatusCode};
use rustauth_core::api::{core_auth_async_endpoints, AuthRouter};
use rustauth_core::context::create_auth_context_with_adapter;
use rustauth_core::db::MemoryAdapter;
use rustauth_core::options::{RustAuthOptions, SecondaryStorage};
use rustauth_core::test_utils::with_integration_test_defaults;
use rustauth_fred::{FredSecondaryStorage, FredSecondaryStorageOptions};
use rustauth_plugins::api_key::{api_key, ApiKeyConfiguration, ApiKeyOptions, ApiKeyStorageMode};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug)]
struct LiveFredTarget {
    name: &'static str,
    url: String,
    explicit: bool,
}

impl LiveFredTarget {
    async fn should_attempt_default_connect(&self) -> bool {
        if self.explicit {
            return true;
        }
        default_target_is_reachable(&self.url).await
    }
}

fn live_fred_targets() -> Vec<LiveFredTarget> {
    let mut targets = Vec::new();
    if let Ok(url) = std::env::var("RUSTAUTH_FRED_REDIS_URL") {
        targets.push(LiveFredTarget {
            name: "redis",
            url,
            explicit: true,
        });
    }
    if let Ok(url) = std::env::var("RUSTAUTH_FRED_VALKEY_URL") {
        targets.push(LiveFredTarget {
            name: "valkey",
            url,
            explicit: true,
        });
    }
    if targets.is_empty() {
        targets.push(LiveFredTarget {
            name: "redis",
            url: "redis://127.0.0.1:6379".to_owned(),
            explicit: false,
        });
        targets.push(LiveFredTarget {
            name: "valkey",
            url: "valkey://127.0.0.1:6380".to_owned(),
            explicit: false,
        });
    }
    targets
}

#[tokio::test]
async fn fred_secondary_storage_concurrent_api_key_creates_keep_both_ids_in_ref_index(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in live_fred_targets() {
        if !target.should_attempt_default_connect().await {
            eprintln!(
                "skipping default {} Fred target `{}` because its TCP endpoint is unavailable",
                target.name, target.url
            );
            continue;
        }
        let storage = match FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: format!("rustauth:test:api-key:fred:{}:{}:", target.name, now_ms()),
                scan_count: 10,
            },
        )
        .await
        {
            Ok(storage) => Arc::new(storage) as Arc<dyn SecondaryStorage>,
            Err(error) if target.explicit => {
                return Err(format!(
                    "explicit {} Fred target `{}` is unavailable: {error}",
                    target.name, target.url
                )
                .into());
            }
            Err(error) => {
                eprintln!(
                    "skipping default {} Fred target `{}` because it is unavailable: {error}",
                    target.name, target.url
                );
                continue;
            }
        };
        assert_concurrent_create_listing_keeps_both_ids(target.name, storage).await?;
    }
    Ok(())
}

async fn assert_concurrent_create_listing_keeps_both_ids(
    storage_name: &str,
    storage: Arc<dyn SecondaryStorage>,
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    storage: ApiKeyStorageMode::SecondaryStorage,
                    custom_storage: Some(storage),
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
    )?;
    let suffix = now_ms();
    let user = sign_up(
        &router,
        &format!("Live Conc {storage_name}"),
        &format!("live-conc-{storage_name}-{suffix}@example.com"),
    )
    .await?;

    let (first, second) = tokio::join!(
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"name": "first"}),
            Some(&user.cookie),
        ),
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"name": "second"}),
            Some(&user.cookie),
        ),
    );
    let first = first?;
    let second = second?;
    assert_eq!(first.status, StatusCode::OK, "{storage_name} first create");
    assert_eq!(
        second.status,
        StatusCode::OK,
        "{storage_name} second create"
    );
    let first_id = first.body["id"].as_str().ok_or("missing first id")?;
    let second_id = second.body["id"].as_str().ok_or("missing second id")?;

    let listed = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list",
        serde_json::Value::Null,
        Some(&user.cookie),
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK, "{storage_name} list");
    assert_eq!(
        listed.body["total"], 2,
        "{storage_name} must keep both concurrently-created keys in the reference index",
    );
    let listed_ids = listed.body["apiKeys"]
        .as_array()
        .ok_or("missing apiKeys array")?
        .iter()
        .filter_map(|api_key| api_key["id"].as_str())
        .collect::<Vec<_>>();
    assert!(
        listed_ids.contains(&first_id),
        "{storage_name} first concurrently-created key id missing from list: {listed_ids:?}"
    );
    assert!(
        listed_ids.contains(&second_id),
        "{storage_name} second concurrently-created key id missing from list: {listed_ids:?}"
    );
    Ok(())
}

fn test_router(
    adapter: Arc<MemoryAdapter>,
    plugin: rustauth_core::plugin::AuthPlugin,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    let context = create_auth_context_with_adapter(
        with_integration_test_defaults(RustAuthOptions {
            plugins: vec![plugin],
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..RustAuthOptions::default()
        }),
        adapter,
    )?;
    Ok(AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(),
    )?)
}

struct SignedUp {
    cookie: String,
}

async fn sign_up(
    router: &AuthRouter,
    name: &str,
    email: &str,
) -> Result<SignedUp, Box<dyn std::error::Error>> {
    let response = request_json(
        router,
        Method::POST,
        "/api/auth/sign-up/email",
        json!({"name":name,"email":email,"password":"secret123"}),
        None,
    )
    .await?;
    assert_eq!(response.status, StatusCode::OK);
    Ok(SignedUp {
        cookie: response.set_cookie.ok_or("missing session cookie")?,
    })
}

struct TestResponse {
    status: StatusCode,
    body: Value,
    set_cookie: Option<String>,
}

async fn request_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> Result<TestResponse, Box<dyn std::error::Error>> {
    let payload = if matches!(body, Value::Null) {
        Vec::new()
    } else {
        serde_json::to_vec(&body)?
    };
    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !payload.is_empty() {
        builder = builder
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "http://localhost:3000");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let request = builder.body(payload)?;
    let response = router.handle_async(request).await?;
    let status = response.status();
    let set_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("rustauth.session_token="))
        .and_then(|value| value.split(';').next().map(str::to_owned));
    let parsed_body = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body())?
    };
    Ok(TestResponse {
        status,
        body: parsed_body,
        set_cookie,
    })
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

async fn default_target_is_reachable(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let Some(port) = parsed.port_or_known_default() else {
        return false;
    };

    timeout(
        StdDuration::from_millis(250),
        TcpStream::connect((host, port)),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}
