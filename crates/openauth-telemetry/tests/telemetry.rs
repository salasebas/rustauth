//! Integration tests aligned with Better Auth `packages/telemetry/src/telemetry.test.ts`.

#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openauth_core::options::{AdvancedOptions, CookieConfig, OpenAuthOptions, TelemetryOptions};
use openauth_telemetry::{
    create_telemetry, types::CustomTrackFn, DetectionInfo, RuntimeInfo, TelemetryContext,
    TelemetryEvent, TelemetryHttpError, TelemetryHttpTransport, TelemetryTestHooks,
};
use serde_json::{json, Value};
use std::sync::OnceLock;
use tokio::sync::oneshot;
use tokio::sync::Mutex as AsyncMutex;

fn telemetry_env_lock() -> &'static AsyncMutex<()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

fn assert_json_superset(actual: &Value, expected: &Value, ctx: &str) {
    match (actual, expected) {
        (Value::Object(am), Value::Object(em)) => {
            for (k, ev) in em {
                let Some(av) = am.get(k) else {
                    panic!("{ctx}: missing key {k}");
                };
                assert_json_superset(av, ev, &format!("{ctx}.{k}"));
            }
        }
        (Value::Array(a), Value::Array(e)) if a.len() >= e.len() => {
            for (i, pair) in e.iter().enumerate() {
                assert_json_superset(&a[i], pair, &format!("{ctx}[{i}]"));
            }
        }
        _ if actual == expected => {}
        _ => panic!("{ctx}: mismatch\nactual={actual:#}\nexpected={expected:#}"),
    }
}

struct EnvRestore(Vec<(&'static str, Option<String>)>);

impl EnvRestore {
    fn unset(keys: &[&'static str]) -> Self {
        let saved = keys
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect::<Vec<_>>();
        for k in keys {
            std::env::remove_var(k);
        }
        Self(saved)
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, old) in self.0.iter() {
            match old {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

struct CountingTransport {
    posts: Arc<AtomicUsize>,
}

impl TelemetryHttpTransport for CountingTransport {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), TelemetryHttpError>> + Send + 'a>> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(()) })
    }
}

fn upstream_style_hooks() -> TelemetryTestHooks {
    TelemetryTestHooks {
        anonymous_id: Some("anon-123".into()),
        runtime: Some(RuntimeInfo {
            name: "node".into(),
            version: Some("test".into()),
        }),
        database: Some(Some(DetectionInfo {
            name: "postgresql".into(),
            version: "1.0.0".into(),
        })),
        framework: Some(Some(DetectionInfo {
            name: "next".into(),
            version: "15.0.0".into(),
        })),
        environment: Some("test".into()),
        system_info: Some(json!({
            "systemPlatform": "darwin",
            "systemRelease": "24.6.0",
            "systemArchitecture": "arm64",
            "cpuCount": 8,
            "cpuModel": "Apple M3",
            "cpuSpeed": 3200,
            "memory": 17179869184_i64,
            "isDocker": false,
            "isTTY": true,
            "isWSL": false,
            "isCI": false,
        })),
        package_manager: Some(Some(DetectionInfo {
            name: "pnpm".into(),
            version: "9.0.0".into(),
        })),
    }
}

#[tokio::test]
async fn publishes_init_when_enabled() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let captured = Arc::new(Mutex::new(None::<Value>));
    let cap = captured.clone();
    let custom: CustomTrackFn = Arc::new(move |ev: TelemetryEvent| {
        let cap = cap.clone();
        Box::pin(async move {
            let j = serde_json::to_value(&ev).expect("serialize event");
            *cap.lock().expect("lock") = Some(j);
        })
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost.com".into()),
        advanced: AdvancedOptions {
            cookie_prefix: Some("test".into()),
            cross_subdomain_cookies: Some(CookieConfig {
                enabled: true,
                domain: Some(".test.com".into()),
            }),
            ..Default::default()
        },
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    let ctx = TelemetryContext {
        custom_track: Some(custom),
        skip_test_check: true,
        test_hooks: Some(upstream_style_hooks()),
        ..Default::default()
    };

    let expected_config =
        openauth_telemetry::get_telemetry_auth_config(&options, &TelemetryContext::default());

    create_telemetry(&options, ctx).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    let event = captured
        .lock()
        .expect("lock")
        .take()
        .expect("custom track must capture init");

    assert_eq!(event["type"], "init");
    assert_eq!(event["anonymousId"], "anon-123");

    let payload = &event["payload"];
    assert_json_superset(payload, &json!({ "environment": "test" }), "payload");
    assert_json_superset(
        payload,
        &json!({
            "runtime": { "name": "node", "version": "test" },
            "database": { "name": "postgresql", "version": "1.0.0" },
            "framework": { "name": "next", "version": "15.0.0" },
            "packageManager": { "name": "pnpm", "version": "9.0.0" },
        }),
        "payload",
    );
    assert_json_superset(&payload["config"], &expected_config, "payload.config");
}

#[tokio::test]
async fn does_not_publish_when_disabled_via_env() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);
    std::env::set_var("OPENAUTH_TELEMETRY", "false");

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost".into()),
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn does_not_publish_when_disabled_via_option() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost".into()),
        telemetry: TelemetryOptions {
            enabled: Some(false),
            debug: false,
        },
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn panicking_custom_track_does_not_abort_create_telemetry() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let custom: CustomTrackFn = Arc::new(|_ev| {
        Box::pin(async move {
            panic!("test panic");
        })
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost".into()),
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    let _publisher = create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;
}

#[tokio::test]
async fn slow_init_custom_track_does_not_block_create_telemetry() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let (started_tx, started_rx) = oneshot::channel();
    let started_tx = Arc::new(Mutex::new(Some(started_tx)));
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        let started_tx = started_tx.clone();
        Box::pin(async move {
            if let Some(tx) = started_tx.lock().expect("lock").take() {
                let _ = tx.send(());
            }
            std::future::pending::<()>().await;
        })
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost".into()),
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    let result = tokio::time::timeout(
        Duration::from_millis(50),
        create_telemetry(
            &options,
            TelemetryContext {
                custom_track: Some(custom),
                skip_test_check: true,
                ..Default::default()
            },
        ),
    )
    .await;

    assert!(
        result.is_ok(),
        "create_telemetry should not wait for init delivery"
    );
    tokio::time::timeout(Duration::from_millis(50), started_rx)
        .await
        .expect("init track should start")
        .expect("init track should signal start");
}

#[tokio::test]
async fn init_with_missing_manifest_env_still_tracks() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&[
        "OPENAUTH_TELEMETRY",
        "OPENAUTH_TELEMETRY_ENDPOINT",
        "CARGO_MANIFEST_DIR",
    ]);

    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let custom: CustomTrackFn = Arc::new(move |_ev| {
        c.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {})
    });

    let options = OpenAuthOptions {
        base_url: Some("https://example.com".into()),
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    create_telemetry(
        &options,
        TelemetryContext {
            custom_track: Some(custom),
            skip_test_check: true,
            ..Default::default()
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(calls.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn noop_skips_http_transport_when_no_endpoint_and_no_custom_sink() {
    let _guard = telemetry_env_lock().lock().await;
    let _teardown = EnvRestore::unset(&["OPENAUTH_TELEMETRY", "OPENAUTH_TELEMETRY_ENDPOINT"]);

    let posts = Arc::new(AtomicUsize::new(0));
    let transport: Arc<dyn TelemetryHttpTransport> = Arc::new(CountingTransport {
        posts: posts.clone(),
    });

    let options = OpenAuthOptions {
        base_url: Some("http://localhost".into()),
        telemetry: TelemetryOptions {
            enabled: Some(true),
            debug: false,
        },
        ..Default::default()
    };

    let publisher = create_telemetry(
        &options,
        TelemetryContext {
            skip_test_check: true,
            http_transport: Some(transport),
            ..Default::default()
        },
    )
    .await;

    publisher
        .publish(TelemetryEvent {
            event_type: "test-event".into(),
            anonymous_id: None,
            payload: json!({ "test": "data" }),
        })
        .await;

    assert_eq!(posts.load(Ordering::SeqCst), 0);
}
