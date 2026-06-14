use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rustauth::db::{Create, DbAdapter, DbValue, MemoryAdapter};
use rustauth::error::RustAuthError;
use rustauth::options::{AdvancedOptions, ExperimentalOptions, RustAuthOptions};
use rustauth::plugin::{PluginDatabaseBeforeAction, PluginDatabaseBeforeInput, PluginDatabaseHook};
use rustauth::RustAuthBuilder;

fn test_options(database_hooks: Vec<PluginDatabaseHook>) -> RustAuthOptions {
    RustAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        experimental: ExperimentalOptions::default().joins(true),
        database_hooks,
        ..RustAuthOptions::default()
    }
}

fn counting_create_hooks() -> (Vec<PluginDatabaseHook>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let before_count = Arc::new(AtomicUsize::new(0));
    let after_count = Arc::new(AtomicUsize::new(0));
    let before_counter = Arc::clone(&before_count);

    let hooks = vec![
        PluginDatabaseHook::before_create("count-before", move |_context, query| {
            before_counter.fetch_add(1, Ordering::SeqCst);
            Ok(PluginDatabaseBeforeAction::Continue(
                PluginDatabaseBeforeInput::Create(query),
            ))
        }),
        PluginDatabaseHook::after_create("count-after", {
            let after_counter = Arc::clone(&after_count);
            move |_context, _query, _result| {
                after_counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }),
    ];

    (hooks, before_count, after_count)
}

async fn run_counted_create(adapter: &dyn DbAdapter) -> Result<(), RustAuthError> {
    adapter
        .create(
            Create::new("user")
                .data("name", DbValue::String("Ada".to_owned()))
                .data("email", DbValue::String("ada@example.com".to_owned())),
        )
        .await?;
    Ok(())
}

fn assert_single_hook_execution(
    before_count: &AtomicUsize,
    after_count: &AtomicUsize,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        before_count.load(Ordering::SeqCst),
        1,
        "expected exactly one before_create hook invocation"
    );
    assert_eq!(
        after_count.load(Ordering::SeqCst),
        1,
        "expected exactly one after_create hook invocation"
    );
    Ok(())
}

#[tokio::test]
async fn rustauth_builder_runs_database_hooks_once_per_operation(
) -> Result<(), Box<dyn std::error::Error>> {
    let (hooks, before_count, after_count) = counting_create_hooks();
    let auth = RustAuthBuilder::new()
        .options(test_options(hooks))
        .adapter(MemoryAdapter::new())
        .build()
        .await?;
    let adapter = auth
        .context()
        .adapter
        .as_deref()
        .ok_or("expected adapter-backed context")?;

    run_counted_create(adapter).await?;
    assert_single_hook_execution(&before_count, &after_count)
}

#[tokio::test]
async fn rustauth_builder_runs_database_hooks_once_with_joins_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let (hooks, before_count, after_count) = counting_create_hooks();
    let auth = RustAuthBuilder::new()
        .options(test_options(hooks))
        .adapter(MemoryAdapter::new())
        .build()
        .await?;
    let adapter = auth
        .context()
        .adapter
        .as_deref()
        .ok_or("expected adapter-backed context")?;

    run_counted_create(adapter).await?;
    assert_single_hook_execution(&before_count, &after_count)
}
