use std::sync::Arc;

use http::StatusCode;
use openauth_core::api::AuthRouter;
use openauth_core::db::{
    AdapterCapabilities, AdapterFuture, Count, Create, DbAdapter, DbRecord, Delete, DeleteMany,
    FindMany, FindOne, MemoryAdapter, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions, RateLimitOptions};
use openauth_core::plugin::AuthPlugin;
use openauth_plugins::magic_link::{magic_link_with, MagicLinkOptions};

use super::support::{
    build_router_with_adapter, get, location, post_json, seed_user, sender, sent_messages, SECRET,
};

#[tokio::test]
async fn failed_user_creation_redirects_with_upstream_error_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let adapter = Arc::new(FailingCreateAdapter::new("user"));
    let router = router(
        adapter,
        magic_link_with(MagicLinkOptions::new(sender(sent.clone()))),
    )?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"new@example.com"}"#,
    )
    .await?;
    let token = sent
        .lock()
        .map_err(|_| "sent lock poisoned")?
        .last()
        .ok_or("missing magic link")?
        .token
        .clone();
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(location(&response).is_some_and(|value| value.contains("error=failed_to_create_user")));
    Ok(())
}

#[tokio::test]
async fn failed_session_creation_redirects_with_upstream_error_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = sent_messages();
    let adapter = Arc::new(FailingCreateAdapter::new("session"));
    seed_user(&adapter.inner, "user_1", "Ada", "ada@example.com", true).await?;
    let router = router(
        adapter,
        magic_link_with(MagicLinkOptions::new(sender(sent.clone()))),
    )?;

    post_json(
        &router,
        "/api/auth/sign-in/magic-link",
        r#"{"email":"ada@example.com"}"#,
    )
    .await?;
    let token = sent
        .lock()
        .map_err(|_| "sent lock poisoned")?
        .last()
        .ok_or("missing magic link")?
        .token
        .clone();
    let response = get(
        &router,
        &format!("/api/auth/magic-link/verify?token={token}"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        location(&response).is_some_and(|value| value.contains("error=failed_to_create_session"))
    );
    Ok(())
}

fn router<A>(adapter: Arc<A>, plugin: AuthPlugin) -> Result<AuthRouter, OpenAuthError>
where
    A: DbAdapter + 'static,
{
    build_router_with_adapter(
        adapter,
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some(SECRET.to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![plugin],
            rate_limit: RateLimitOptions {
                enabled: Some(false),
                ..RateLimitOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )
}

struct FailingCreateAdapter {
    inner: MemoryAdapter,
    fail_model: &'static str,
}

impl FailingCreateAdapter {
    fn new(fail_model: &'static str) -> Self {
        Self {
            inner: MemoryAdapter::new(),
            fail_model,
        }
    }
}

impl DbAdapter for FailingCreateAdapter {
    fn id(&self) -> &str {
        "failing-create"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        self.inner.capabilities()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        if query.model == self.fail_model {
            return Box::pin(async {
                Err(OpenAuthError::Adapter("forced create failure".to_owned()))
            });
        }
        self.inner.create(query)
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        self.inner.find_one(query)
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        self.inner.find_many(query)
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        self.inner.count(query)
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        self.inner.update(query)
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        self.inner.update_many(query)
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        self.inner.delete(query)
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        self.inner.delete_many(query)
    }

    fn transaction<'a>(
        &'a self,
        callback: openauth_core::db::TransactionCallback<'a>,
    ) -> AdapterFuture<'a, ()> {
        self.inner.transaction(callback)
    }
}
