use super::*;
use time::Duration;

use rustauth_core::db::{
    Count, Delete, DeleteMany, FindMany, TransactionCallback, Update, UpdateMany,
};

/// Adapter that behaves like `MemoryAdapter` but always fails `delete`, to
/// exercise the sign-out path when server-side session invalidation fails.
struct FailingDeleteAdapter(MemoryAdapter);

impl DbAdapter for FailingDeleteAdapter {
    fn id(&self) -> &str {
        self.0.id()
    }
    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        self.0.create(query)
    }
    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        self.0.find_one(query)
    }
    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        self.0.find_many(query)
    }
    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        self.0.count(query)
    }
    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        self.0.update(query)
    }
    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        self.0.update_many(query)
    }
    fn delete<'a>(&'a self, _query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async { Err(RustAuthError::Adapter("delete failed".to_owned())) })
    }
    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        self.0.delete_many(query)
    }
    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        self.0.transaction(callback)
    }
}

#[tokio::test]
async fn sign_out_route_does_not_report_success_when_delete_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(FailingDeleteAdapter(MemoryAdapter::default()));
    let context = create_auth_context_with_adapter(
        RustAuthOptions {
            secret: Some(secret().to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..RustAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let router =
        AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-out",
            "{}",
            Some(&cookie),
        )?)
        .await?;

    assert_ne!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn sign_out_route_deletes_session_and_expires_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router(adapter.clone())?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-out",
            "{}",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(adapter.is_empty("session").await);
    assert!(set_cookie_values(&response).iter().any(|cookie| cookie
        .starts_with("rustauth.session_token=;")
        && cookie.contains("Max-Age=0")));
    Ok(())
}
