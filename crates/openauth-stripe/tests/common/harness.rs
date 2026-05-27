use http::{Method, Request};
use openauth_core::context::{create_auth_context_with_adapter, AuthContext};
use openauth_core::cookies::{set_session_cookie, CookieOptions, SessionCookieOptions};
use openauth_core::db::{Create, DbAdapter, DbValue, MemoryAdapter, User};
use openauth_core::options::OpenAuthOptions;
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::user::{CreateUserInput, DbUserStore};
use openauth_stripe::options::{StripeOptions, StripePlan, SubscriptionOptions};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{StripeClient, StripeTransport};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

pub fn organization_stripe_options(
    transport: Arc<dyn StripeTransport>,
    authorize: bool,
) -> StripeOptions {
    StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .organization(openauth_stripe::options::OrganizationStripeOptions::enabled())
    .subscription(
        SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
            .authorize_reference(move |_input, _| {
                let authorize = authorize;
                Box::pin(async move { Ok(authorize) })
            }),
    )
}

pub fn stripe_options(transport: Arc<dyn StripeTransport>) -> StripeOptions {
    StripeOptions::new(
        StripeClient::with_transport("sk_test", transport),
        "whsec_test",
    )
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("pro").price_id("price_pro")
    ]))
}

pub async fn authenticated_context(
) -> Result<(AuthContext, MemoryAdapter, String), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            base_url: Some("http://localhost:3000".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter_arc,
    )?;
    let user = DbUserStore::new(&adapter)
        .create_user(
            CreateUserInput::new("Ada Lovelace", "ada@example.com")
                .id("user_1")
                .email_verified(true),
        )
        .await?;
    let session = DbSessionStore::new(&adapter)
        .create_session(
            CreateSessionInput::new(user.id, OffsetDateTime::now_utc() + Duration::days(7))
                .token("session_token_1"),
        )
        .await?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions {
            dont_remember: false,
            overrides: CookieOptions::default(),
        },
    )?;
    let session_cookie = cookies.first().ok_or("session cookie")?;
    Ok((
        context,
        adapter,
        format!("{}={}", session_cookie.name, session_cookie.value),
    ))
}

pub async fn create_subscription_record(
    adapter: &MemoryAdapter,
    id: &str,
    reference_id: &str,
    status: &str,
    stripe_customer_id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut create = Create::new("subscription")
        .data("id", DbValue::String(id.to_owned()))
        .data("plan", DbValue::String("pro".to_owned()))
        .data("reference_id", DbValue::String(reference_id.to_owned()))
        .data("status", DbValue::String(status.to_owned()))
        .data("cancel_at_period_end", DbValue::Boolean(false))
        .data("seats", DbValue::Number(1))
        .data("billing_interval", DbValue::String("month".to_owned()))
        .force_allow_id();
    if let Some(customer_id) = stripe_customer_id {
        create = create.data(
            "stripe_customer_id",
            DbValue::String(customer_id.to_owned()),
        );
    } else {
        create = create.data("stripe_customer_id", DbValue::Null);
    }
    adapter.create(create).await?;
    Ok(())
}

pub fn upgrade_request(cookie_header: &str, body: &[u8]) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(body.to_vec())
}

pub fn plugin_endpoint<'a>(
    plugin: &'a openauth_core::plugin::AuthPlugin,
    path: &str,
) -> Option<&'a openauth_core::api::AsyncAuthEndpoint> {
    plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == path)
}

pub fn stripe_plugin(transport: Arc<dyn StripeTransport>) -> openauth_core::plugin::AuthPlugin {
    stripe(stripe_options(transport))
}

pub async fn session_cookie_for_user(
    context: &AuthContext,
    adapter: &MemoryAdapter,
    user: &User,
    token: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let session = DbSessionStore::new(adapter)
        .create_session(
            CreateSessionInput::new(
                user.id.clone(),
                OffsetDateTime::now_utc() + Duration::days(7),
            )
            .token(token),
        )
        .await?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        &session.token,
        SessionCookieOptions {
            dont_remember: false,
            overrides: CookieOptions::default(),
        },
    )?;
    let session_cookie = cookies.first().ok_or("session cookie")?;
    Ok(format!("{}={}", session_cookie.name, session_cookie.value))
}

pub async fn create_user(
    adapter: &MemoryAdapter,
    id: &str,
    email: &str,
) -> Result<User, Box<dyn std::error::Error>> {
    Ok(DbUserStore::new(adapter)
        .create_user(
            CreateUserInput::new("Test User", email)
                .id(id)
                .email_verified(true),
        )
        .await?)
}

pub fn json_post_request(
    path: &str,
    cookie_header: &str,
    body: &[u8],
) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:3000/api/auth{path}"))
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(body.to_vec())
}
