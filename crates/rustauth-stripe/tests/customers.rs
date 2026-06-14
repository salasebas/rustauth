#![allow(clippy::unwrap_used)]

use http::{Method, Request, StatusCode};
use rustauth_core::context::{create_auth_context_with_adapter, AuthContext};
use rustauth_core::cookies::{set_session_cookie, CookieOptions, SessionCookieOptions};
use rustauth_core::db::{Create, DbAdapter, DbRecord, DbValue, FindOne, MemoryAdapter, Where};
use rustauth_core::error::RustAuthError;
use rustauth_core::options::RustAuthOptions;
use rustauth_core::session::{CreateSessionInput, DbSessionStore};
use rustauth_core::user::{CreateUserInput, DbUserStore};
use rustauth_stripe::options::{
    OrganizationStripeOptions, StripeOptions, StripePlan, SubscriptionOptions,
};
use rustauth_stripe::stripe;
use rustauth_stripe::stripe_api::{
    StripeClient, StripeRequest, StripeResponse, StripeTransport, StripeTransportFuture,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use time::{Duration, OffsetDateTime};

fn stripe_search_limit(request: &StripeRequest) -> usize {
    request
        .body
        .split('&')
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == "limit").then(|| value.parse().unwrap_or(1))
        })
        .unwrap_or(1)
}

fn stripe_search_results(data: Value, request: &StripeRequest) -> Value {
    let limit = stripe_search_limit(request);
    let items = data
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({
        "object": "search_result",
        "data": items.into_iter().take(limit).collect::<Vec<_>>(),
    })
}

#[derive(Default)]
struct CustomerTransport {
    requests: Mutex<Vec<StripeRequest>>,
    mode: CustomerTransportMode,
}

impl CustomerTransport {
    fn new(mode: CustomerTransportMode) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            mode,
        }
    }

    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Copy, Default)]
enum CustomerTransportMode {
    #[default]
    CreateCustomer,
    SearchFindsUserCustomer,
    SearchFindsDashboardCustomer,
    SearchFindsForeignUserCustomer,
    SearchFindsForeignThenDashboardCustomer,
    SearchFailsListFindsUserCustomer,
    SearchFailsListPaginatesToUserCustomer,
    SearchFailsListPaginatesToOrganizationCustomer,
    ExistingCustomerEmailDiffers,
    CreateCustomerFails,
    CheckoutSessionDeclined,
}

impl StripeTransport for CustomerTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let response = match (self.mode, request.path.as_str(), request.method.as_str()) {
            (CustomerTransportMode::CreateCustomer, "/v1/customers/search", _) => StripeResponse {
                status: 200,
                body: json!({ "object": "search_result", "data": [] }),
            },
            (CustomerTransportMode::SearchFindsUserCustomer, "/v1/customers/search", _) => {
                StripeResponse {
                    status: 200,
                    body: json!({
                        "object": "search_result",
                        "data": [{
                            "id": "cus_search_user",
                            "object": "customer",
                            "metadata": { "userId": "user_1", "customerType": "user" }
                        }]
                    }),
                }
            }
            (CustomerTransportMode::SearchFindsDashboardCustomer, "/v1/customers/search", _) => {
                StripeResponse {
                    status: 200,
                    body: json!({
                        "object": "search_result",
                        "data": [{
                            "id": "cus_dashboard",
                            "object": "customer",
                            "email": "ada@example.com",
                            "metadata": {}
                        }]
                    }),
                }
            }
            (CustomerTransportMode::SearchFindsForeignUserCustomer, "/v1/customers/search", _) => {
                StripeResponse {
                    status: 200,
                    body: json!({
                        "object": "search_result",
                        "data": [{
                            "id": "cus_foreign_user",
                            "object": "customer",
                            "email": "ada@example.com",
                            "metadata": { "userId": "user_2", "customerType": "user" }
                        }]
                    }),
                }
            }
            (
                CustomerTransportMode::SearchFindsForeignThenDashboardCustomer,
                "/v1/customers/search",
                _,
            ) => StripeResponse {
                status: 200,
                body: stripe_search_results(
                    json!({
                        "object": "search_result",
                        "data": [
                            {
                                "id": "cus_foreign_user",
                                "object": "customer",
                                "email": "ada@example.com",
                                "metadata": { "userId": "user_2", "customerType": "user" }
                            },
                            {
                                "id": "cus_dashboard",
                                "object": "customer",
                                "email": "ada@example.com",
                                "metadata": {}
                            }
                        ]
                    }),
                    &request,
                ),
            },
            (
                CustomerTransportMode::SearchFailsListFindsUserCustomer,
                "/v1/customers/search",
                _,
            ) => StripeResponse {
                status: 500,
                body: json!({ "error": { "message": "Search unavailable" } }),
            },
            (CustomerTransportMode::SearchFailsListFindsUserCustomer, "/v1/customers", "GET") => {
                StripeResponse {
                    status: 200,
                    body: json!({
                        "object": "list",
                        "data": [
                            {
                                "id": "cus_org",
                                "object": "customer",
                                "metadata": { "organizationId": "user_1", "customerType": "organization" }
                            },
                            {
                                "id": "cus_list_user",
                                "object": "customer",
                                "metadata": { "userId": "user_1", "customerType": "user" }
                            }
                        ]
                    }),
                }
            }
            (
                CustomerTransportMode::SearchFailsListPaginatesToUserCustomer,
                "/v1/customers/search",
                _,
            ) => StripeResponse {
                status: 500,
                body: json!({ "error": { "message": "Search unavailable" } }),
            },
            (
                CustomerTransportMode::SearchFailsListPaginatesToUserCustomer,
                "/v1/customers",
                "GET",
            ) => {
                if request.body.contains("starting_after=") {
                    StripeResponse {
                        status: 200,
                        body: json!({
                            "object": "list",
                            "has_more": false,
                            "data": [{
                                "id": "cus_list_user_page2",
                                "object": "customer",
                                "metadata": { "userId": "user_1", "customerType": "user" }
                            }]
                        }),
                    }
                } else {
                    StripeResponse {
                        status: 200,
                        body: json!({
                            "object": "list",
                            "has_more": true,
                            "data": [{
                                "id": "cus_foreign_user",
                                "object": "customer",
                                "email": "ada@example.com",
                                "metadata": { "userId": "user_2", "customerType": "user" }
                            }]
                        }),
                    }
                }
            }
            (
                CustomerTransportMode::SearchFailsListPaginatesToOrganizationCustomer,
                "/v1/customers/search",
                _,
            ) => StripeResponse {
                status: 500,
                body: json!({ "error": { "message": "Search unavailable" } }),
            },
            (
                CustomerTransportMode::SearchFailsListPaginatesToOrganizationCustomer,
                "/v1/customers",
                "GET",
            ) => {
                if request.body.contains("starting_after=") {
                    StripeResponse {
                        status: 200,
                        body: json!({
                            "object": "list",
                            "has_more": false,
                            "data": [{
                                "id": "cus_org_page2",
                                "object": "customer",
                                "metadata": {
                                    "organizationId": "org_1",
                                    "customerType": "organization"
                                }
                            }]
                        }),
                    }
                } else {
                    StripeResponse {
                        status: 200,
                        body: json!({
                            "object": "list",
                            "has_more": true,
                            "data": [{
                                "id": "cus_unrelated",
                                "object": "customer",
                                "metadata": {
                                    "organizationId": "org_other",
                                    "customerType": "organization"
                                }
                            }]
                        }),
                    }
                }
            }
            (_, "/v1/customers", "GET") => StripeResponse {
                status: 200,
                body: json!({ "object": "list", "data": [] }),
            },
            (CustomerTransportMode::CreateCustomerFails, "/v1/customers", "POST") => {
                StripeResponse {
                    status: 400,
                    body: json!({ "error": { "message": "create failed" } }),
                }
            }
            (_, "/v1/customers", _) => StripeResponse {
                status: 200,
                body: json!({ "id": "cus_created", "object": "customer" }),
            },
            (
                CustomerTransportMode::ExistingCustomerEmailDiffers,
                "/v1/customers/cus_existing",
                "GET",
            ) => StripeResponse {
                status: 200,
                body: json!({
                    "id": "cus_existing",
                    "object": "customer",
                    "email": "old@example.com"
                }),
            },
            (
                CustomerTransportMode::ExistingCustomerEmailDiffers,
                "/v1/customers/cus_existing",
                "POST",
            ) => StripeResponse {
                status: 200,
                body: json!({
                    "id": "cus_existing",
                    "object": "customer",
                    "email": "new@example.com"
                }),
            },
            (CustomerTransportMode::CheckoutSessionDeclined, "/v1/checkout/sessions", "POST") => {
                StripeResponse {
                    status: 400,
                    body: json!({
                        "error": {
                            "message": "Your card was declined.",
                            "code": "card_declined"
                        }
                    }),
                }
            }
            (_, "/v1/checkout/sessions", _) => StripeResponse {
                status: 200,
                body: json!({
                    "id": "cs_test_123",
                    "object": "checkout.session",
                    "url": "https://checkout.stripe.test/session"
                }),
            },
            _ => StripeResponse {
                status: 200,
                body: json!({ "id": "ok" }),
            },
        };
        if let Err(error) = self
            .requests
            .lock()
            .map(|mut requests| requests.push(request))
        {
            let message = error.to_string();
            return Box::pin(async move {
                Err(rustauth_stripe::stripe_api::StripeApiError::Transport(
                    message,
                ))
            });
        }
        Box::pin(async move { Ok(response) })
    }
}

#[tokio::test]
async fn upgrade_creates_and_persists_user_customer_before_checkout(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::default());
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    )
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/customers/search"));
    let create_customer = requests
        .iter()
        .find(|request| request.method == "POST" && request.path == "/v1/customers")
        .ok_or("create customer request")?;
    assert!(create_customer.body.contains("email=ada%40example.com"));
    assert!(create_customer.body.contains("metadata%5BuserId%5D=user_1"));
    assert!(create_customer
        .body
        .contains("metadata%5BcustomerType%5D=user"));
    let checkout = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout.body.contains("customer=cus_created"));
    assert!(!checkout.body.contains("customer_email="));
    let stored_user = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String("user_1".to_owned()))),
        )
        .await?
        .ok_or("stored user")?;
    assert_eq!(
        stored_user.get("stripe_customer_id"),
        Some(&DbValue::String("cus_created".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn customer_create_params_merge_safely_and_call_hook(
) -> Result<(), Box<dyn std::error::Error>> {
    let hook_calls = Arc::new(AtomicUsize::new(0));
    let hook_calls_for_options = Arc::clone(&hook_calls);
    let transport = Arc::new(CustomerTransport::default());
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .get_customer_create_params(|input, _| {
            Box::pin(async move {
                assert_eq!(input.user.id, "user_1");
                Ok(json!({
                    "email": "evil@example.com",
                    "phone": "+1234567890",
                    "address": { "country": "US" },
                    "metadata": {
                        "customField": "customValue",
                        "userId": "attacker",
                        "customerType": "organization",
                        "__proto__": "polluted",
                        "constructor": "polluted"
                    }
                }))
            })
        })
        .on_customer_create(move |input, context| {
            let hook_calls = Arc::clone(&hook_calls_for_options);
            Box::pin(async move {
                assert_eq!(input.user.id, "user_1");
                assert_eq!(input.stripe_customer["id"], "cus_created");
                assert_eq!(context.base_url.as_deref(), Some("http://localhost:3000"));
                hook_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        })
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    )
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    let requests = transport.requests()?;
    let create_customer = requests
        .iter()
        .find(|request| request.method == "POST" && request.path == "/v1/customers")
        .ok_or("create customer request")?;
    assert!(create_customer.body.contains("email=ada%40example.com"));
    assert!(!create_customer.body.contains("evil%40example.com"));
    assert!(create_customer.body.contains("phone=%2B1234567890"));
    assert!(create_customer.body.contains("address%5Bcountry%5D=US"));
    assert!(create_customer.body.contains("metadata%5BuserId%5D=user_1"));
    assert!(create_customer
        .body
        .contains("metadata%5BcustomerType%5D=user"));
    assert!(create_customer
        .body
        .contains("metadata%5BcustomField%5D=customValue"));
    assert!(!create_customer.body.contains("__proto__"));
    assert!(!create_customer.body.contains("constructor"));
    Ok(())
}

#[tokio::test]
async fn upgrade_reuses_customer_found_by_search() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::SearchFindsUserCustomer,
    ));
    let (response, adapter, requests) = upgrade_with_transport(Arc::clone(&transport)).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    let checkout = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout.body.contains("customer=cus_search_user"));
    assert_user_customer(&adapter, "cus_search_user").await?;
    Ok(())
}

#[tokio::test]
async fn upgrade_reuses_dashboard_customer_found_by_email_search(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::SearchFindsDashboardCustomer,
    ));
    let (response, adapter, requests) = upgrade_with_transport(transport.clone()).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_user_customer(&adapter, "cus_dashboard").await?;
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/customers/search"
            && request.body.contains("email%3A%22ada%40example.com%22")
            && request
                .body
                .contains("-metadata%5B%22customerType%22%5D%3A%22organization%22")));
    assert!(!requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    assert!(requests.iter().any(|request| {
        request.path == "/v1/checkout/sessions" && request.body.contains("customer=cus_dashboard")
    }));
    Ok(())
}

#[tokio::test]
async fn upgrade_refuses_foreign_user_customer_and_creates_new(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::SearchFindsForeignUserCustomer,
    ));
    let (response, adapter, requests) = upgrade_with_transport(Arc::clone(&transport)).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    let checkout = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout.body.contains("customer=cus_created"));
    assert!(!checkout.body.contains("cus_foreign_user"));
    assert_user_customer(&adapter, "cus_created").await?;
    Ok(())
}

#[tokio::test]
async fn upgrade_skips_foreign_user_customer_and_reuses_dashboard(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::SearchFindsForeignThenDashboardCustomer,
    ));
    let (response, adapter, requests) = upgrade_with_transport(Arc::clone(&transport)).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let search = requests
        .iter()
        .find(|request| request.path == "/v1/customers/search")
        .ok_or("search request")?;
    assert!(search.body.split('&').any(|pair| pair == "limit=100"));
    assert!(!search.body.split('&').any(|pair| pair == "limit=1"));
    assert!(!requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    let checkout = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout.body.contains("customer=cus_dashboard"));
    assert!(!checkout.body.contains("cus_foreign_user"));
    assert_user_customer(&adapter, "cus_dashboard").await?;
    Ok(())
}

#[tokio::test]
async fn linked_existing_customer_invokes_customer_create_hook(
) -> Result<(), Box<dyn std::error::Error>> {
    let hook_calls = Arc::new(AtomicUsize::new(0));
    let hook_calls_for_options = Arc::clone(&hook_calls);
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::SearchFindsUserCustomer,
    ));
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .on_customer_create(move |input, _| {
            let hook_calls = Arc::clone(&hook_calls_for_options);
            Box::pin(async move {
                assert_eq!(input.user.id, "user_1");
                assert_eq!(input.stripe_customer["id"], "cus_search_user");
                hook_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        })
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    )
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
    let requests = transport.requests()?;
    assert!(!requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    Ok(())
}

#[tokio::test]
async fn upgrade_falls_back_to_paginated_customer_list() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::SearchFailsListPaginatesToUserCustomer,
    ));
    let (response, adapter, requests) = upgrade_with_transport(Arc::clone(&transport)).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let list_requests: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "GET" && request.path == "/v1/customers")
        .collect();
    assert_eq!(list_requests.len(), 2);
    assert!(!list_requests[0].body.contains("starting_after="));
    assert!(list_requests[1]
        .body
        .contains("starting_after=cus_foreign_user"));
    assert!(!requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    let checkout = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout.body.contains("customer=cus_list_user_page2"));
    assert_user_customer(&adapter, "cus_list_user_page2").await?;
    Ok(())
}

#[tokio::test]
async fn upgrade_falls_back_to_customer_list_and_ignores_org_customer(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::SearchFailsListFindsUserCustomer,
    ));
    let (response, adapter, requests) = upgrade_with_transport(Arc::clone(&transport)).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(requests
        .iter()
        .any(|request| request.method == "GET" && request.path == "/v1/customers"));
    assert!(!requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    let checkout = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout.body.contains("customer=cus_list_user"));
    assert_user_customer(&adapter, "cus_list_user").await?;
    Ok(())
}

#[tokio::test]
async fn upgrade_maps_stripe_customer_create_failure_to_plugin_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::CreateCustomerFails,
    ));
    let (response, _adapter, requests) = upgrade_with_transport(Arc::clone(&transport)).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_error_code(&response, "UNABLE_TO_CREATE_CUSTOMER")?;
    assert!(requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    Ok(())
}

#[tokio::test]
async fn upgrade_maps_customer_create_params_failure_to_plugin_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::default());
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .get_customer_create_params(|_, _| {
            Box::pin(async { Err(RustAuthError::Api("callback failed".to_owned())) })
        })
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    )
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_error_code(&response, "UNABLE_TO_CREATE_CUSTOMER")?;
    Ok(())
}

#[tokio::test]
async fn upgrade_creates_and_persists_organization_customer_before_checkout(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::default());
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
                .authorize_reference(|input, _| {
                    Box::pin(async move {
                        Ok(input.reference_id == "org_1"
                            && input.action
                                == rustauth_stripe::options::AuthorizeReferenceAction::UpgradeSubscription)
                    })
                }),
        ),
    ).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .data("slug", DbValue::String("acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/customers/search"));
    let create_customer = requests
        .iter()
        .find(|request| request.method == "POST" && request.path == "/v1/customers")
        .ok_or("create customer request")?;
    assert!(create_customer.body.contains("name=Acme"));
    assert!(create_customer
        .body
        .contains("metadata%5BorganizationId%5D=org_1"));
    assert!(create_customer
        .body
        .contains("metadata%5BcustomerType%5D=organization"));
    assert!(!create_customer.body.contains("metadata%5BuserId%5D"));
    let checkout = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout.body.contains("customer=cus_created"));
    let stored_org = adapter
        .find_one(
            FindOne::new("organization")
                .where_clause(Where::new("id", DbValue::String("org_1".to_owned()))),
        )
        .await?
        .ok_or("stored organization")?;
    assert_eq!(
        stored_org.get("stripe_customer_id"),
        Some(&DbValue::String("cus_created".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn organization_upgrade_maps_customer_create_failure_to_plugin_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::CreateCustomerFails,
    ));
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
                .authorize_reference(|input, _| {
                    Box::pin(async move { Ok(input.reference_id == "org_1") })
                }),
        ),
    )
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .data("slug", DbValue::String("acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_error_code(&response, "UNABLE_TO_CREATE_CUSTOMER")?;
    Ok(())
}

#[tokio::test]
async fn organization_upgrade_maps_customer_create_params_failure_to_plugin_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::default());
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .organization(
            OrganizationStripeOptions::enabled().get_customer_create_params(|_, _| {
                Box::pin(async { Err(RustAuthError::Api("org callback failed".to_owned())) })
            }),
        )
        .subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
                .authorize_reference(|input, _| {
                    Box::pin(async move { Ok(input.reference_id == "org_1") })
                }),
        ),
    )
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .data("slug", DbValue::String("acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_error_code(&response, "UNABLE_TO_CREATE_CUSTOMER")?;
    assert!(!transport
        .requests()?
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    Ok(())
}

#[tokio::test]
async fn signup_and_upgrade_call_customers_create_only_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::default());
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .create_customer_on_sign_up(true)
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    )
    .unwrap();
    let adapter = MemoryAdapter::new();
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        RustAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            base_url: Some("http://localhost:3000".to_owned()),
            plugins: vec![plugin.clone()],
            ..RustAuthOptions::default()
        },
        adapter_arc,
    )?;
    let hooked_adapter = context.adapter().ok_or("context adapter")?;
    DbUserStore::new(hooked_adapter.as_ref())
        .create_user(
            CreateUserInput::new("Ada Lovelace", "ada@example.com")
                .id("user_1")
                .email_verified(true),
        )
        .await?;

    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let session = DbSessionStore::new(&adapter)
        .create_session(
            CreateSessionInput::new("user_1", OffsetDateTime::now_utc() + Duration::days(7))
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
    let cookie_header = format!("{}={}", session_cookie.name, session_cookie.value);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;
    let response = (endpoint.handler)(&context, request).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let create_customer_calls = transport
        .requests()?
        .iter()
        .filter(|request| request.method == "POST" && request.path == "/v1/customers")
        .count();
    assert_eq!(create_customer_calls, 1);
    Ok(())
}

#[tokio::test]
async fn subscription_upgrade_checkout_error_returns_stripe_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::CheckoutSessionDeclined,
    ));
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    )
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_error_code(&response, "card_declined")?;
    Ok(())
}

#[tokio::test]
async fn create_customer_on_sign_up_creates_and_links_user_customer(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::default());
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .create_customer_on_sign_up(true),
    )
    .unwrap();
    let adapter = MemoryAdapter::new();
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        RustAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![plugin],
            ..RustAuthOptions::default()
        },
        adapter_arc,
    )?;
    let hooked_adapter = context.adapter().ok_or("context adapter")?;

    DbUserStore::new(hooked_adapter.as_ref())
        .create_user(
            CreateUserInput::new("Ada Lovelace", "ada@example.com")
                .id("user_1")
                .email_verified(true),
        )
        .await?;

    let requests = transport.requests()?;
    assert!(requests
        .iter()
        .any(|request| request.path == "/v1/customers/search"));
    assert!(requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    assert_user_customer(&adapter, "cus_created").await?;
    Ok(())
}

#[tokio::test]
async fn organization_upgrade_falls_back_to_paginated_customer_list(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::SearchFailsListPaginatesToOrganizationCustomer,
    ));
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(
            SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
                .authorize_reference(|input, _| {
                    Box::pin(async move {
                        Ok(input.reference_id == "org_1"
                            && input.action
                                == rustauth_stripe::options::AuthorizeReferenceAction::UpgradeSubscription)
                    })
                }),
        ),
    ).unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .data("slug", DbValue::String("acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(
            br#"{"customerType":"organization","referenceId":"org_1","plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#
                .to_vec(),
        )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let requests = transport.requests()?;
    let list_requests: Vec<_> = requests
        .iter()
        .filter(|request| request.method == "GET" && request.path == "/v1/customers")
        .collect();
    assert_eq!(list_requests.len(), 2);
    assert!(!requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    let checkout = requests
        .iter()
        .find(|request| request.path == "/v1/checkout/sessions")
        .ok_or("checkout request")?;
    assert!(checkout.body.contains("customer=cus_org_page2"));
    let stored_org = adapter
        .find_one(
            FindOne::new("organization")
                .where_clause(Where::new("id", DbValue::String("org_1".to_owned()))),
        )
        .await?
        .ok_or("stored organization")?;
    assert_eq!(
        stored_org.get("stripe_customer_id"),
        Some(&DbValue::String("cus_org_page2".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn create_customer_on_sign_up_reuses_list_fallback_customer(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::SearchFailsListFindsUserCustomer,
    ));
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .create_customer_on_sign_up(true),
    )
    .unwrap();
    let adapter = MemoryAdapter::new();
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        RustAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![plugin],
            ..RustAuthOptions::default()
        },
        adapter_arc,
    )?;
    let hooked_adapter = context.adapter().ok_or("context adapter")?;

    DbUserStore::new(hooked_adapter.as_ref())
        .create_user(
            CreateUserInput::new("Ada Lovelace", "ada@example.com")
                .id("user_1")
                .email_verified(true),
        )
        .await?;

    let requests = transport.requests()?;
    assert!(requests
        .iter()
        .any(|request| request.method == "GET" && request.path == "/v1/customers"));
    assert!(!requests
        .iter()
        .any(|request| request.method == "POST" && request.path == "/v1/customers"));
    assert_user_customer(&adapter, "cus_list_user").await?;
    Ok(())
}

#[tokio::test]
async fn user_email_update_syncs_existing_stripe_customer() -> Result<(), Box<dyn std::error::Error>>
{
    let transport = Arc::new(CustomerTransport::new(
        CustomerTransportMode::ExistingCustomerEmailDiffers,
    ));
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(StripeOptions::new(
        StripeClient::with_transport("sk_test", client_transport),
        "whsec_test",
    ))
    .unwrap();
    let adapter = MemoryAdapter::new();
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        RustAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![plugin],
            ..RustAuthOptions::default()
        },
        adapter_arc,
    )?;
    let mut additional_fields = DbRecord::new();
    additional_fields.insert(
        "stripe_customer_id".to_owned(),
        DbValue::String("cus_existing".to_owned()),
    );
    let hooked_adapter = context.adapter().ok_or("context adapter")?;
    let users = DbUserStore::new(hooked_adapter.as_ref());
    users
        .create_user(
            CreateUserInput::new("Ada Lovelace", "ada@example.com")
                .id("user_1")
                .email_verified(true)
                .additional_fields(additional_fields),
        )
        .await?;

    users
        .update_user_email("user_1", "new@example.com", true)
        .await?;

    let requests = transport.requests()?;
    assert!(requests.iter().any(|request| {
        request.method == "GET" && request.path == "/v1/customers/cus_existing"
    }));
    let update_request = requests
        .iter()
        .find(|request| request.method == "POST" && request.path == "/v1/customers/cus_existing")
        .ok_or("customer update request")?;
    assert!(update_request.body.contains("email=new%40example.com"));
    Ok(())
}

async fn upgrade_with_transport(
    transport: Arc<CustomerTransport>,
) -> Result<(http::Response<Vec<u8>>, MemoryAdapter, Vec<StripeRequest>), Box<dyn std::error::Error>>
{
    let client_transport: Arc<dyn StripeTransport> = transport.clone();
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport("sk_test", client_transport),
            "whsec_test",
        )
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    )
    .unwrap();
    let endpoint = plugin
        .endpoints
        .iter()
        .find(|endpoint| endpoint.path == "/subscription/upgrade")
        .ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/subscription/upgrade")
        .header("content-type", "application/json")
        .header("cookie", cookie_header)
        .body(br#"{"plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#.to_vec())?;
    let response = (endpoint.handler)(&context, request).await?;
    let requests = transport.requests()?;
    Ok((response, adapter, requests))
}

async fn assert_user_customer(
    adapter: &MemoryAdapter,
    customer_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let stored_user = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String("user_1".to_owned()))),
        )
        .await?
        .ok_or("stored user")?;
    assert_eq!(
        stored_user.get("stripe_customer_id"),
        Some(&DbValue::String(customer_id.to_owned()))
    );
    Ok(())
}

fn assert_error_code(
    response: &http::Response<Vec<u8>>,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], expected);
    Ok(())
}

async fn authenticated_context(
) -> Result<(AuthContext, MemoryAdapter, String), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let adapter_arc: Arc<dyn DbAdapter> = Arc::new(adapter.clone());
    let context = create_auth_context_with_adapter(
        RustAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            base_url: Some("http://localhost:3000".to_owned()),
            ..RustAuthOptions::default()
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
