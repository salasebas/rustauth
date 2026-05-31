use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{
    Create, DbAdapter, DbField, DbFieldType, DbTable, DbValue, Delete, DeleteMany, MemoryAdapter,
    Update, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
use openauth_core::plugin::{AuthPlugin, PluginSchemaContribution};
use openauth_stripe::options::{
    OrganizationStripeOptions, StripeOptions, StripePlan, SubscriptionOptions,
};
use openauth_stripe::stripe;
use openauth_stripe::stripe_api::{
    StripeClient, StripeRequest, StripeResponse, StripeTransport, StripeTransportFuture,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct OrganizationTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl OrganizationTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for OrganizationTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let body = match request.path.as_str() {
            "/v1/subscriptions/stripe_sub_team" if request.method == "GET" => json!({
                "id": "stripe_sub_team",
                "object": "subscription",
                "status": "active",
                "items": {
                    "data": [
                        {
                            "id": "si_base",
                            "price": {
                                "id": "price_team",
                                "object": "price",
                                "recurring": { "interval": "month", "usage_type": "licensed" }
                            },
                            "quantity": 1
                        },
                        {
                            "id": "si_seats",
                            "price": {
                                "id": "price_team_seat",
                                "object": "price",
                                "recurring": { "interval": "month", "usage_type": "licensed" }
                            },
                            "quantity": 1
                        }
                    ]
                }
            }),
            _ => json!({ "id": "cus_org", "object": "customer" }),
        };
        if let Err(error) = self
            .requests
            .lock()
            .map(|mut requests| requests.push(request))
        {
            let message = error.to_string();
            return Box::pin(async move {
                Err(openauth_stripe::stripe_api::StripeApiError::Transport(
                    message,
                ))
            });
        }
        Box::pin(async { Ok(StripeResponse { status: 200, body }) })
    }
}

#[derive(Default)]
struct MissingSeatItemTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl MissingSeatItemTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for MissingSeatItemTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let body = match request.path.as_str() {
            "/v1/subscriptions/stripe_sub_team" if request.method == "GET" => json!({
                "id": "stripe_sub_team",
                "object": "subscription",
                "status": "active",
                "items": {
                    "data": [{
                        "id": "si_base",
                        "price": {
                            "id": "price_team",
                            "object": "price",
                            "recurring": { "interval": "month", "usage_type": "licensed" }
                        },
                        "quantity": 1
                    }]
                }
            }),
            _ => json!({ "id": "ok", "object": "subscription" }),
        };
        if let Err(error) = self
            .requests
            .lock()
            .map(|mut requests| requests.push(request))
        {
            let message = error.to_string();
            return Box::pin(async move {
                Err(openauth_stripe::stripe_api::StripeApiError::Transport(
                    message,
                ))
            });
        }
        Box::pin(async { Ok(StripeResponse { status: 200, body }) })
    }
}

#[tokio::test]
async fn active_subscription_blocks_organization_delete() -> Result<(), Box<dyn std::error::Error>>
{
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test")
            .organization(OrganizationStripeOptions::enabled())
            .subscription(SubscriptionOptions::enabled(vec![
                StripePlan::new("pro").price_id("price_pro")
            ])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_1".to_owned()))
                .data("reference_id", DbValue::String("org_1".to_owned()))
                .data("status", DbValue::String("active".to_owned()))
                .force_allow_id(),
        )
        .await?;

    let result = adapter
        .delete(
            Delete::new("organization")
                .where_clause(Where::new("id", DbValue::String("org_1".to_owned()))),
        )
        .await;

    assert_eq!(
        result,
        Err(OpenAuthError::Api(
            "Cannot delete organization with active subscription".to_owned()
        ))
    );
    Ok(())
}

#[tokio::test]
async fn organization_delete_allowed_without_active_subscription(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test")
            .organization(OrganizationStripeOptions::enabled())
            .subscription(SubscriptionOptions::enabled(vec![
                StripePlan::new("pro").price_id("price_pro")
            ])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_1".to_owned()))
                .data("reference_id", DbValue::String("org_1".to_owned()))
                .data("status", DbValue::String("canceled".to_owned()))
                .force_allow_id(),
        )
        .await?;

    adapter
        .delete(
            Delete::new("organization")
                .where_clause(Where::new("id", DbValue::String("org_1".to_owned()))),
        )
        .await?;

    Ok(())
}

#[tokio::test]
async fn active_subscription_blocks_bulk_organization_delete(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = stripe(
        StripeOptions::new(StripeClient::new("sk_test"), "whsec_test")
            .organization(OrganizationStripeOptions::enabled())
            .subscription(SubscriptionOptions::enabled(vec![
                StripePlan::new("pro").price_id("price_pro")
            ])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    for organization_id in ["org_1", "org_2"] {
        adapter
            .create(
                Create::new("organization")
                    .data("id", DbValue::String(organization_id.to_owned()))
                    .data("name", DbValue::String("Acme".to_owned()))
                    .force_allow_id(),
            )
            .await?;
    }
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_1".to_owned()))
                .data("reference_id", DbValue::String("org_2".to_owned()))
                .data("status", DbValue::String("trialing".to_owned()))
                .force_allow_id(),
        )
        .await?;

    let result = adapter
        .delete_many(
            DeleteMany::new("organization").where_clause(
                Where::new(
                    "id",
                    DbValue::StringArray(vec!["org_1".to_owned(), "org_2".to_owned()]),
                )
                .operator(WhereOperator::In),
            ),
        )
        .await;

    assert_eq!(
        result,
        Err(OpenAuthError::Api(
            "Cannot delete organization with active subscription".to_owned()
        ))
    );
    Ok(())
}

#[tokio::test]
async fn organization_name_update_syncs_stripe_customer() -> Result<(), Box<dyn std::error::Error>>
{
    let transport = Arc::new(OrganizationTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(SubscriptionOptions::enabled(vec![
            StripePlan::new("pro").price_id("price_pro")
        ])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Old Acme".to_owned()))
                .data("stripe_customer_id", DbValue::String("cus_org".to_owned()))
                .force_allow_id(),
        )
        .await?;

    adapter
        .update(
            Update::new("organization")
                .where_clause(Where::new("id", DbValue::String("org_1".to_owned())))
                .data("name", DbValue::String("New Acme".to_owned())),
        )
        .await?;

    let requests = transport.requests()?;
    let update_request = requests
        .iter()
        .find(|request| request.method == "POST" && request.path == "/v1/customers/cus_org")
        .ok_or("customer update request")?;
    assert!(update_request.body.contains("name=New+Acme"));
    Ok(())
}

#[tokio::test]
async fn member_create_syncs_organization_subscription_seats(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(OrganizationTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("team")
            .price_id("price_team")
            .seat_price_id("price_team_seat")
            .proration_behavior("always_invoice")])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_team".to_owned()))
                .data("reference_id", DbValue::String("org_1".to_owned()))
                .data("status", DbValue::String("active".to_owned()))
                .data("plan", DbValue::String("team".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_team".to_owned()),
                )
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String("mem_1".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .force_allow_id(),
        )
        .await?;

    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String("mem_2".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("user_id", DbValue::String("user_2".to_owned()))
                .force_allow_id(),
        )
        .await?;

    let requests = transport.requests()?;
    assert!(requests.iter().any(|request| {
        request.method == "GET" && request.path == "/v1/subscriptions/stripe_sub_team"
    }));
    let update_request = requests
        .iter()
        .find(|request| {
            request.method == "POST"
                && request.path == "/v1/subscriptions/stripe_sub_team"
                && request.body.contains("items%5B0%5D%5Bquantity%5D=2")
        })
        .ok_or("subscription update request")?;
    assert!(update_request
        .body
        .contains("items%5B0%5D%5Bid%5D=si_seats"));
    assert!(update_request.body.contains("items%5B0%5D%5Bquantity%5D=2"));
    assert!(update_request
        .body
        .contains("proration_behavior=always_invoice"));
    Ok(())
}

#[tokio::test]
async fn member_create_persists_synced_organization_subscription_seats(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(OrganizationTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("team")
            .price_id("price_team")
            .seat_price_id("price_team_seat")])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String("mem_1".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_team".to_owned()))
                .data("reference_id", DbValue::String("org_1".to_owned()))
                .data("status", DbValue::String("active".to_owned()))
                .data("plan", DbValue::String("team".to_owned()))
                .data("seats", DbValue::Number(1))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_team".to_owned()),
                )
                .force_allow_id(),
        )
        .await?;

    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String("mem_2".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("user_id", DbValue::String("user_2".to_owned()))
                .force_allow_id(),
        )
        .await?;

    let records = adapter
        .find_many(openauth_core::db::FindMany::new("subscription"))
        .await?;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_team".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(2)));
    Ok(())
}

#[tokio::test]
async fn member_create_adds_missing_stripe_seat_item() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(MissingSeatItemTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("team")
            .price_id("price_team")
            .seat_price_id("price_team_seat")])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String("mem_1".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_team".to_owned()))
                .data("reference_id", DbValue::String("org_1".to_owned()))
                .data("status", DbValue::String("active".to_owned()))
                .data("plan", DbValue::String("team".to_owned()))
                .data("seats", DbValue::Number(1))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_team".to_owned()),
                )
                .force_allow_id(),
        )
        .await?;

    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String("mem_2".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("user_id", DbValue::String("user_2".to_owned()))
                .force_allow_id(),
        )
        .await?;

    let requests = transport.requests()?;
    let update_request = requests
        .iter()
        .find(|request| {
            request.method == "POST" && request.path == "/v1/subscriptions/stripe_sub_team"
        })
        .ok_or("subscription update request")?;
    assert!(update_request
        .body
        .contains("items%5B0%5D%5Bprice%5D=price_team_seat"));
    assert!(update_request.body.contains("items%5B0%5D%5Bquantity%5D=2"));
    let records = adapter
        .find_many(openauth_core::db::FindMany::new("subscription"))
        .await?;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_team".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(2)));
    Ok(())
}

#[tokio::test]
async fn member_delete_syncs_organization_subscription_seats(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(OrganizationTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("team")
            .price_id("price_team")
            .seat_price_id("price_team_seat")])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_team".to_owned()))
                .data("reference_id", DbValue::String("org_1".to_owned()))
                .data("status", DbValue::String("active".to_owned()))
                .data("plan", DbValue::String("team".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_team".to_owned()),
                )
                .force_allow_id(),
        )
        .await?;
    for member_id in ["mem_1", "mem_2"] {
        adapter
            .create(
                Create::new("member")
                    .data("id", DbValue::String(member_id.to_owned()))
                    .data("organization_id", DbValue::String("org_1".to_owned()))
                    .data("user_id", DbValue::String(format!("user_{member_id}")))
                    .force_allow_id(),
            )
            .await?;
    }

    adapter
        .delete(
            Delete::new("member")
                .where_clause(Where::new("id", DbValue::String("mem_2".to_owned()))),
        )
        .await?;

    let requests = transport.requests()?;
    let update_request = requests
        .iter()
        .rev()
        .find(|request| {
            request.method == "POST" && request.path == "/v1/subscriptions/stripe_sub_team"
        })
        .ok_or("subscription update request")?;
    assert!(update_request.body.contains("items%5B0%5D%5Bquantity%5D=1"));
    assert!(update_request
        .body
        .contains("proration_behavior=create_prorations"));
    Ok(())
}

#[tokio::test]
async fn invitation_acceptance_syncs_organization_subscription_seats(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(OrganizationTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("team")
            .price_id("price_team")
            .seat_price_id("price_team_seat")])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_team".to_owned()))
                .data("reference_id", DbValue::String("org_1".to_owned()))
                .data("status", DbValue::String("active".to_owned()))
                .data("plan", DbValue::String("team".to_owned()))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_team".to_owned()),
                )
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String("mem_1".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("invitation")
                .data("id", DbValue::String("inv_1".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("email", DbValue::String("user2@example.com".to_owned()))
                .data("status", DbValue::String("pending".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let request_count_before_accept = transport.requests()?.len();

    adapter
        .update(
            Update::new("invitation")
                .where_clause(Where::new("id", DbValue::String("inv_1".to_owned())))
                .data("status", DbValue::String("accepted".to_owned())),
        )
        .await?;

    let requests = transport.requests()?;
    let update_request = requests[request_count_before_accept..]
        .iter()
        .find(|request| {
            request.method == "POST" && request.path == "/v1/subscriptions/stripe_sub_team"
        })
        .ok_or("subscription update request after invitation acceptance")?;
    assert!(update_request
        .body
        .contains("items%5B0%5D%5Bid%5D=si_seats"));
    assert!(update_request.body.contains("items%5B0%5D%5Bquantity%5D=1"));
    Ok(())
}

#[derive(Default)]
struct BulkDeleteTransport {
    requests: Mutex<Vec<StripeRequest>>,
}

impl BulkDeleteTransport {
    fn requests(&self) -> Result<Vec<StripeRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|error| error.to_string())
    }
}

impl StripeTransport for BulkDeleteTransport {
    fn send<'a>(&'a self, request: StripeRequest) -> StripeTransportFuture<'a> {
        let body = if request.method == "GET" && request.path.starts_with("/v1/subscriptions/") {
            json!({
                "id": request.path.trim_start_matches("/v1/subscriptions/"),
                "object": "subscription",
                "status": "active",
                "items": {
                    "data": [{
                        "id": "si_seats",
                        "price": {
                            "id": "price_team_seat",
                            "object": "price",
                            "recurring": { "interval": "month", "usage_type": "licensed" }
                        },
                        "quantity": 2
                    }]
                }
            })
        } else {
            json!({ "id": "ok", "object": "subscription" })
        };
        if let Err(error) = self
            .requests
            .lock()
            .map(|mut requests| requests.push(request))
        {
            let message = error.to_string();
            return Box::pin(async move {
                Err(openauth_stripe::stripe_api::StripeApiError::Transport(
                    message,
                ))
            });
        }
        Box::pin(async { Ok(StripeResponse { status: 200, body }) })
    }
}

#[tokio::test]
async fn last_member_delete_clamps_organization_seats_to_one(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(OrganizationTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("team")
            .price_id("price_team")
            .seat_price_id("price_team_seat")])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("subscription")
                .data("id", DbValue::String("sub_team".to_owned()))
                .data("reference_id", DbValue::String("org_1".to_owned()))
                .data("status", DbValue::String("active".to_owned()))
                .data("plan", DbValue::String("team".to_owned()))
                .data("seats", DbValue::Number(1))
                .data(
                    "stripe_subscription_id",
                    DbValue::String("stripe_sub_team".to_owned()),
                )
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("member")
                .data("id", DbValue::String("mem_1".to_owned()))
                .data("organization_id", DbValue::String("org_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .force_allow_id(),
        )
        .await?;

    adapter
        .delete(
            Delete::new("member")
                .where_clause(Where::new("id", DbValue::String("mem_1".to_owned()))),
        )
        .await?;

    let requests = transport.requests()?;
    let update_request = requests
        .iter()
        .rev()
        .find(|request| {
            request.method == "POST" && request.path == "/v1/subscriptions/stripe_sub_team"
        })
        .ok_or("subscription update request")?;
    assert!(update_request.body.contains("items%5B0%5D%5Bquantity%5D=1"));
    let records = adapter
        .find_many(openauth_core::db::FindMany::new("subscription"))
        .await?;
    let subscription = records
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("sub_team".to_owned())))
        .ok_or("subscription")?;
    assert_eq!(subscription.get("seats"), Some(&DbValue::Number(1)));
    Ok(())
}

#[tokio::test]
async fn bulk_member_delete_syncs_each_organization_once() -> Result<(), Box<dyn std::error::Error>>
{
    let transport = Arc::new(BulkDeleteTransport::default());
    let plugin = stripe(
        StripeOptions::new(
            StripeClient::with_transport(
                "sk_test",
                Arc::clone(&transport) as Arc<dyn StripeTransport>,
            ),
            "whsec_test",
        )
        .organization(OrganizationStripeOptions::enabled())
        .subscription(SubscriptionOptions::enabled(vec![StripePlan::new("team")
            .price_id("price_team")
            .seat_price_id("price_team_seat")])),
    );
    let adapter = MemoryAdapter::new();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            plugins: vec![minimal_organization_plugin(), plugin],
            ..OpenAuthOptions::default()
        },
        Arc::new(adapter),
    )?;
    let adapter = context.adapter().ok_or("context adapter")?;
    for (org_id, sub_id, stripe_id) in [
        ("org_1", "sub_1", "stripe_sub_1"),
        ("org_2", "sub_2", "stripe_sub_2"),
    ] {
        adapter
            .create(
                Create::new("organization")
                    .data("id", DbValue::String(org_id.to_owned()))
                    .data("name", DbValue::String("Acme".to_owned()))
                    .force_allow_id(),
            )
            .await?;
        adapter
            .create(
                Create::new("subscription")
                    .data("id", DbValue::String(sub_id.to_owned()))
                    .data("reference_id", DbValue::String(org_id.to_owned()))
                    .data("status", DbValue::String("active".to_owned()))
                    .data("plan", DbValue::String("team".to_owned()))
                    .data(
                        "stripe_subscription_id",
                        DbValue::String(stripe_id.to_owned()),
                    )
                    .force_allow_id(),
            )
            .await?;
    }
    for (member_id, org_id) in [
        ("mem_1a", "org_1"),
        ("mem_1b", "org_1"),
        ("mem_2a", "org_2"),
        ("mem_2b", "org_2"),
    ] {
        adapter
            .create(
                Create::new("member")
                    .data("id", DbValue::String(member_id.to_owned()))
                    .data("organization_id", DbValue::String(org_id.to_owned()))
                    .data("user_id", DbValue::String(format!("user_{member_id}")))
                    .force_allow_id(),
            )
            .await?;
    }

    let requests_before_delete = transport.requests()?.len();

    adapter
        .delete_many(
            DeleteMany::new("member").where_clause(
                Where::new(
                    "organization_id",
                    DbValue::StringArray(vec!["org_1".to_owned(), "org_2".to_owned()]),
                )
                .operator(WhereOperator::In),
            ),
        )
        .await?;

    let requests = transport.requests()?;
    let count_updates = |path: &str| {
        requests[requests_before_delete..]
            .iter()
            .filter(|request| request.method == "POST" && request.path == path)
            .count()
    };
    assert_eq!(count_updates("/v1/subscriptions/stripe_sub_1"), 1);
    assert_eq!(count_updates("/v1/subscriptions/stripe_sub_2"), 1);
    Ok(())
}

fn minimal_organization_plugin() -> AuthPlugin {
    let mut fields = indexmap::IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    fields.insert("name".to_owned(), DbField::new("name", DbFieldType::String));
    let organization = PluginSchemaContribution::table(
        "organization",
        DbTable {
            name: "organizations".to_owned(),
            fields,
            order: Some(20),
        },
    );
    let mut member_fields = indexmap::IndexMap::new();
    member_fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    member_fields.insert(
        "organization_id".to_owned(),
        DbField::new("organization_id", DbFieldType::String),
    );
    member_fields.insert(
        "user_id".to_owned(),
        DbField::new("user_id", DbFieldType::String),
    );
    let member = PluginSchemaContribution::table(
        "member",
        DbTable {
            name: "members".to_owned(),
            fields: member_fields,
            order: Some(21),
        },
    );
    let mut invitation_fields = indexmap::IndexMap::new();
    invitation_fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    invitation_fields.insert(
        "organization_id".to_owned(),
        DbField::new("organization_id", DbFieldType::String),
    );
    invitation_fields.insert(
        "email".to_owned(),
        DbField::new("email", DbFieldType::String),
    );
    invitation_fields.insert(
        "status".to_owned(),
        DbField::new("status", DbFieldType::String),
    );
    let invitation = PluginSchemaContribution::table(
        "invitation",
        DbTable {
            name: "invitations".to_owned(),
            fields: invitation_fields,
            order: Some(22),
        },
    );
    AuthPlugin::new("organization")
        .with_schema(organization)
        .with_schema(member)
        .with_schema(invitation)
}
