#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::harness::{
    json_post_request, organization_stripe_options, plugin_endpoint, stripe_plugin, upgrade_request,
};

#[tokio::test]
async fn reference_user_upgrade_passes_with_explicit_own_reference_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe_plugin(Arc::clone(&transport) as Arc<dyn StripeTransport>);
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"plan":"pro","referenceId":"user_1","successUrl":"/ok","cancelUrl":"/pricing","disableRedirect":true}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn reference_user_upgrade_rejects_when_authorizer_denies(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .subscription(
        SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
            .authorize_reference(|_input, _| Box::pin(async { Ok(false) })),
    );
    let plugin = stripe(options).unwrap();
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"plan":"pro","referenceId":"user_2","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "UNAUTHORIZED");
    assert!(transport.requests()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn reference_org_upgrade_requires_authorize_reference(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport(
            "sk_test",
            Arc::clone(&transport) as Arc<dyn StripeTransport>,
        ),
        "whsec_test",
    )
    .organization(openauth_stripe::options::OrganizationStripeOptions::enabled())
    .subscription(SubscriptionOptions::enabled(vec![
        StripePlan::new("pro").price_id("price_pro")
    ]));
    let plugin = stripe(options).unwrap();
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"customerType":"organization","referenceId":"org_1","plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "AUTHORIZE_REFERENCE_REQUIRED");
    assert!(transport.requests()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn reference_org_upgrade_requires_reference_id() -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(organization_stripe_options(
        Arc::clone(&transport) as Arc<dyn StripeTransport>,
        true,
    ))
    .unwrap();
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, _adapter, cookie_header) = authenticated_context().await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"customerType":"organization","plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "ORGANIZATION_REFERENCE_ID_REQUIRED");
    assert!(transport.requests()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn reference_org_upgrade_rejects_when_authorizer_denies(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let plugin = stripe(organization_stripe_options(
        Arc::clone(&transport) as Arc<dyn StripeTransport>,
        false,
    ))
    .unwrap();
    let endpoint = plugin_endpoint(&plugin, "/subscription/upgrade").ok_or("upgrade endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .data("slug", DbValue::String("acme".to_owned()))
                .data("stripe_customer_id", DbValue::String("cus_org".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let request = upgrade_request(
        &cookie_header,
        br#"{"customerType":"organization","referenceId":"org_1","plan":"pro","successUrl":"/ok","cancelUrl":"/pricing"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "UNAUTHORIZED");
    assert!(transport.requests()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn reference_org_cancel_passes_when_authorizer_allows(
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = Arc::new(CaptureTransport::default());
    let options = StripeOptions::new(
        StripeClient::with_transport("sk_test", Arc::clone(&transport) as Arc<dyn StripeTransport>),
        "whsec_test",
    )
    .organization(openauth_stripe::options::OrganizationStripeOptions::enabled())
    .subscription(
        SubscriptionOptions::enabled(vec![StripePlan::new("pro").price_id("price_pro")])
            .authorize_reference(|input, _| {
                Box::pin(async move {
                    Ok(input.reference_id == "org_1"
                        && input.action
                            == openauth_stripe::options::AuthorizeReferenceAction::CancelSubscription)
                })
            }),
    );
    let plugin = stripe(options).unwrap();
    let endpoint = plugin_endpoint(&plugin, "/subscription/cancel").ok_or("cancel endpoint")?;
    let (context, adapter, cookie_header) = authenticated_context().await?;
    create_subscription_record(&adapter, "sub_org", "org_1", "active", Some("cus_org")).await?;
    openauth_core::db::DbAdapter::update(
        &adapter,
        openauth_core::db::Update::new("subscription")
            .where_clause(openauth_core::db::Where::new(
                "id",
                DbValue::String("sub_org".to_owned()),
            ))
            .data(
                "stripe_subscription_id",
                DbValue::String("stripe_sub_active".to_owned()),
            ),
    )
    .await?;
    adapter
        .create(
            Create::new("organization")
                .data("id", DbValue::String("org_1".to_owned()))
                .data("name", DbValue::String("Acme".to_owned()))
                .data("slug", DbValue::String("acme".to_owned()))
                .data("stripe_customer_id", DbValue::String("cus_org".to_owned()))
                .force_allow_id(),
        )
        .await?;
    let request = json_post_request(
        "/subscription/cancel",
        &cookie_header,
        br#"{"customerType":"organization","referenceId":"org_1","returnUrl":"/account"}"#,
    )?;

    let response = (endpoint.handler)(&context, request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(transport
        .requests()?
        .iter()
        .any(|request| request.path == "/v1/billing_portal/sessions"));
    Ok(())
}
