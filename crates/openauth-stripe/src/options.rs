use std::future::Future;
use std::sync::Arc;

use openauth_core::api::ApiRequest;
use openauth_core::context::AuthContext;
use openauth_core::db::{Session, User};
use openauth_core::env::logger::Logger;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginSchemaContribution;
use serde_json::json;

use crate::models::{StripeEvent, StripeSubscription, Subscription};
use crate::stripe_api::StripeClient;

#[non_exhaustive]
#[derive(Clone)]
pub struct StripeOptions {
    pub(crate) stripe_client: StripeClient,
    pub(crate) stripe_webhook_secret: String,
    pub(crate) create_customer_on_sign_up: bool,
    pub(crate) subscription: Option<SubscriptionOptions>,
    pub(crate) organization: Option<OrganizationStripeOptions>,
    pub(crate) on_event: Option<StripeEventHook>,
    pub(crate) on_customer_create: Option<CustomerCreateHook>,
    pub(crate) get_customer_create_params: Option<GetCustomerCreateParamsHook>,
    pub(crate) schema: Vec<PluginSchemaContribution>,
}

type StripeEventHook = Arc<
    dyn Fn(StripeEvent) -> crate::stripe_api::BoxFuture<'static, Result<(), OpenAuthError>>
        + Send
        + Sync,
>;
type CustomerCreateHook = Arc<
    dyn Fn(
            CustomerCreateInput,
            CustomerCreateContext,
        ) -> crate::stripe_api::BoxFuture<'static, Result<(), OpenAuthError>>
        + Send
        + Sync,
>;
type GetCustomerCreateParamsHook = Arc<
    dyn Fn(
            CustomerCreateParamsInput,
            CustomerCreateContext,
        )
            -> crate::stripe_api::BoxFuture<'static, Result<serde_json::Value, OpenAuthError>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct CustomerCreateContext {
    pub base_url: Option<String>,
    pub request_path: Option<String>,
    pub logger: Logger,
}

impl std::fmt::Debug for CustomerCreateContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CustomerCreateContext")
            .field("base_url", &self.base_url)
            .field("request_path", &self.request_path)
            .finish_non_exhaustive()
    }
}

impl CustomerCreateContext {
    pub fn from_auth_context(context: &AuthContext) -> Self {
        Self {
            base_url: Some(context.base_url.clone()),
            request_path: None,
            logger: context.logger.clone(),
        }
    }

    pub fn database_hook(request_path: Option<String>, logger: &Logger) -> Self {
        Self {
            base_url: None,
            request_path,
            logger: logger.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CustomerCreateInput {
    pub stripe_customer: serde_json::Value,
    pub user: User,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerCreateParamsInput {
    pub user: User,
}

impl StripeOptions {
    pub fn new(stripe_client: StripeClient, stripe_webhook_secret: impl Into<String>) -> Self {
        Self {
            stripe_client,
            stripe_webhook_secret: stripe_webhook_secret.into(),
            create_customer_on_sign_up: false,
            subscription: None,
            organization: None,
            on_event: None,
            on_customer_create: None,
            get_customer_create_params: None,
            schema: Vec::new(),
        }
    }

    pub fn create_customer_on_sign_up(mut self, enabled: bool) -> Self {
        self.create_customer_on_sign_up = enabled;
        self
    }

    pub fn subscription(mut self, subscription: SubscriptionOptions) -> Self {
        self.subscription = Some(subscription);
        self
    }

    pub fn organization(mut self, organization: OrganizationStripeOptions) -> Self {
        self.organization = Some(organization);
        self
    }

    pub fn schema(mut self, contribution: PluginSchemaContribution) -> Self {
        self.schema.push(contribution);
        self
    }

    pub fn on_event<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(StripeEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_event = Some(Arc::new(move |event| Box::pin(hook(event))));
        self
    }

    pub fn on_customer_create<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(CustomerCreateInput, CustomerCreateContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_customer_create = Some(Arc::new(move |input, ctx| Box::pin(hook(input, ctx))));
        self
    }

    pub fn get_customer_create_params<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(CustomerCreateParamsInput, CustomerCreateContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<serde_json::Value, OpenAuthError>> + Send + 'static,
    {
        self.get_customer_create_params =
            Some(Arc::new(move |input, ctx| Box::pin(hook(input, ctx))));
        self
    }

    pub fn to_metadata(&self) -> serde_json::Value {
        json!({
            "subscription": self.subscription.as_ref().map(|subscription| json!({
                "enabled": subscription.enabled,
                "plans": subscription.plans.iter().map(|plan| plan.name.clone()).collect::<Vec<_>>()
            })),
            "organization": self.organization.as_ref().map(|organization| json!({
                "enabled": organization.enabled
            })),
            "createCustomerOnSignUp": self.create_customer_on_sign_up
        })
    }
}

#[non_exhaustive]
#[derive(Clone)]
pub struct SubscriptionOptions {
    pub(crate) enabled: bool,
    pub(crate) plans: Arc<Vec<StripePlan>>,
    pub(crate) get_plans: Option<GetPlansHook>,
    pub(crate) require_email_verification: bool,
    pub(crate) authorize_reference: Option<AuthorizeReferenceHook>,
    pub(crate) on_subscription_complete: Option<SubscriptionLifecycleHook>,
    pub(crate) on_subscription_created: Option<SubscriptionLifecycleHook>,
    pub(crate) on_subscription_update: Option<SubscriptionUpdateHook>,
    pub(crate) on_subscription_cancel: Option<SubscriptionLifecycleHook>,
    pub(crate) on_subscription_deleted: Option<SubscriptionLifecycleHook>,
    pub(crate) get_checkout_session_params: Option<GetCheckoutSessionParamsHook>,
}

type GetPlansHook = Arc<
    dyn Fn() -> crate::stripe_api::BoxFuture<'static, Result<Vec<StripePlan>, OpenAuthError>>
        + Send
        + Sync,
>;

type AuthorizeReferenceHook = Arc<
    dyn Fn(
            AuthorizeReferenceInput,
            &AuthContext,
        ) -> crate::stripe_api::BoxFuture<'static, Result<bool, OpenAuthError>>
        + Send
        + Sync,
>;

type SubscriptionLifecycleHook = Arc<
    dyn Fn(
            SubscriptionLifecycleInput,
        ) -> crate::stripe_api::BoxFuture<'static, Result<(), OpenAuthError>>
        + Send
        + Sync,
>;

type SubscriptionUpdateHook = Arc<
    dyn Fn(
            SubscriptionUpdateInput,
        ) -> crate::stripe_api::BoxFuture<'static, Result<(), OpenAuthError>>
        + Send
        + Sync,
>;
type GetCheckoutSessionParamsHook = Arc<
    dyn Fn(
            CheckoutSessionParamsInput,
            &ApiRequest,
            &AuthContext,
        )
            -> crate::stripe_api::BoxFuture<'static, Result<serde_json::Value, OpenAuthError>>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, PartialEq)]
pub struct SubscriptionLifecycleInput {
    pub event: StripeEvent,
    pub subscription: Subscription,
    pub stripe_subscription: Option<StripeSubscription>,
    pub plan: Option<StripePlan>,
    pub cancellation_details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SubscriptionUpdateInput {
    pub event: StripeEvent,
    pub subscription: Subscription,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckoutSessionParamsInput {
    pub user: User,
    pub session: Session,
    pub plan: StripePlan,
    pub subscription: Subscription,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeReferenceInput {
    pub user_id: String,
    pub user: User,
    pub session: Session,
    pub reference_id: String,
    pub action: AuthorizeReferenceAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeReferenceAction {
    UpgradeSubscription,
    ListSubscription,
    CancelSubscription,
    RestoreSubscription,
    BillingPortal,
}

impl AuthorizeReferenceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UpgradeSubscription => "upgrade-subscription",
            Self::ListSubscription => "list-subscription",
            Self::CancelSubscription => "cancel-subscription",
            Self::RestoreSubscription => "restore-subscription",
            Self::BillingPortal => "billing-portal",
        }
    }
}

impl SubscriptionOptions {
    pub fn enabled(plans: Vec<StripePlan>) -> Self {
        Self {
            enabled: true,
            plans: Arc::new(plans),
            get_plans: None,
            require_email_verification: false,
            authorize_reference: None,
            on_subscription_complete: None,
            on_subscription_created: None,
            on_subscription_update: None,
            on_subscription_cancel: None,
            on_subscription_deleted: None,
            get_checkout_session_params: None,
        }
    }

    pub fn enabled_dynamic<F, Fut>(provider: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<StripePlan>, OpenAuthError>> + Send + 'static,
    {
        Self {
            get_plans: Some(Arc::new(move || Box::pin(provider()))),
            ..Self::enabled(Vec::new())
        }
    }

    pub fn plans_provider<F, Fut>(mut self, provider: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<StripePlan>, OpenAuthError>> + Send + 'static,
    {
        self.get_plans = Some(Arc::new(move || Box::pin(provider())));
        self
    }

    pub async fn resolve_plans(&self) -> Result<Self, OpenAuthError> {
        let Some(provider) = &self.get_plans else {
            return Ok(self.clone());
        };
        let plans = provider().await?;
        let mut resolved = self.clone();
        resolved.plans = Arc::new(plans);
        Ok(resolved)
    }

    pub fn require_email_verification(mut self, enabled: bool) -> Self {
        self.require_email_verification = enabled;
        self
    }

    pub fn authorize_reference<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(AuthorizeReferenceInput, &AuthContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, OpenAuthError>> + Send + 'static,
    {
        self.authorize_reference = Some(Arc::new(move |input, ctx| Box::pin(hook(input, ctx))));
        self
    }

    pub fn get_checkout_session_params<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(CheckoutSessionParamsInput, &ApiRequest, &AuthContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<serde_json::Value, OpenAuthError>> + Send + 'static,
    {
        self.get_checkout_session_params = Some(Arc::new(move |input, request, ctx| {
            Box::pin(hook(input, request, ctx))
        }));
        self
    }

    pub fn on_subscription_complete<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(SubscriptionLifecycleInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_subscription_complete = Some(Arc::new(move |input| Box::pin(hook(input))));
        self
    }

    pub fn on_subscription_created<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(SubscriptionLifecycleInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_subscription_created = Some(Arc::new(move |input| Box::pin(hook(input))));
        self
    }

    pub fn on_subscription_update<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(SubscriptionUpdateInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_subscription_update = Some(Arc::new(move |input| Box::pin(hook(input))));
        self
    }

    pub fn on_subscription_cancel<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(SubscriptionLifecycleInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_subscription_cancel = Some(Arc::new(move |input| Box::pin(hook(input))));
        self
    }

    pub fn on_subscription_deleted<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(SubscriptionLifecycleInput) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_subscription_deleted = Some(Arc::new(move |input| Box::pin(hook(input))));
        self
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct StripePlan {
    pub(crate) name: String,
    pub(crate) price_id: Option<String>,
    pub(crate) lookup_key: Option<String>,
    pub(crate) annual_discount_price_id: Option<String>,
    pub(crate) annual_discount_lookup_key: Option<String>,
    pub(crate) limits: Option<serde_json::Value>,
    pub(crate) group: Option<String>,
    pub(crate) seat_price_id: Option<String>,
    pub(crate) proration_behavior: Option<String>,
    pub(crate) line_items: Vec<serde_json::Value>,
    pub(crate) free_trial: Option<FreeTrialOptions>,
}

impl StripePlan {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            price_id: None,
            lookup_key: None,
            annual_discount_price_id: None,
            annual_discount_lookup_key: None,
            limits: None,
            group: None,
            seat_price_id: None,
            proration_behavior: None,
            line_items: Vec::new(),
            free_trial: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn price_id(mut self, price_id: impl Into<String>) -> Self {
        self.price_id = Some(price_id.into());
        self
    }

    pub fn lookup_key(mut self, lookup_key: impl Into<String>) -> Self {
        self.lookup_key = Some(lookup_key.into());
        self
    }

    pub fn annual_discount_price_id(mut self, price_id: impl Into<String>) -> Self {
        self.annual_discount_price_id = Some(price_id.into());
        self
    }

    pub fn annual_discount_lookup_key(mut self, lookup_key: impl Into<String>) -> Self {
        self.annual_discount_lookup_key = Some(lookup_key.into());
        self
    }

    pub fn seat_price_id(mut self, price_id: impl Into<String>) -> Self {
        self.seat_price_id = Some(price_id.into());
        self
    }

    pub fn limits(mut self, limits: serde_json::Value) -> Self {
        self.limits = Some(limits);
        self
    }

    pub fn group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    pub fn line_item(mut self, line_item: serde_json::Value) -> Self {
        self.line_items.push(line_item);
        self
    }

    pub fn proration_behavior(mut self, proration_behavior: impl Into<String>) -> Self {
        self.proration_behavior = Some(proration_behavior.into());
        self
    }

    pub fn free_trial(mut self, free_trial: FreeTrialOptions) -> Self {
        self.free_trial = Some(free_trial);
        self
    }
}

#[non_exhaustive]
#[derive(Clone)]
pub struct FreeTrialOptions {
    pub(crate) days: i64,
    pub(crate) on_trial_start: Option<TrialStartHook>,
    pub(crate) on_trial_end: Option<TrialLifecycleHook>,
    pub(crate) on_trial_expired: Option<TrialLifecycleHook>,
}

type TrialStartHook = Arc<
    dyn Fn(Subscription) -> crate::stripe_api::BoxFuture<'static, Result<(), OpenAuthError>>
        + Send
        + Sync,
>;
type TrialLifecycleHook = Arc<
    dyn Fn(
            Subscription,
            &AuthContext,
        ) -> crate::stripe_api::BoxFuture<'static, Result<(), OpenAuthError>>
        + Send
        + Sync,
>;

impl std::fmt::Debug for FreeTrialOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FreeTrialOptions")
            .field("days", &self.days)
            .finish_non_exhaustive()
    }
}

impl PartialEq for FreeTrialOptions {
    fn eq(&self, other: &Self) -> bool {
        self.days == other.days
    }
}

impl Eq for FreeTrialOptions {}

impl FreeTrialOptions {
    pub fn new(days: i64) -> Self {
        Self {
            days,
            on_trial_start: None,
            on_trial_end: None,
            on_trial_expired: None,
        }
    }

    pub fn on_trial_start<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(Subscription) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_trial_start = Some(Arc::new(move |subscription| Box::pin(hook(subscription))));
        self
    }

    pub fn on_trial_end<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(Subscription, &AuthContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_trial_end = Some(Arc::new(move |subscription, ctx| {
            Box::pin(hook(subscription, ctx))
        }));
        self
    }

    pub fn on_trial_expired<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(Subscription, &AuthContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_trial_expired = Some(Arc::new(move |subscription, ctx| {
            Box::pin(hook(subscription, ctx))
        }));
        self
    }
}

#[non_exhaustive]
#[derive(Clone)]
pub struct OrganizationStripeOptions {
    pub(crate) enabled: bool,
    pub(crate) get_customer_create_params: Option<GetOrganizationCustomerCreateParamsHook>,
    pub(crate) on_customer_create: Option<OrganizationCustomerCreateHook>,
}

type GetOrganizationCustomerCreateParamsHook = Arc<
    dyn Fn(
            OrganizationCustomerCreateParamsInput,
            CustomerCreateContext,
        )
            -> crate::stripe_api::BoxFuture<'static, Result<serde_json::Value, OpenAuthError>>
        + Send
        + Sync,
>;
type OrganizationCustomerCreateHook = Arc<
    dyn Fn(
            OrganizationCustomerCreateInput,
            CustomerCreateContext,
        ) -> crate::stripe_api::BoxFuture<'static, Result<(), OpenAuthError>>
        + Send
        + Sync,
>;

#[derive(Debug, Clone, PartialEq)]
pub struct OrganizationCustomerCreateParamsInput {
    pub organization: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OrganizationCustomerCreateInput {
    pub stripe_customer: serde_json::Value,
    pub organization: serde_json::Value,
}

impl OrganizationStripeOptions {
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            get_customer_create_params: None,
            on_customer_create: None,
        }
    }

    pub fn get_customer_create_params<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(OrganizationCustomerCreateParamsInput, CustomerCreateContext) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: Future<Output = Result<serde_json::Value, OpenAuthError>> + Send + 'static,
    {
        self.get_customer_create_params =
            Some(Arc::new(move |input, ctx| Box::pin(hook(input, ctx))));
        self
    }

    pub fn on_customer_create<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(OrganizationCustomerCreateInput, CustomerCreateContext) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: Future<Output = Result<(), OpenAuthError>> + Send + 'static,
    {
        self.on_customer_create = Some(Arc::new(move |input, ctx| Box::pin(hook(input, ctx))));
        self
    }
}
