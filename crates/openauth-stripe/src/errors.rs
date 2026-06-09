use openauth_core::plugin::PluginErrorCode;

/// Invalid Stripe plugin configuration detected at build time.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StripeConfigError {
    #[error("stripe_webhook_secret must not be empty")]
    EmptyWebhookSecret,
    #[error(
        "seat-based billing requires organization: {{ enabled: true }} in stripe plugin options"
    )]
    SeatPricingWithoutOrganization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripeErrorCode {
    Unauthorized,
    InvalidRequestBody,
    SubscriptionNotFound,
    SubscriptionPlanNotFound,
    AlreadySubscribedPlan,
    ReferenceIdNotAllowed,
    CustomerNotFound,
    UnableToCreateCustomer,
    UnableToCreateBillingPortal,
    StripeSignatureNotFound,
    StripeWebhookSecretNotFound,
    StripeWebhookError,
    FailedToConstructStripeEvent,
    FailedToFetchPlans,
    EmailVerificationRequired,
    SubscriptionNotActive,
    SubscriptionNotPendingChange,
    OrganizationNotFound,
    OrganizationSubscriptionNotEnabled,
    AuthorizeReferenceRequired,
    OrganizationHasActiveSubscription,
    OrganizationReferenceIdRequired,
}

impl std::fmt::Display for StripeErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

impl StripeErrorCode {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::InvalidRequestBody => "INVALID_REQUEST_BODY",
            Self::SubscriptionNotFound => "SUBSCRIPTION_NOT_FOUND",
            Self::SubscriptionPlanNotFound => "SUBSCRIPTION_PLAN_NOT_FOUND",
            Self::AlreadySubscribedPlan => "ALREADY_SUBSCRIBED_PLAN",
            Self::ReferenceIdNotAllowed => "REFERENCE_ID_NOT_ALLOWED",
            Self::CustomerNotFound => "CUSTOMER_NOT_FOUND",
            Self::UnableToCreateCustomer => "UNABLE_TO_CREATE_CUSTOMER",
            Self::UnableToCreateBillingPortal => "UNABLE_TO_CREATE_BILLING_PORTAL",
            Self::StripeSignatureNotFound => "STRIPE_SIGNATURE_NOT_FOUND",
            Self::StripeWebhookSecretNotFound => "STRIPE_WEBHOOK_SECRET_NOT_FOUND",
            Self::StripeWebhookError => "STRIPE_WEBHOOK_ERROR",
            Self::FailedToConstructStripeEvent => "FAILED_TO_CONSTRUCT_STRIPE_EVENT",
            Self::FailedToFetchPlans => "FAILED_TO_FETCH_PLANS",
            Self::EmailVerificationRequired => "EMAIL_VERIFICATION_REQUIRED",
            Self::SubscriptionNotActive => "SUBSCRIPTION_NOT_ACTIVE",
            Self::SubscriptionNotPendingChange => "SUBSCRIPTION_NOT_PENDING_CHANGE",
            Self::OrganizationNotFound => "ORGANIZATION_NOT_FOUND",
            Self::OrganizationSubscriptionNotEnabled => "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED",
            Self::AuthorizeReferenceRequired => "AUTHORIZE_REFERENCE_REQUIRED",
            Self::OrganizationHasActiveSubscription => "ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION",
            Self::OrganizationReferenceIdRequired => "ORGANIZATION_REFERENCE_ID_REQUIRED",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Unauthorized => "Unauthorized access",
            Self::InvalidRequestBody => "Invalid request body",
            Self::SubscriptionNotFound => "Subscription not found",
            Self::SubscriptionPlanNotFound => "Subscription plan not found",
            Self::AlreadySubscribedPlan => "You're already subscribed to this plan",
            Self::ReferenceIdNotAllowed => "Reference id is not allowed",
            Self::CustomerNotFound => "Stripe customer not found for this user",
            Self::UnableToCreateCustomer => "Unable to create customer",
            Self::UnableToCreateBillingPortal => "Unable to create billing portal session",
            Self::StripeSignatureNotFound => "Stripe signature not found",
            Self::StripeWebhookSecretNotFound => "Stripe webhook secret not found",
            Self::StripeWebhookError => "Stripe webhook error",
            Self::FailedToConstructStripeEvent => "Failed to construct Stripe event",
            Self::FailedToFetchPlans => "Failed to fetch plans",
            Self::EmailVerificationRequired => {
                "Email verification is required before you can subscribe to a plan"
            }
            Self::SubscriptionNotActive => "Subscription is not active",
            Self::SubscriptionNotPendingChange => {
                "Subscription has no pending cancellation or scheduled plan change"
            }
            Self::OrganizationNotFound => "Organization not found",
            Self::OrganizationSubscriptionNotEnabled => "Organization subscription is not enabled",
            Self::AuthorizeReferenceRequired => {
                "Organization subscriptions require authorizeReference callback to be configured"
            }
            Self::OrganizationHasActiveSubscription => {
                "Cannot delete organization with active subscription"
            }
            Self::OrganizationReferenceIdRequired => {
                "Reference ID is required. Provide referenceId or set activeOrganizationId in session"
            }
        }
    }
}

pub fn error_codes() -> Vec<PluginErrorCode> {
    [
        StripeErrorCode::Unauthorized,
        StripeErrorCode::InvalidRequestBody,
        StripeErrorCode::SubscriptionNotFound,
        StripeErrorCode::SubscriptionPlanNotFound,
        StripeErrorCode::AlreadySubscribedPlan,
        StripeErrorCode::ReferenceIdNotAllowed,
        StripeErrorCode::CustomerNotFound,
        StripeErrorCode::UnableToCreateCustomer,
        StripeErrorCode::UnableToCreateBillingPortal,
        StripeErrorCode::StripeSignatureNotFound,
        StripeErrorCode::StripeWebhookSecretNotFound,
        StripeErrorCode::StripeWebhookError,
        StripeErrorCode::FailedToConstructStripeEvent,
        StripeErrorCode::FailedToFetchPlans,
        StripeErrorCode::EmailVerificationRequired,
        StripeErrorCode::SubscriptionNotActive,
        StripeErrorCode::SubscriptionNotPendingChange,
        StripeErrorCode::OrganizationNotFound,
        StripeErrorCode::OrganizationSubscriptionNotEnabled,
        StripeErrorCode::AuthorizeReferenceRequired,
        StripeErrorCode::OrganizationHasActiveSubscription,
        StripeErrorCode::OrganizationReferenceIdRequired,
    ]
    .into_iter()
    .map(|code| PluginErrorCode::new(code.code(), code.message()))
    .collect()
}
