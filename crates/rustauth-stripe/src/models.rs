use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub plan: String,
    #[serde(rename = "referenceId")]
    pub reference_id: String,
    #[serde(default, rename = "stripeCustomerId")]
    pub stripe_customer_id: Option<String>,
    #[serde(default, rename = "stripeSubscriptionId")]
    pub stripe_subscription_id: Option<String>,
    pub status: String,
    #[serde(default, rename = "periodStart", with = "time::serde::rfc3339::option")]
    pub period_start: Option<OffsetDateTime>,
    #[serde(default, rename = "periodEnd", with = "time::serde::rfc3339::option")]
    pub period_end: Option<OffsetDateTime>,
    #[serde(default, rename = "trialStart", with = "time::serde::rfc3339::option")]
    pub trial_start: Option<OffsetDateTime>,
    #[serde(default, rename = "trialEnd", with = "time::serde::rfc3339::option")]
    pub trial_end: Option<OffsetDateTime>,
    #[serde(default, rename = "cancelAtPeriodEnd")]
    pub cancel_at_period_end: bool,
    #[serde(default, rename = "cancelAt", with = "time::serde::rfc3339::option")]
    pub cancel_at: Option<OffsetDateTime>,
    #[serde(default, rename = "canceledAt", with = "time::serde::rfc3339::option")]
    pub canceled_at: Option<OffsetDateTime>,
    #[serde(default, rename = "endedAt", with = "time::serde::rfc3339::option")]
    pub ended_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub seats: Option<i64>,
    #[serde(default, rename = "billingInterval")]
    pub billing_interval: Option<String>,
    #[serde(default, rename = "stripeScheduleId")]
    pub stripe_schedule_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StripePrice {
    pub id: String,
    #[serde(default)]
    pub lookup_key: Option<String>,
    #[serde(default)]
    pub recurring: Option<StripeRecurring>,
}

impl StripePrice {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            lookup_key: None,
            recurring: None,
        }
    }

    pub fn lookup_key(mut self, lookup_key: impl Into<String>) -> Self {
        self.lookup_key = Some(lookup_key.into());
        self
    }

    pub fn recurring(mut self, interval: impl Into<String>, usage_type: impl Into<String>) -> Self {
        self.recurring = Some(StripeRecurring {
            interval: interval.into(),
            usage_type: Some(usage_type.into()),
        });
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StripeRecurring {
    pub interval: String,
    #[serde(default)]
    pub usage_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StripeSubscriptionItem {
    pub id: String,
    pub price: StripePrice,
    #[serde(default)]
    pub quantity: Option<i64>,
    #[serde(default)]
    pub current_period_start: Option<i64>,
    #[serde(default)]
    pub current_period_end: Option<i64>,
}

impl StripeSubscriptionItem {
    pub fn new(id: impl Into<String>, price: StripePrice) -> Self {
        Self {
            id: id.into(),
            price,
            quantity: None,
            current_period_start: None,
            current_period_end: None,
        }
    }

    pub fn quantity(mut self, quantity: i64) -> Self {
        self.quantity = Some(quantity);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeList<T> {
    pub data: Vec<T>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    #[serde(default)]
    pub customer: Option<serde_json::Value>,
    pub status: String,
    pub items: StripeList<StripeSubscriptionItem>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub cancel_at_period_end: bool,
    #[serde(default)]
    pub cancel_at: Option<i64>,
    #[serde(default)]
    pub canceled_at: Option<i64>,
    #[serde(default)]
    pub ended_at: Option<i64>,
    #[serde(default)]
    pub trial_start: Option<i64>,
    #[serde(default)]
    pub trial_end: Option<i64>,
    #[serde(default)]
    pub schedule: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeCheckoutSession {
    pub id: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub subscription: Option<serde_json::Value>,
    #[serde(default)]
    pub client_reference_id: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeEventData {
    pub object: serde_json::Value,
}
