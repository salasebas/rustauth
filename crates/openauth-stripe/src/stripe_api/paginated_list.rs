use std::future::Future;

use serde_json::{json, Value};

use super::{StripeApiError, StripeClient};

/// Stripe list endpoints default to 10 items; billing state decisions must scan
/// the full customer history, not only the first page.
const STRIPE_LIST_PAGE_LIMIT: u64 = 100;
/// Safety cap to avoid unbounded loops if Stripe keeps returning `has_more`.
const MAX_STRIPE_LIST_PAGES: usize = 100;

impl StripeClient {
    /// List every subscription page for `params` and return a single merged list object.
    pub async fn list_subscriptions_all(&self, mut params: Value) -> Result<Value, StripeApiError> {
        self.paginate_list(
            |page_params| self.list_subscriptions(page_params),
            &mut params,
        )
        .await
    }

    /// List every subscription schedule page for `params` and return a single merged list object.
    pub async fn list_subscription_schedules_all(
        &self,
        mut params: Value,
    ) -> Result<Value, StripeApiError> {
        self.paginate_list(
            |page_params| self.list_subscription_schedules(page_params),
            &mut params,
        )
        .await
    }

    /// Walk subscription list pages until `predicate` matches or the list is exhausted.
    pub async fn find_subscription<F>(
        &self,
        mut params: Value,
        mut predicate: F,
    ) -> Result<Option<Value>, StripeApiError>
    where
        F: FnMut(&Value) -> bool,
    {
        let mut pages = 0usize;
        loop {
            if pages >= MAX_STRIPE_LIST_PAGES {
                return Ok(None);
            }
            pages += 1;
            set_list_page_params(&mut params);
            let page = self.list_subscriptions(params.clone()).await?;
            if let Some(found) = page
                .get("data")
                .and_then(Value::as_array)
                .and_then(|subscriptions| subscriptions.iter().find(|sub| predicate(sub)).cloned())
            {
                return Ok(Some(found));
            }
            if !stripe_list_has_more(&page) {
                return Ok(None);
            }
            let Some(last_id) = last_list_item_id(&page) else {
                return Ok(None);
            };
            set_starting_after(&mut params, last_id);
        }
    }

    /// Walk subscription schedule list pages until `predicate` matches or the list is exhausted.
    pub async fn find_subscription_schedule<F>(
        &self,
        mut params: Value,
        mut predicate: F,
    ) -> Result<Option<Value>, StripeApiError>
    where
        F: FnMut(&Value) -> bool,
    {
        let mut pages = 0usize;
        loop {
            if pages >= MAX_STRIPE_LIST_PAGES {
                return Ok(None);
            }
            pages += 1;
            set_list_page_params(&mut params);
            let page = self.list_subscription_schedules(params.clone()).await?;
            if let Some(found) = page
                .get("data")
                .and_then(Value::as_array)
                .and_then(|schedules| {
                    schedules
                        .iter()
                        .find(|schedule| predicate(schedule))
                        .cloned()
                })
            {
                return Ok(Some(found));
            }
            if !stripe_list_has_more(&page) {
                return Ok(None);
            }
            let Some(last_id) = last_list_item_id(&page) else {
                return Ok(None);
            };
            set_starting_after(&mut params, last_id);
        }
    }

    async fn paginate_list<F, Fut>(
        &self,
        fetch_page: F,
        params: &mut Value,
    ) -> Result<Value, StripeApiError>
    where
        F: Fn(Value) -> Fut,
        Fut: Future<Output = Result<Value, StripeApiError>>,
    {
        let mut merged = Vec::new();
        let mut pages = 0usize;
        loop {
            if pages >= MAX_STRIPE_LIST_PAGES {
                break;
            }
            pages += 1;
            set_list_page_params(params);
            let page = fetch_page(params.clone()).await?;
            if let Some(data) = page.get("data").and_then(Value::as_array) {
                merged.extend(data.iter().cloned());
            }
            if !stripe_list_has_more(&page) {
                break;
            }
            let Some(last_id) = last_list_item_id(&page) else {
                break;
            };
            set_starting_after(params, last_id);
        }
        Ok(json!({
            "object": "list",
            "data": merged,
            "has_more": false,
        }))
    }
}

fn set_list_page_params(params: &mut Value) {
    let Some(object) = params.as_object_mut() else {
        return;
    };
    object.insert("limit".to_owned(), json!(STRIPE_LIST_PAGE_LIMIT));
}

fn set_starting_after(params: &mut Value, id: &str) {
    let Some(object) = params.as_object_mut() else {
        return;
    };
    object.insert("starting_after".to_owned(), json!(id));
}

fn stripe_list_has_more(page: &Value) -> bool {
    page.get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn last_list_item_id(page: &Value) -> Option<&str> {
    page.get("data")?.as_array()?.last()?.get("id")?.as_str()
}
