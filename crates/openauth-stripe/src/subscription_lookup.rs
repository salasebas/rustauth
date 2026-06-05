use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindMany, Where};
use openauth_core::error::OpenAuthError;

/// Matches historical `FindMany::limit(100)` page size for reference-scoped queries.
pub(crate) const LOCAL_SUBSCRIPTION_PAGE_SIZE: usize = 100;
/// Safety cap so a reference with an extreme number of rows cannot loop forever.
pub(crate) const MAX_LOCAL_SUBSCRIPTION_PAGES: usize = 100;

pub(crate) fn reference_subscription_where(reference_id: &str) -> FindMany {
    FindMany::new("subscription").where_clause(Where::new(
        "reference_id",
        DbValue::String(reference_id.to_owned()),
    ))
}

/// Load every subscription row for a billing reference, paging through the adapter.
pub(crate) async fn all_reference_subscription_records(
    adapter: &dyn DbAdapter,
    reference_id: &str,
) -> Result<Vec<DbRecord>, OpenAuthError> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    let mut pages = 0usize;
    loop {
        if pages >= MAX_LOCAL_SUBSCRIPTION_PAGES {
            break;
        }
        pages += 1;
        let page = adapter
            .find_many(
                reference_subscription_where(reference_id)
                    .limit(LOCAL_SUBSCRIPTION_PAGE_SIZE)
                    .offset(offset),
            )
            .await?;
        let page_len = page.len();
        records.extend(page);
        if page_len < LOCAL_SUBSCRIPTION_PAGE_SIZE {
            break;
        }
        offset = offset.saturating_add(LOCAL_SUBSCRIPTION_PAGE_SIZE);
    }
    Ok(records)
}

/// Scan reference subscription rows until `predicate` returns true.
pub(crate) async fn reference_subscription_exists(
    adapter: &dyn DbAdapter,
    reference_id: &str,
    mut predicate: impl FnMut(&DbRecord) -> bool,
) -> Result<bool, OpenAuthError> {
    let mut offset = 0usize;
    let mut pages = 0usize;
    loop {
        if pages >= MAX_LOCAL_SUBSCRIPTION_PAGES {
            return Ok(false);
        }
        pages += 1;
        let page = adapter
            .find_many(
                reference_subscription_where(reference_id)
                    .limit(LOCAL_SUBSCRIPTION_PAGE_SIZE)
                    .offset(offset),
            )
            .await?;
        if page.iter().any(&mut predicate) {
            return Ok(true);
        }
        if page.len() < LOCAL_SUBSCRIPTION_PAGE_SIZE {
            return Ok(false);
        }
        offset = offset.saturating_add(LOCAL_SUBSCRIPTION_PAGE_SIZE);
    }
}
