use std::future::Future;

use crate::error::OpenAuthError;
use crate::options::SecondaryStorage;

pub async fn assert_secondary_storage_contract<S, Fut, Factory>(
    mut storage_factory: Factory,
) -> Result<(), OpenAuthError>
where
    S: SecondaryStorage,
    Fut: Future<Output = Result<S, OpenAuthError>>,
    Factory: FnMut(&'static str) -> Fut,
{
    assert_set_if_not_exists_is_atomic(&mut storage_factory).await?;
    assert_compare_and_set_is_atomic(&mut storage_factory).await?;
    assert_delete_if_value_is_atomic(&mut storage_factory).await?;
    assert_take_is_atomic(&mut storage_factory).await?;
    Ok(())
}

async fn assert_set_if_not_exists_is_atomic<S, Fut, Factory>(
    storage_factory: &mut Factory,
) -> Result<(), OpenAuthError>
where
    S: SecondaryStorage,
    Fut: Future<Output = Result<S, OpenAuthError>>,
    Factory: FnMut(&'static str) -> Fut,
{
    let storage = storage_factory("nx").await?;
    assert!(
        storage
            .set_if_not_exists("existing", "first".to_owned(), Some(60))
            .await?,
        "set_if_not_exists should create an absent key",
    );
    assert!(
        !storage
            .set_if_not_exists("existing", "second".to_owned(), Some(60))
            .await?,
        "set_if_not_exists should not overwrite an existing key",
    );
    assert_eq!(storage.get("existing").await?.as_deref(), Some("first"));

    let (first, second) = tokio::join!(
        storage.set_if_not_exists("concurrent", "first".to_owned(), Some(60)),
        storage.set_if_not_exists("concurrent", "second".to_owned(), Some(60)),
    );
    let created = [first?, second?]
        .into_iter()
        .filter(|created| *created)
        .count();
    assert_eq!(
        created, 1,
        "concurrent set_if_not_exists should create exactly once",
    );
    assert!(
        matches!(
            storage.get("concurrent").await?.as_deref(),
            Some("first" | "second")
        ),
        "set_if_not_exists should keep one concurrent payload",
    );

    storage
        .set("ttl-zero-existing", "stale".to_owned(), Some(60))
        .await?;
    assert!(
        !storage
            .set_if_not_exists("ttl-zero-existing", "ignored".to_owned(), Some(0))
            .await?,
        "set_if_not_exists with ttl=0 should not create or overwrite",
    );
    assert_eq!(
        storage.get("ttl-zero-existing").await?.as_deref(),
        Some("stale"),
        "set_if_not_exists with ttl=0 must leave an existing key untouched",
    );
    assert!(
        !storage
            .set_if_not_exists("ttl-zero-absent", "ignored".to_owned(), Some(0))
            .await?,
        "set_if_not_exists with ttl=0 should not create an absent key",
    );
    assert_eq!(storage.get("ttl-zero-absent").await?, None);
    Ok(())
}

async fn assert_compare_and_set_is_atomic<S, Fut, Factory>(
    storage_factory: &mut Factory,
) -> Result<(), OpenAuthError>
where
    S: SecondaryStorage,
    Fut: Future<Output = Result<S, OpenAuthError>>,
    Factory: FnMut(&'static str) -> Fut,
{
    let storage = storage_factory("cas").await?;
    assert!(
        storage
            .compare_and_set("absent", None, "created".to_owned(), Some(60))
            .await?,
        "compare_and_set should create when expected value is absent",
    );
    assert_eq!(storage.get("absent").await?.as_deref(), Some("created"));
    assert!(
        !storage
            .compare_and_set("absent", None, "wrong".to_owned(), Some(60))
            .await?,
        "compare_and_set should reject absent expectation once key exists",
    );
    assert!(
        storage
            .compare_and_set(
                "absent",
                Some("created".to_owned()),
                "updated".to_owned(),
                Some(60),
            )
            .await?,
        "compare_and_set should replace a matching value",
    );
    assert_eq!(storage.get("absent").await?.as_deref(), Some("updated"));

    storage
        .set("concurrent", "seed".to_owned(), Some(60))
        .await?;
    let (first, second) = tokio::join!(
        storage.compare_and_set(
            "concurrent",
            Some("seed".to_owned()),
            "first".to_owned(),
            Some(60),
        ),
        storage.compare_and_set(
            "concurrent",
            Some("seed".to_owned()),
            "second".to_owned(),
            Some(60),
        ),
    );
    let applied = [first?, second?]
        .into_iter()
        .filter(|applied| *applied)
        .count();
    assert_eq!(
        applied, 1,
        "concurrent compare_and_set should apply exactly once",
    );
    assert!(
        matches!(
            storage.get("concurrent").await?.as_deref(),
            Some("first" | "second")
        ),
        "compare_and_set should keep the winning value",
    );

    storage
        .set("ttl-zero", "stale".to_owned(), Some(60))
        .await?;
    assert!(
        storage
            .compare_and_set(
                "ttl-zero",
                Some("stale".to_owned()),
                "ignored".to_owned(),
                Some(0),
            )
            .await?,
        "ttl=0 compare_and_set should delete a matching key",
    );
    assert_eq!(storage.get("ttl-zero").await?, None);
    Ok(())
}

async fn assert_delete_if_value_is_atomic<S, Fut, Factory>(
    storage_factory: &mut Factory,
) -> Result<(), OpenAuthError>
where
    S: SecondaryStorage,
    Fut: Future<Output = Result<S, OpenAuthError>>,
    Factory: FnMut(&'static str) -> Fut,
{
    let storage = storage_factory("delete-if").await?;
    assert!(
        !storage.delete_if_value("missing", None).await?,
        "delete_if_value should not delete when expected is absent",
    );
    storage
        .set("existing", "payload".to_owned(), Some(60))
        .await?;
    assert!(
        !storage
            .delete_if_value("existing", Some("wrong".to_owned()))
            .await?,
        "delete_if_value should reject a non-matching expected value",
    );
    assert_eq!(storage.get("existing").await?.as_deref(), Some("payload"));
    assert!(
        storage
            .delete_if_value("existing", Some("payload".to_owned()))
            .await?,
        "delete_if_value should delete a matching value",
    );
    assert_eq!(storage.get("existing").await?, None);

    storage
        .set("concurrent-delete", "seed".to_owned(), Some(60))
        .await?;
    let (first, second) = tokio::join!(
        storage.delete_if_value("concurrent-delete", Some("seed".to_owned())),
        storage.delete_if_value("concurrent-delete", Some("seed".to_owned())),
    );
    let deleted = [first?, second?]
        .into_iter()
        .filter(|deleted| *deleted)
        .count();
    assert_eq!(
        deleted, 1,
        "concurrent delete_if_value should delete exactly once",
    );
    assert_eq!(storage.get("concurrent-delete").await?, None);
    Ok(())
}

async fn assert_take_is_atomic<S, Fut, Factory>(
    storage_factory: &mut Factory,
) -> Result<(), OpenAuthError>
where
    S: SecondaryStorage,
    Fut: Future<Output = Result<S, OpenAuthError>>,
    Factory: FnMut(&'static str) -> Fut,
{
    let storage = storage_factory("take").await?;
    storage
        .set("one-time", "payload".to_owned(), Some(60))
        .await?;
    let (first, second) = tokio::join!(storage.take("one-time"), storage.take("one-time"));
    let taken = [first?, second?].into_iter().flatten().collect::<Vec<_>>();
    assert_eq!(taken.len(), 1, "concurrent take should return one payload");
    assert_eq!(taken[0], "payload");
    assert_eq!(storage.get("one-time").await?, None);
    Ok(())
}
