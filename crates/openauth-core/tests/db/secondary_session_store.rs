use std::sync::Arc;

use openauth_core::db::MemoryAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::session::{CreateSessionInput, SessionStore};
use openauth_core::test_utils::MemorySecondaryStorage;
use time::{Duration, OffsetDateTime};

fn secondary_store(
    adapter: &MemoryAdapter,
    storage: Arc<MemorySecondaryStorage>,
) -> SessionStore<'_> {
    SessionStore::with_storage(adapter, Some(storage), false, false)
}

fn user_index_key(user_id: &str) -> String {
    format!("session:user:{user_id}")
}

#[tokio::test]
async fn secondary_session_store_user_index_receives_ttl() -> Result<(), OpenAuthError> {
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(MemorySecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(2);

    store
        .create_session(
            CreateSessionInput::new("user_1", expires_at)
                .token("token_1")
                .id("session_1"),
        )
        .await?;

    let index_ttl = storage.ttl_for_key(&user_index_key("user_1"))?;
    let Some(index_ttl) = index_ttl else {
        return Err(OpenAuthError::Adapter(
            "expected user session index TTL".to_owned(),
        ));
    };
    assert!(index_ttl > 0);
    assert!(index_ttl <= 2 * 60 * 60);
    Ok(())
}

#[tokio::test]
async fn secondary_session_store_user_index_ttl_tracks_latest_expiry() -> Result<(), OpenAuthError>
{
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(MemorySecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let sooner = OffsetDateTime::now_utc() + Duration::hours(1);
    let later = OffsetDateTime::now_utc() + Duration::hours(3);

    store
        .create_session(
            CreateSessionInput::new("user_1", sooner)
                .token("token_soon")
                .id("session_soon"),
        )
        .await?;
    store
        .create_session(
            CreateSessionInput::new("user_1", later)
                .token("token_late")
                .id("session_late"),
        )
        .await?;

    let index_ttl = storage
        .ttl_for_key(&user_index_key("user_1"))?
        .ok_or_else(|| OpenAuthError::Adapter("missing user session index TTL".to_owned()))?;
    assert!(index_ttl > 2 * 60 * 60);
    assert!(index_ttl <= 3 * 60 * 60);
    Ok(())
}

#[tokio::test]
async fn secondary_session_store_expired_user_index_is_removed() -> Result<(), OpenAuthError> {
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(MemorySecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let expires_at = OffsetDateTime::now_utc() + Duration::seconds(1);

    store
        .create_session(
            CreateSessionInput::new("user_1", expires_at)
                .token("token_1")
                .id("session_1"),
        )
        .await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    assert!(
        !storage.has_key(&user_index_key("user_1"))?,
        "expired user session index must not remain in secondary storage"
    );
    assert!(
        !storage.has_key("session:token_1")?,
        "expired session record must not remain in secondary storage"
    );
    Ok(())
}

#[tokio::test]
async fn secondary_session_store_list_sessions_after_ttl_cleanup() -> Result<(), OpenAuthError> {
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(MemorySecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let active_expiry = OffsetDateTime::now_utc() + Duration::hours(2);
    let short_expiry = OffsetDateTime::now_utc() + Duration::seconds(1);

    store
        .create_session(
            CreateSessionInput::new("user_1", active_expiry)
                .token("token_active")
                .id("session_active"),
        )
        .await?;
    store
        .create_session(
            CreateSessionInput::new("user_1", short_expiry)
                .token("token_short")
                .id("session_short"),
        )
        .await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let sessions = store.list_user_sessions("user_1").await?;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].token, "token_active");
    assert!(
        storage.has_key(&user_index_key("user_1"))?,
        "active user session index must remain while a session is active"
    );
    Ok(())
}

#[tokio::test]
async fn secondary_session_store_update_expiry_refreshes_user_index_ttl(
) -> Result<(), OpenAuthError> {
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(MemorySecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let initial_expiry = OffsetDateTime::now_utc() + Duration::minutes(30);
    let extended_expiry = OffsetDateTime::now_utc() + Duration::hours(4);

    store
        .create_session(
            CreateSessionInput::new("user_1", initial_expiry)
                .token("token_1")
                .id("session_1"),
        )
        .await?;

    let initial_ttl = storage
        .ttl_for_key(&user_index_key("user_1"))?
        .ok_or_else(|| OpenAuthError::Adapter("missing initial index TTL".to_owned()))?;

    store
        .update_session_expiry("token_1", extended_expiry)
        .await?;

    let refreshed_ttl = storage
        .ttl_for_key(&user_index_key("user_1"))?
        .ok_or_else(|| OpenAuthError::Adapter("missing refreshed index TTL".to_owned()))?;
    assert!(refreshed_ttl > initial_ttl);
    Ok(())
}

#[tokio::test]
async fn secondary_session_store_refresh_user_sessions_bumps_updated_at(
) -> Result<(), OpenAuthError> {
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(MemorySecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(2);

    let created = store
        .create_session(
            CreateSessionInput::new("user_1", expires_at)
                .token("token_1")
                .id("session_1"),
        )
        .await?;
    let initial_ttl = storage
        .ttl_for_key("session:token_1")?
        .ok_or_else(|| OpenAuthError::Adapter("missing initial session TTL".to_owned()))?;

    let refreshed = store.refresh_user_sessions("user_1").await?;
    let session = store
        .find_session("token_1")
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing refreshed session".to_owned()))?;
    let refreshed_ttl = storage
        .ttl_for_key("session:token_1")?
        .ok_or_else(|| OpenAuthError::Adapter("missing refreshed session TTL".to_owned()))?;

    assert_eq!(refreshed, 1);
    assert!(session.updated_at >= created.updated_at);
    assert!(refreshed_ttl <= initial_ttl);
    assert!(refreshed_ttl > 0);
    Ok(())
}
