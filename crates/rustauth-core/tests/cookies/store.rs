use rustauth_core::cookies::{ChunkedCookieStore, CookieOptions};

#[test]
fn chunked_cookie_store_returns_single_cookie_for_small_values() {
    let store = ChunkedCookieStore::new("session_data", CookieOptions::default(), "");

    let cookies = store.chunk("abc");

    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name, "session_data");
    assert_eq!(cookies[0].value, "abc");
}

#[test]
fn chunked_cookie_store_splits_large_values() {
    let store = ChunkedCookieStore::new("session_data", CookieOptions::default(), "");

    let cookies = store.chunk(&"x".repeat(5000));

    assert!(cookies.iter().any(|cookie| cookie.name == "session_data.0"));
    assert!(cookies.iter().any(|cookie| cookie.name == "session_data.1"));
}

#[test]
fn chunked_cookie_store_joins_existing_chunks_by_index() {
    let store = ChunkedCookieStore::new(
        "session_data",
        CookieOptions::default(),
        "session_data.1=world; session_data.0=hello",
    );

    assert_eq!(store.value().as_deref(), Some("helloworld"));
}

#[test]
fn chunked_cookie_store_cleans_existing_chunks() {
    let store = ChunkedCookieStore::new(
        "session_data",
        CookieOptions::default(),
        "session_data.0=hello; session_data.1=world",
    );

    let clean = store.clean();

    assert_eq!(clean.len(), 2);
    assert!(clean.iter().all(|cookie| cookie.value.is_empty()));
    assert!(clean
        .iter()
        .all(|cookie| cookie.attributes.max_age == Some(0)));
}
