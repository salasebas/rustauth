use openauth_core::context::request_state::{
    current_new_session, define_request_state, has_request_state, run_with_request_state,
    set_current_new_session,
};
use openauth_core::db::{Session, User};
use openauth_core::error::OpenAuthError;
use time::{Duration, OffsetDateTime};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Marker {
    id: &'static str,
}

#[tokio::test]
async fn run_with_request_state_exposes_state_inside_scope() {
    let result = run_with_request_state(async {
        assert!(has_request_state());
        "success"
    })
    .await;

    assert_eq!(result, "success");
}

#[tokio::test]
async fn has_request_state_returns_false_outside_scope() {
    assert!(!has_request_state());
}

#[tokio::test]
async fn request_state_is_isolated_between_concurrent_scopes() -> Result<(), OpenAuthError> {
    let state = define_request_state(|| Marker { id: "initial" });

    let first = run_with_request_state({
        let state = state.clone();
        async move {
            state.set(Marker { id: "first" })?;
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            state.get()
        }
    });

    let second = run_with_request_state({
        let state = state.clone();
        async move {
            state.set(Marker { id: "second" })?;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            state.get()
        }
    });

    let (first, second) = tokio::join!(first, second);

    assert_eq!(first?, Marker { id: "first" });
    assert_eq!(second?, Marker { id: "second" });

    Ok(())
}

#[tokio::test]
async fn request_state_lazily_initializes_once_per_scope() -> Result<(), OpenAuthError> {
    let state = define_request_state(|| Marker { id: "initial" });

    run_with_request_state(async {
        assert_eq!(state.get()?, Marker { id: "initial" });
        state.set(Marker { id: "updated" })?;
        assert_eq!(state.get()?, Marker { id: "updated" });
        Ok(())
    })
    .await
}

#[tokio::test]
async fn request_state_returns_error_outside_scope() {
    let state = define_request_state(|| Marker { id: "initial" });

    assert_eq!(state.get(), Err(OpenAuthError::RequestStateMissing));
}

#[tokio::test]
async fn current_new_session_defaults_to_none_inside_scope() -> Result<(), OpenAuthError> {
    run_with_request_state(async {
        assert!(current_new_session()?.is_none());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn current_new_session_can_be_set_inside_scope() -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    let session = Session {
        id: "session_1".to_owned(),
        user_id: "user_1".to_owned(),
        expires_at: now + Duration::days(7),
        token: "token_1".to_owned(),
        ip_address: None,
        user_agent: None,
        created_at: now,
        updated_at: now,
    };
    let user = User {
        id: "user_1".to_owned(),
        name: "Ada".to_owned(),
        email: "ada@example.com".to_owned(),
        email_verified: true,
        image: None,
        username: None,
        display_username: None,
        created_at: now,
        updated_at: now,
    };

    run_with_request_state(async {
        set_current_new_session(session.clone(), user.clone())?;
        let current = current_new_session()?.ok_or(OpenAuthError::RequestStateMissing)?;
        assert_eq!(current.session, session);
        assert_eq!(current.user, user);
        Ok(())
    })
    .await
}
