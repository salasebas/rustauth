use openauth_core::context::request_state::{
    define_request_state, has_request_state, run_with_request_state,
};
use openauth_core::error::OpenAuthError;

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
