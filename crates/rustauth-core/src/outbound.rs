use std::future::Future;
use std::pin::Pin;

use crate::context::AuthContext;
use crate::error::RustAuthError;
use crate::options::BackgroundTaskFuture;

/// Future returned by outbound email/SMS sender hooks.
pub type OutboundSendFuture =
    Pin<Box<dyn Future<Output = Result<(), RustAuthError>> + Send + 'static>>;

/// Returns an immediately-ready outbound future.
pub fn ready_outbound(result: Result<(), RustAuthError>) -> OutboundSendFuture {
    Box::pin(async move { result })
}

/// Dispatches outbound delivery on a background task without blocking the caller.
pub fn dispatch_outbound(context: &AuthContext, send: OutboundSendFuture) {
    let logger = context.logger.clone();
    let task: BackgroundTaskFuture = Box::pin(async move {
        if let Err(error) = send.await {
            logger.error("outbound delivery failed", &[&error.to_string()]);
        }
    });
    if context.background_tasks.is_some() {
        context.run_background_task(task);
    } else {
        tokio::spawn(task);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::context::create_auth_context;
    use crate::error::RustAuthError;
    use crate::options::{
        AdvancedOptions, BackgroundTaskFuture, BackgroundTaskRunner, RustAuthOptions,
    };

    use super::dispatch_outbound;

    #[derive(Default)]
    struct CountingBackgroundRunner {
        calls: AtomicUsize,
    }

    impl CountingBackgroundRunner {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl BackgroundTaskRunner for CountingBackgroundRunner {
        fn spawn(&self, task: BackgroundTaskFuture) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(task);
        }
    }

    #[tokio::test]
    async fn dispatch_outbound_spawns_without_awaiting_sender() -> Result<(), RustAuthError> {
        let counting = Arc::new(CountingBackgroundRunner::default());
        let runner: Arc<dyn BackgroundTaskRunner> =
            Arc::clone(&counting) as Arc<dyn BackgroundTaskRunner>;
        let context = create_auth_context(
            RustAuthOptions::default()
                .advanced(AdvancedOptions::default().background_tasks(runner)),
        )?;

        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let started_for_send = Arc::clone(&started);
        let finished_for_send = Arc::clone(&finished);

        dispatch_outbound(
            &context,
            Box::pin(async move {
                started_for_send.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                finished_for_send.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        );

        assert_eq!(counting.calls(), 1);
        assert_eq!(started.load(Ordering::SeqCst), 0);

        tokio::time::sleep(Duration::from_millis(75)).await;
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(finished.load(Ordering::SeqCst), 1);
        Ok(())
    }
}
