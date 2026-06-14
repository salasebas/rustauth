use crate::options::{BackgroundTaskFuture, BackgroundTaskRunner};

/// Spawns background work on the Tokio runtime.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioBackgroundTaskRunner;

impl BackgroundTaskRunner for TokioBackgroundTaskRunner {
    fn spawn(&self, task: BackgroundTaskFuture) {
        tokio::spawn(task);
    }
}
