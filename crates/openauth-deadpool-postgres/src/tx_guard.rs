use std::sync::Arc;

use deadpool_postgres::Client as DeadpoolClient;
use tokio::runtime::Handle;
use tokio::sync::Mutex;

/// Rolls back an in-flight transaction if the owning future is dropped before
/// an explicit `COMMIT`/`ROLLBACK` runs (request cancellation, task abort, or
/// panic between `BEGIN` and cleanup).
///
/// The pooled client is shared through an `Arc<Mutex<_>>`; the guard keeps a
/// clone so the checked-out connection cannot be recycled into the pool until
/// the spawned `ROLLBACK` has completed, guaranteeing the next borrower sees a
/// clean connection instead of an orphaned open transaction.
pub(crate) struct PooledClientRollbackGuard {
    client: Arc<Mutex<DeadpoolClient>>,
    handle: Handle,
    armed: bool,
}

impl PooledClientRollbackGuard {
    /// Arms a guard for the open transaction on the pooled `client`.
    pub(crate) fn new(client: Arc<Mutex<DeadpoolClient>>) -> Self {
        Self {
            client,
            handle: Handle::current(),
            armed: true,
        }
    }

    /// Marks the transaction as resolved so `Drop` does not issue a `ROLLBACK`.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PooledClientRollbackGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let client = Arc::clone(&self.client);
        let _rollback_task = self.handle.spawn(async move {
            let locked = client.lock().await;
            let _rollback_result = locked.batch_execute("ROLLBACK").await;
        });
    }
}
