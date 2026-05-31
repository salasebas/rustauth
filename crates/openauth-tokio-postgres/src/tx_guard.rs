use std::sync::Arc;

use tokio::runtime::Handle;
use tokio::sync::OwnedRwLockWriteGuard;
use tokio_postgres::Client;

/// Rolls back an in-flight transaction if the owning future is dropped before
/// an explicit `COMMIT`/`ROLLBACK` runs (request cancellation, task abort, or
/// panic between `BEGIN` and cleanup).
///
/// The adapter shares a single process-wide `Arc<Client>`, so a leaked open
/// transaction would let a later `COMMIT` persist the aborted writes. The guard
/// keeps the `tx_gate` write lock until the spawned `ROLLBACK` completes, which
/// prevents any read or write on the shared connection from observing the dirty
/// transaction before it is undone.
pub(crate) struct SharedClientRollbackGuard {
    client: Arc<Client>,
    gate: Option<OwnedRwLockWriteGuard<()>>,
    handle: Handle,
    armed: bool,
}

impl SharedClientRollbackGuard {
    /// Arms a guard for the open transaction on `client`, holding `gate` until
    /// the transaction is resolved.
    pub(crate) fn new(client: Arc<Client>, gate: OwnedRwLockWriteGuard<()>) -> Self {
        Self {
            client,
            gate: Some(gate),
            handle: Handle::current(),
            armed: true,
        }
    }

    /// Marks the transaction as resolved so `Drop` does not issue a `ROLLBACK`.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SharedClientRollbackGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let client = Arc::clone(&self.client);
        let gate = self.gate.take();
        let _rollback_task = self.handle.spawn(async move {
            let _rollback_result = client.batch_execute("ROLLBACK").await;
            drop(gate);
        });
    }
}
