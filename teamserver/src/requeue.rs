//! Stale-dispatch re-queue worker (A9).
//!
//! Every 30 seconds, walk the in-memory tasks and re-queue any task that has
//! been `Dispatched` for longer than `STALE_DISPATCH_TIMEOUT_SECONDS` without
//! a response. Resets it to `ReQueued`, pushes it back onto the agent's
//! pending queue, and emits a `TaskReQueued` event into the persistence
//! worker so SQLite stays consistent.

use crate::persistence::PersistEvent;
use crate::SharedState;
use std::time::Duration;
use tokio::sync::mpsc;

/// How long a dispatched task can stay un-replied before it is reset.
pub const STALE_DISPATCH_TIMEOUT_SECONDS: u64 = 600;

pub fn spawn(state: SharedState, tx: mpsc::UnboundedSender<PersistEvent>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        // Skip the immediate first tick so boot isn't noisy.
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(err) = tick_once(&state, &tx).await {
                eprintln!("[-] re-queue worker: {err}");
            }
        }
    });
}

async fn tick_once(
    state: &SharedState,
    tx: &mpsc::UnboundedSender<PersistEvent>,
) -> Result<(), String> {
    let now = unix_now();
    let mut requeued = Vec::new();
    {
        let mut s = state.lock().await;
        // Collect the task ids first so we can borrow `s.store.pending_tasks`
        // separately afterwards without overlapping `iter_mut` on tasks.
        let stale: Vec<String> = s
            .store
            .tasks
            .iter()
            .filter_map(|(task_id, record)| {
                if let Some(disp) = record.dispatched_at_unix {
                    if record.status == shared::TaskStatus::Dispatched
                        && now.saturating_sub(disp) > STALE_DISPATCH_TIMEOUT_SECONDS
                    {
                        return Some(task_id.clone());
                    }
                }
                None
            })
            .collect();
        for task_id in stale {
            let agent_id = s.store.tasks.get(&task_id).map(|r| r.agent_id.clone());
            if let Some(record) = s.store.tasks.get_mut(&task_id) {
                record.status = shared::TaskStatus::ReQueued;
                record.dispatched_at_unix = None;
                record.completed_at_unix = None;
            }
            if let Some(agent_id) = agent_id {
                s.store
                    .pending_tasks
                    .entry(agent_id)
                    .or_default()
                    .push_back(task_id.clone());
                requeued.push(task_id);
            }
        }
    }
    for task_id in requeued {
        let _ = tx.send(PersistEvent::TaskReQueued { task_id });
    }
    Ok(())
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}