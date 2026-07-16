use std::sync::Arc;

use tokio::sync::{broadcast, watch, Mutex};

use crate::domain::{
    CanonicalSnapshot, CheckStatus, Impact, SubsystemCheck, Transition, TRANSITION_CAPACITY,
};

#[derive(Clone)]
pub struct StatePublisher {
    inner: Arc<Mutex<CanonicalSnapshot>>,
    snapshots: watch::Sender<CanonicalSnapshot>,
    events: broadcast::Sender<Transition>,
}

impl StatePublisher {
    pub fn new(mut initial: CanonicalSnapshot) -> Self {
        initial.schema_version = 2;
        let (snapshots, _) = watch::channel(initial.clone());
        let (events, _) = broadcast::channel(TRANSITION_CAPACITY);
        Self {
            inner: Arc::new(Mutex::new(initial)),
            snapshots,
            events,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<CanonicalSnapshot> {
        self.snapshots.subscribe()
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<Transition> {
        self.events.subscribe()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn observe(
        &self,
        id: &str,
        status: CheckStatus,
        impact: Impact,
        reason_code: &str,
        safe_message: impl Into<String>,
        next_attempt_at_unix_ms: Option<u64>,
        recovery_attempt: Option<u32>,
    ) {
        let now = crate::runtime::unix_ms();
        let safe_message = safe_message.into();
        let mut state = self.inner.lock().await;
        let previous = state
            .checks
            .get(id)
            .cloned()
            .unwrap_or_else(|| SubsystemCheck::pending(id, impact, now));
        let changed = previous.status != status || previous.reason_code != reason_code;
        let failures = if matches!(status, CheckStatus::Failed | CheckStatus::Degraded) {
            previous.consecutive_failures.saturating_add(1)
        } else {
            0
        };
        let changed_at = if changed {
            now
        } else {
            previous.changed_at_unix_ms
        };
        state.checks.insert(
            id.to_owned(),
            SubsystemCheck {
                id: id.to_owned(),
                status,
                impact,
                observed_at_unix_ms: now,
                changed_at_unix_ms: changed_at,
                reason_code: reason_code.to_owned(),
                safe_message: safe_message.clone(),
                consecutive_failures: failures,
                next_attempt_at_unix_ms,
            },
        );
        state.generated_at_unix_ms = now;
        if changed {
            state.sequence += 1;
            let transition = Transition {
                sequence: state.sequence,
                timestamp_unix_ms: now,
                component: id.to_owned(),
                from_status: previous.status,
                to_status: status,
                reason_code: reason_code.to_owned(),
                safe_message,
                recovery_attempt,
            };
            if state.transitions.len() == TRANSITION_CAPACITY {
                state.transitions.pop_front();
            }
            state.transitions.push_back(transition.clone());
            let _ = self.events.send(transition);
        }
        state.derive_aggregate();
        self.snapshots.send_replace(state.clone());
    }

    pub async fn mutate(&self, update: impl FnOnce(&mut CanonicalSnapshot)) {
        let mut state = self.inner.lock().await;
        update(&mut state);
        state.generated_at_unix_ms = crate::runtime::unix_ms();
        state.derive_aggregate();
        self.snapshots.send_replace(state.clone());
    }

    pub async fn emit(&self, component: &str, reason_code: &str, safe_message: &str) {
        let now = crate::runtime::unix_ms();
        let mut state = self.inner.lock().await;
        state.sequence += 1;
        state.generated_at_unix_ms = now;
        let transition = Transition {
            sequence: state.sequence,
            timestamp_unix_ms: now,
            component: component.to_owned(),
            from_status: CheckStatus::Healthy,
            to_status: CheckStatus::Healthy,
            reason_code: reason_code.to_owned(),
            safe_message: safe_message.to_owned(),
            recovery_attempt: None,
        };
        if state.transitions.len() == TRANSITION_CAPACITY {
            state.transitions.pop_front();
        }
        state.transitions.push_back(transition.clone());
        let _ = self.events.send(transition);
        self.snapshots.send_replace(state.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn emits_only_meaningful_transitions_and_bounds_history() {
        let publisher = StatePublisher::new(CanonicalSnapshot::default());
        publisher
            .observe(
                "test",
                CheckStatus::Healthy,
                Impact::Advisory,
                "test.ok",
                "ok",
                None,
                None,
            )
            .await;
        publisher
            .observe(
                "test",
                CheckStatus::Healthy,
                Impact::Advisory,
                "test.ok",
                "ok",
                None,
                None,
            )
            .await;
        assert_eq!(publisher.subscribe().borrow().transitions.len(), 1);
        for index in 0..250 {
            let status = if index % 2 == 0 {
                CheckStatus::Failed
            } else {
                CheckStatus::Healthy
            };
            publisher
                .observe(
                    "test",
                    status,
                    Impact::Advisory,
                    if status == CheckStatus::Failed {
                        "test.failed"
                    } else {
                        "test.ok"
                    },
                    "safe",
                    None,
                    None,
                )
                .await;
        }
        assert_eq!(
            publisher.subscribe().borrow().transitions.len(),
            TRANSITION_CAPACITY
        );
    }
}
