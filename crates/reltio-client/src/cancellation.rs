use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventStamp {
    at: Instant,
    sequence: u64,
}

impl EventStamp {
    pub fn precedes(self, other: Self) -> bool {
        self.at < other.at || self.at == other.at && self.sequence < other.sequence
    }

    pub fn occurred_before(self, instant: Instant) -> bool {
        self.at < instant
    }

    pub fn occurred_at_or_before(self, instant: Instant) -> bool {
        self.at <= instant
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationReason {
    Other,
    Signal,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CancellationEvent {
    stamp: EventStamp,
    reason: CancellationReason,
}

/// A cloneable, process-local cancellation signal that remains set once canceled.
#[derive(Clone)]
pub struct CancellationToken {
    sender: watch::Sender<Option<CancellationEvent>>,
    sequence: Arc<AtomicU64>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancel_with_reason(CancellationReason::Other);
    }

    pub fn cancel_with_reason(&self, reason: CancellationReason) {
        let sequence = &self.sequence;
        self.sender.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(CancellationEvent {
                    stamp: EventStamp {
                        at: Instant::now(),
                        sequence: sequence.fetch_add(1, Ordering::SeqCst),
                    },
                    reason,
                });
                true
            }
        });
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled_at().is_some()
    }

    pub fn cancelled_at(&self) -> Option<EventStamp> {
        self.sender.borrow().map(|event| event.stamp)
    }

    pub fn cancellation_reason(&self) -> Option<CancellationReason> {
        self.sender.borrow().map(|event| event.reason)
    }

    pub fn event_stamp(&self) -> EventStamp {
        EventStamp {
            at: Instant::now(),
            sequence: self.sequence.fetch_add(1, Ordering::SeqCst),
        }
    }

    pub async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        if receiver.borrow_and_update().is_some() {
            return;
        }
        while receiver.changed().await.is_ok() {
            if receiver.borrow_and_update().is_some() {
                return;
            }
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        let (sender, _) = watch::channel(None);
        Self {
            sender,
            sequence: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl std::fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("is_cancelled", &self.is_cancelled())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn cancellation_is_sticky_across_clones_without_lost_wakeups() {
        let token = CancellationToken::new();
        let waiting = token.clone();
        let waiter = tokio::spawn(async move { waiting.cancelled().await });

        token.cancel();

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("registered waiter wakes")
            .expect("waiter task completes");
        assert!(token.is_cancelled());
        let first = token
            .cancelled_at()
            .expect("cancellation has an event stamp");
        token.cancel();
        assert_eq!(token.cancelled_at(), Some(first));
        assert_eq!(token.cancellation_reason(), Some(CancellationReason::Other));
        tokio::time::timeout(Duration::from_secs(1), token.cancelled())
            .await
            .expect("late waiter observes sticky cancellation");
    }

    #[test]
    fn first_cancellation_reason_is_sticky() {
        let token = CancellationToken::new();
        token.cancel_with_reason(CancellationReason::Deadline);
        let first = token.cancelled_at();

        token.cancel_with_reason(CancellationReason::Signal);

        assert_eq!(token.cancelled_at(), first);
        assert_eq!(
            token.cancellation_reason(),
            Some(CancellationReason::Deadline)
        );
    }
}
