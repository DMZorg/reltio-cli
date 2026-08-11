use tokio::sync::watch;

/// A cloneable, process-local cancellation signal that remains set once canceled.
#[derive(Clone)]
pub struct CancellationToken {
    sender: watch::Sender<bool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    pub async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        if *receiver.borrow_and_update() {
            return;
        }
        while receiver.changed().await.is_ok() {
            if *receiver.borrow_and_update() {
                return;
            }
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender }
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
        tokio::time::timeout(Duration::from_secs(1), token.cancelled())
            .await
            .expect("late waiter observes sticky cancellation");
    }
}
