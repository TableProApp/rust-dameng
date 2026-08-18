//! Cooperative interruption for blocking socket reads.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Cancellation and deadline state shared between a [`crate::Client`] and whoever drives it.
///
/// `read_message` polls a socket that the server may leave silent indefinitely. Holding a
/// clone of this lets another thread stop that poll, which is the only way to abandon a
/// running statement: DM8 offers no out-of-band cancel request.
///
/// Interrupting returns while the server may still be writing its response, so the protocol
/// stream is left mid-message. A client that observes [`Error::Cancelled`] or
/// [`Error::Timeout`] must be closed rather than reused, or a later statement would read
/// the abandoned response as its own.
#[derive(Debug, Default)]
pub struct Interrupt {
    cancelled: AtomicBool,
    timeout_millis: AtomicU64,
}

impl Interrupt {
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks any in-flight read to stop at its next poll.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Clears cancellation and the deadline. Call before starting a statement.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
        self.timeout_millis.store(0, Ordering::SeqCst);
    }

    /// Zero disables the deadline.
    pub fn set_timeout_millis(&self, millis: u64) {
        self.timeout_millis.store(millis, Ordering::SeqCst);
    }

    /// Resolves the configured timeout against the current instant.
    pub fn deadline(&self) -> Option<Instant> {
        match self.timeout_millis.load(Ordering::SeqCst) {
            0 => None,
            millis => Instant::now().checked_add(Duration::from_millis(millis)),
        }
    }

    /// Fails once the caller has cancelled or `deadline` has passed.
    pub fn check(&self, deadline: Option<Instant>) -> Result<()> {
        if self.is_cancelled() {
            return Err(Error::Cancelled);
        }
        match deadline {
            Some(deadline) if Instant::now() >= deadline => Err(Error::Timeout(
                "the statement exceeded its time limit".to_string(),
            )),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_passes_while_idle() {
        let interrupt = Interrupt::new();
        assert!(interrupt.check(None).is_ok());
    }

    #[test]
    fn check_reports_cancellation() {
        let interrupt = Interrupt::new();
        interrupt.cancel();
        assert!(matches!(interrupt.check(None), Err(Error::Cancelled)));
    }

    #[test]
    fn check_reports_an_elapsed_deadline() {
        let interrupt = Interrupt::new();
        let deadline = Instant::now() - Duration::from_millis(1);
        assert!(matches!(
            interrupt.check(Some(deadline)),
            Err(Error::Timeout(_))
        ));
    }

    #[test]
    fn cancellation_outranks_a_live_deadline() {
        let interrupt = Interrupt::new();
        interrupt.cancel();
        let deadline = Instant::now() + Duration::from_secs(60);
        assert!(matches!(
            interrupt.check(Some(deadline)),
            Err(Error::Cancelled)
        ));
    }

    #[test]
    fn reset_clears_cancellation_and_timeout() {
        let interrupt = Interrupt::new();
        interrupt.cancel();
        interrupt.set_timeout_millis(50);
        interrupt.reset();
        assert!(!interrupt.is_cancelled());
        assert!(interrupt.deadline().is_none());
    }

    #[test]
    fn zero_timeout_disables_the_deadline() {
        let interrupt = Interrupt::new();
        interrupt.set_timeout_millis(0);
        assert!(interrupt.deadline().is_none());
    }

    #[test]
    fn a_positive_timeout_produces_a_future_deadline() {
        let interrupt = Interrupt::new();
        interrupt.set_timeout_millis(10_000);
        let deadline = interrupt.deadline().expect("deadline");
        assert!(deadline > Instant::now());
    }
}
