//! Native PIN-attempt throttling.
//!
//! `PinThrottle` is intentionally stateful and should be stored behind the
//! application's existing synchronization boundary, for example
//! `Arc<Mutex<PinThrottle>>` or an `AppState` field of type
//! `Mutex<PinThrottle>`. A short-lived [`PinAttemptPermit`] reserves the single
//! allowed verification slot while the expensive PIN KDF runs outside the
//! mutex. Concurrent attempts and late completions are rejected.

use std::fmt;
use std::time::{Duration, Instant};

/// Parameters for PIN throttling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinThrottleConfig {
    /// Delay after the first failed verification.
    pub base_delay: Duration,
    /// Upper bound for exponential backoff.
    pub max_delay: Duration,
    /// Maximum lifetime of an in-flight verification permit.
    pub attempt_timeout: Duration,
}

impl Default for PinThrottleConfig {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(5 * 60),
            attempt_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinThrottleConfigError {
    ZeroBaseDelay,
    MaximumBelowBase,
    ZeroAttemptTimeout,
}

impl fmt::Display for PinThrottleConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBaseDelay => f.write_str("PIN throttle base delay must be non-zero"),
            Self::MaximumBelowBase => {
                f.write_str("PIN throttle maximum delay must not be below its base delay")
            }
            Self::ZeroAttemptTimeout => {
                f.write_str("PIN verification permit timeout must be non-zero")
            }
        }
    }
}

impl std::error::Error for PinThrottleConfigError {}

/// Reason a new verification attempt cannot start yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAttemptDenied {
    /// A previous failure is still cooling down.
    CoolingDown { retry_after: Duration },
    /// Another verifier currently owns the sole attempt permit.
    AttemptInProgress { retry_after: Duration },
    /// The monotonically increasing permit identifier was exhausted.
    PermitIdExhausted,
}

impl fmt::Display for PinAttemptDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoolingDown { retry_after } => write!(
                f,
                "PIN verification is rate-limited; retry in {} ms",
                retry_after.as_millis()
            ),
            Self::AttemptInProgress { retry_after } => write!(
                f,
                "another PIN verification is in progress; retry in at most {} ms",
                retry_after.as_millis()
            ),
            Self::PermitIdExhausted => f.write_str("PIN verification permit counter exhausted"),
        }
    }
}

impl std::error::Error for PinAttemptDenied {}

/// Failure to complete a previously issued permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinAttemptCompletionError {
    /// The permit was already completed, superseded, or never issued here.
    StalePermit,
    /// Verification took longer than the configured permit lifetime.
    ExpiredPermit,
}

impl fmt::Display for PinAttemptCompletionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StalePermit => f.write_str("stale PIN verification permit"),
            Self::ExpiredPermit => f.write_str("expired PIN verification permit"),
        }
    }
}

impl std::error::Error for PinAttemptCompletionError {}

/// Opaque, single-use reservation for one PIN verification.
///
/// The type is deliberately neither `Clone` nor `Copy`. Dropping it without
/// completion keeps the slot reserved until `attempt_timeout`, preventing an
/// early-return path from opening an unlimited parallel-attempt window.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "the permit must be completed with record_success or record_failure"]
pub struct PinAttemptPermit {
    id: u64,
}

#[derive(Debug, Clone, Copy)]
struct InFlightAttempt {
    id: u64,
    started_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Cooldown {
    started_at: Instant,
    duration: Duration,
}

/// Stateful PIN rate limiter intended to be protected by an external `Mutex`.
#[derive(Debug)]
pub struct PinThrottle {
    config: PinThrottleConfig,
    failed_attempts: u32,
    cooldown: Option<Cooldown>,
    in_flight: Option<InFlightAttempt>,
    next_permit_id: u64,
}

impl Default for PinThrottle {
    fn default() -> Self {
        // The built-in constants satisfy validation by construction.
        Self::new(PinThrottleConfig::default()).expect("valid default PIN throttle config")
    }
}

impl PinThrottle {
    pub fn new(config: PinThrottleConfig) -> Result<Self, PinThrottleConfigError> {
        if config.base_delay.is_zero() {
            return Err(PinThrottleConfigError::ZeroBaseDelay);
        }
        if config.max_delay < config.base_delay {
            return Err(PinThrottleConfigError::MaximumBelowBase);
        }
        if config.attempt_timeout.is_zero() {
            return Err(PinThrottleConfigError::ZeroAttemptTimeout);
        }

        Ok(Self {
            config,
            failed_attempts: 0,
            cooldown: None,
            in_flight: None,
            next_permit_id: 0,
        })
    }

    /// Reserve the only verification slot.
    ///
    /// Call this while holding the external mutex, release the mutex while the
    /// expensive KDF runs, then reacquire it and complete the returned permit.
    pub fn begin_attempt(&mut self, now: Instant) -> Result<PinAttemptPermit, PinAttemptDenied> {
        if let Some(in_flight) = self.in_flight {
            let remaining = remaining(in_flight.started_at, self.config.attempt_timeout, now);
            if !remaining.is_zero() {
                return Err(PinAttemptDenied::AttemptInProgress {
                    retry_after: remaining,
                });
            }
            // A verifier that finishes after this point owns a stale permit.
            self.in_flight = None;
        }

        let retry_after = self.retry_after(now);
        if !retry_after.is_zero() {
            return Err(PinAttemptDenied::CoolingDown { retry_after });
        }
        self.cooldown = None;

        let id = self
            .next_permit_id
            .checked_add(1)
            .ok_or(PinAttemptDenied::PermitIdExhausted)?;
        self.next_permit_id = id;
        self.in_flight = Some(InFlightAttempt {
            id,
            started_at: now,
        });
        Ok(PinAttemptPermit { id })
    }

    /// Complete an attempt as failed and return the newly imposed delay.
    pub fn record_failure(
        &mut self,
        permit: PinAttemptPermit,
        now: Instant,
    ) -> Result<Duration, PinAttemptCompletionError> {
        self.consume_permit(permit, now)?;
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        let delay = self.delay_for_failures(self.failed_attempts);
        self.cooldown = Some(Cooldown {
            started_at: now,
            duration: delay,
        });
        Ok(delay)
    }

    /// Complete an attempt as successful and reset all accumulated backoff.
    pub fn record_success(
        &mut self,
        permit: PinAttemptPermit,
        now: Instant,
    ) -> Result<(), PinAttemptCompletionError> {
        self.consume_permit(permit, now)?;
        self.failed_attempts = 0;
        self.cooldown = None;
        Ok(())
    }

    /// Remaining failure cooldown at `now`.
    pub fn retry_after(&self, now: Instant) -> Duration {
        self.cooldown
            .map(|cooldown| remaining(cooldown.started_at, cooldown.duration, now))
            .unwrap_or(Duration::ZERO)
    }

    #[cfg(test)]
    pub fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    /// Reset throttling after a PIN is securely changed or removed.
    pub fn reset(&mut self) {
        self.failed_attempts = 0;
        self.cooldown = None;
        self.in_flight = None;
    }

    fn consume_permit(
        &mut self,
        permit: PinAttemptPermit,
        now: Instant,
    ) -> Result<(), PinAttemptCompletionError> {
        let Some(in_flight) = self.in_flight else {
            return Err(PinAttemptCompletionError::StalePermit);
        };
        if in_flight.id != permit.id {
            return Err(PinAttemptCompletionError::StalePermit);
        }
        if remaining(in_flight.started_at, self.config.attempt_timeout, now).is_zero() {
            self.in_flight = None;
            return Err(PinAttemptCompletionError::ExpiredPermit);
        }
        self.in_flight = None;
        Ok(())
    }

    fn delay_for_failures(&self, failures: u32) -> Duration {
        let mut delay = self.config.base_delay;
        let mut doublings = failures.saturating_sub(1);
        while doublings > 0 && delay < self.config.max_delay {
            delay = delay.saturating_mul(2).min(self.config.max_delay);
            doublings -= 1;
        }
        delay
    }
}

fn remaining(started_at: Instant, duration: Duration, now: Instant) -> Duration {
    let elapsed = now.checked_duration_since(started_at).unwrap_or_default();
    duration.saturating_sub(elapsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn test_config() -> PinThrottleConfig {
        PinThrottleConfig {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            attempt_timeout: Duration::from_secs(10),
        }
    }

    fn fail_at(throttle: &mut PinThrottle, now: Instant) -> Duration {
        let permit = throttle.begin_attempt(now).unwrap();
        throttle
            .record_failure(permit, now + Duration::from_millis(1))
            .unwrap()
    }

    #[test]
    fn first_failure_blocks_until_exact_deadline() {
        let mut throttle = PinThrottle::new(test_config()).unwrap();
        let start = Instant::now();
        let delay = fail_at(&mut throttle, start);
        let failed_at = start + Duration::from_millis(1);

        assert_eq!(delay, Duration::from_secs(1));
        assert_eq!(throttle.failed_attempts(), 1);
        assert_eq!(
            throttle.begin_attempt(failed_at + Duration::from_millis(250)),
            Err(PinAttemptDenied::CoolingDown {
                retry_after: Duration::from_millis(750)
            })
        );
        assert!(throttle
            .begin_attempt(failed_at + Duration::from_secs(1))
            .is_ok());
    }

    #[test]
    fn failures_back_off_exponentially_and_cap() {
        let mut throttle = PinThrottle::new(test_config()).unwrap();
        let mut now = Instant::now();
        let expected = [1, 2, 4, 5, 5, 5];

        for seconds in expected {
            let delay = fail_at(&mut throttle, now);
            assert_eq!(delay, Duration::from_secs(seconds));
            now += Duration::from_millis(1) + delay;
        }
        assert_eq!(throttle.failed_attempts(), expected.len() as u32);
    }

    #[test]
    fn success_resets_backoff() {
        let mut throttle = PinThrottle::new(test_config()).unwrap();
        let start = Instant::now();
        let first_delay = fail_at(&mut throttle, start);
        let second_start = start + Duration::from_millis(1) + first_delay;
        let second_delay = fail_at(&mut throttle, second_start);
        let success_start = second_start + Duration::from_millis(1) + second_delay;

        let permit = throttle.begin_attempt(success_start).unwrap();
        throttle
            .record_success(permit, success_start + Duration::from_millis(1))
            .unwrap();
        assert_eq!(throttle.failed_attempts(), 0);
        assert_eq!(throttle.retry_after(success_start), Duration::ZERO);

        let next = success_start + Duration::from_secs(1);
        assert_eq!(fail_at(&mut throttle, next), Duration::from_secs(1));
    }

    #[test]
    fn in_flight_attempt_blocks_parallel_work_and_expires() {
        let mut throttle = PinThrottle::new(test_config()).unwrap();
        let start = Instant::now();
        let stale = throttle.begin_attempt(start).unwrap();

        assert_eq!(
            throttle.begin_attempt(start + Duration::from_secs(3)),
            Err(PinAttemptDenied::AttemptInProgress {
                retry_after: Duration::from_secs(7)
            })
        );

        let replacement = throttle
            .begin_attempt(start + Duration::from_secs(10))
            .unwrap();
        assert_eq!(
            throttle.record_success(stale, start + Duration::from_secs(10)),
            Err(PinAttemptCompletionError::StalePermit)
        );
        throttle
            .record_success(replacement, start + Duration::from_secs(11))
            .unwrap();
    }

    #[test]
    fn expired_completion_cannot_change_state() {
        let mut throttle = PinThrottle::new(test_config()).unwrap();
        let start = Instant::now();
        let permit = throttle.begin_attempt(start).unwrap();

        assert_eq!(
            throttle.record_failure(permit, start + Duration::from_secs(10)),
            Err(PinAttemptCompletionError::ExpiredPermit)
        );
        assert_eq!(throttle.failed_attempts(), 0);
        assert_eq!(
            throttle.retry_after(start + Duration::from_secs(10)),
            Duration::ZERO
        );
    }

    #[test]
    fn external_mutex_allows_only_one_parallel_reservation() {
        let throttle = Arc::new(Mutex::new(PinThrottle::new(test_config()).unwrap()));
        let now = Instant::now();
        let mut workers = Vec::new();

        for _ in 0..8 {
            let throttle = Arc::clone(&throttle);
            workers.push(thread::spawn(move || {
                throttle.lock().unwrap().begin_attempt(now).is_ok()
            }));
        }

        let admitted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 1);
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        assert_eq!(
            PinThrottle::new(PinThrottleConfig {
                base_delay: Duration::ZERO,
                ..test_config()
            })
            .unwrap_err(),
            PinThrottleConfigError::ZeroBaseDelay
        );
        assert_eq!(
            PinThrottle::new(PinThrottleConfig {
                base_delay: Duration::from_secs(2),
                max_delay: Duration::from_secs(1),
                ..test_config()
            })
            .unwrap_err(),
            PinThrottleConfigError::MaximumBelowBase
        );
        assert_eq!(
            PinThrottle::new(PinThrottleConfig {
                attempt_timeout: Duration::ZERO,
                ..test_config()
            })
            .unwrap_err(),
            PinThrottleConfigError::ZeroAttemptTimeout
        );
    }
}
