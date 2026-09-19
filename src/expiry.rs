use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Status {
    Ok,
    Warning,
    Expired,
}

/// Whole days between `now` and `not_after` — negative if already expired.
/// Pure, so every rule around "how close is too close" is testable
/// without an actual TLS handshake.
pub fn days_until(not_after: SystemTime, now: SystemTime) -> i64 {
    match not_after.duration_since(now) {
        Ok(remaining) => (remaining.as_secs() / 86400) as i64,
        Err(elapsed) => -((elapsed.duration().as_secs() / 86400) as i64) - 1,
    }
}

pub fn status(days_remaining: i64, warn_threshold: i64) -> Status {
    if days_remaining < 0 {
        Status::Expired
    } else if days_remaining <= warn_threshold {
        Status::Warning
    } else {
        Status::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn counts_whole_days_remaining() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let not_after = now + Duration::from_secs(10 * 86400);
        assert_eq!(days_until(not_after, now), 10);
    }

    #[test]
    fn already_expired_is_negative() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let not_after = now - Duration::from_secs(5 * 86400);
        assert!(days_until(not_after, now) < 0);
    }

    #[test]
    fn status_classifies_correctly() {
        assert_eq!(status(60, 30), Status::Ok);
        assert_eq!(status(30, 30), Status::Warning);
        assert_eq!(status(5, 30), Status::Warning);
        assert_eq!(status(-1, 30), Status::Expired);
        assert_eq!(status(-100, 30), Status::Expired);
    }

    #[test]
    fn zero_days_remaining_is_a_warning_not_yet_expired() {
        assert_eq!(status(0, 30), Status::Warning);
    }
}
