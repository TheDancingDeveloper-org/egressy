use rand::Rng;

const BACKOFF: [u64; 5] = [2, 5, 10, 30, 60];

pub fn retry_delay_seconds(attempt: u32, maximum: u64) -> u64 {
    let index = attempt.saturating_sub(1) as usize;
    let base = BACKOFF
        .get(index)
        .copied()
        .unwrap_or_else(|| 60_u64.saturating_mul(2_u64.saturating_pow((index - 4).min(2) as u32)))
        .min(maximum);
    let jitter = rand::rng().random_range(0..=(base / 5).max(1));
    base.saturating_add(jitter).min(maximum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_backoff_is_bounded() {
        for attempt in 1..100 {
            assert!(retry_delay_seconds(attempt, 300) <= 300);
        }
        assert!((2..=3).contains(&retry_delay_seconds(1, 300)));
    }
}
