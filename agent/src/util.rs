pub fn random_jitter(base: u64, jitter: u64) -> u64 {
    if jitter == 0 {
        return base;
    }
    base + (rand::random::<u64>() % (jitter + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_jitter_returns_base_without_jitter() {
        assert_eq!(random_jitter(30, 0), 30);
    }

    #[test]
    fn random_jitter_stays_within_inclusive_bounds() {
        for _ in 0..256 {
            let value = random_jitter(30, 5);
            assert!(
                (30..=35).contains(&value),
                "expected jittered value in 30..=35, got {}",
                value
            );
        }
    }
}
