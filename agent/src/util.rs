/// Returns the current Unix epoch timestamp in seconds.
pub fn now_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_jitter(base: u64, jitter: u64) -> u64 {
    if jitter == 0 {
        return base;
    }
    base + (rand::random::<u64>() % (jitter + 1))
}