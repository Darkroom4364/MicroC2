pub fn random_jitter(base: u64, jitter: u64) -> u64 {
    if jitter == 0 {
        return base;
    }
    base + (rand::random::<u64>() % (jitter + 1))
}
