/// Safe mutex handling utilities to prevent panic propagation from poisoned mutexes
use std::sync::{Mutex, MutexGuard, PoisonError};
use log::{error, warn};

/// Result type for mutex operations
pub type MutexResult<T> = Result<T, String>;

/// Safely lock a mutex, recovering from poison errors
pub fn safe_lock<T>(mutex: &Mutex<T>) -> MutexResult<MutexGuard<T>> {
    match mutex.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => {
            warn!("[MUTEX] Recovering from poisoned mutex");
            // Recover the guard from the poisoned state
            Ok(poisoned.into_inner())
        }
    }
}

/// Execute a closure with a safely locked mutex
pub fn with_lock<T, F, R>(mutex: &Mutex<T>, f: F) -> MutexResult<R>
where
    F: FnOnce(&T) -> R,
{
    let guard = safe_lock(mutex)?;
    Ok(f(&*guard))
}

/// Execute a closure with a safely locked mutex (mutable)
pub fn with_lock_mut<T, F, R>(mutex: &Mutex<T>, f: F) -> MutexResult<R>
where
    F: FnOnce(&mut T) -> R,
{
    let mut guard = safe_lock(mutex)?;
    Ok(f(&mut *guard))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_safe_lock_normal() {
        let mutex = Mutex::new(42);
        let result = safe_lock(&mutex);
        assert!(result.is_ok());
        assert_eq!(*result.unwrap(), 42);
    }

    #[test]
    fn test_safe_lock_recovers_from_poison() {
        let mutex = Arc::new(Mutex::new(0));
        let mutex_clone = mutex.clone();

        // Create a poisoned mutex by panicking while holding the lock
        let handle = thread::spawn(move || {
            let _guard = mutex_clone.lock().unwrap();
            panic!("Intentional panic to poison mutex");
        });

        // Wait for thread to panic
        let _ = handle.join();

        // Our safe_lock should recover from the poison
        let result = safe_lock(&*mutex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_lock() {
        let mutex = Mutex::new(vec![1, 2, 3]);
        let result = with_lock(&mutex, |v| v.len());
        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn test_with_lock_mut() {
        let mutex = Mutex::new(vec![1, 2, 3]);
        let result = with_lock_mut(&mutex, |v| {
            v.push(4);
            v.len()
        });
        assert_eq!(result.unwrap(), 4);
    }
}
