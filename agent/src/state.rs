use crate::dormant::MemoryProtector;
use once_cell::sync::Lazy;
use std::sync::Mutex;

//  Simplified initialization - no initial state needed
pub static MEMORY_PROTECTOR: Lazy<Mutex<MemoryProtector>> =
    Lazy::new(|| Mutex::new(MemoryProtector::new()));
