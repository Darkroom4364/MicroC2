//! Compile-time registry for typed, bounded agent modules.
//!
//! A module is not arbitrary operator code. It has a stable identifier, a
//! closed input contract, and an implementation compiled into the payload.

use serde_json::{json, Value};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use sysinfo::System;

pub const CAPABILITY_INVENTORY_ID: &str = "agent.capability_inventory.v1";

type ModuleFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, ModuleError>> + Send + 'a>>;
type ModuleExecutor = for<'a> fn(&'a Value) -> ModuleFuture<'a>;

#[derive(Clone, Copy)]
struct ModuleDefinition {
    id: &'static str,
    validate_input: fn(&Value) -> Result<(), ModuleError>,
    execute: ModuleExecutor,
}

const MODULES: [ModuleDefinition; 1] = [ModuleDefinition {
    id: CAPABILITY_INVENTORY_ID,
    validate_input: validate_empty_input,
    execute: execute_capability_inventory,
}];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleError {
    message: String,
}

impl ModuleError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ModuleError {}

/// Returns every module this payload can execute. The heartbeat advertises
/// these IDs so the server never assigns a module to an incompatible agent.
pub fn registered_module_ids() -> Vec<String> {
    MODULES.iter().map(|module| module.id.to_string()).collect()
}

/// Executes a compile-time registered module after validating its input.
pub async fn execute(module_id: &str, input: &Value) -> Result<Value, ModuleError> {
    let module = MODULES
        .iter()
        .find(|candidate| candidate.id == module_id)
        .ok_or_else(|| ModuleError::new("unsupported module"))?;
    (module.validate_input)(input)?;
    (module.execute)(input).await
}

fn validate_empty_input(input: &Value) -> Result<(), ModuleError> {
    match input.as_object() {
        Some(object) if object.is_empty() => Ok(()),
        _ => Err(ModuleError::new("module input must be an empty object")),
    }
}

fn execute_capability_inventory(_input: &Value) -> ModuleFuture<'_> {
    Box::pin(async {
        let system = System::new_all();
        let logical_cpu_count = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        Ok(json!({
            "operating_system": std::env::consts::OS,
            "architecture": std::env::consts::ARCH,
            "logical_cpu_count": logical_cpu_count,
            "total_memory_bytes": system.total_memory(),
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn registry_advertises_only_compile_time_modules() {
        assert_eq!(registered_module_ids(), vec![CAPABILITY_INVENTORY_ID]);
    }

    #[tokio::test]
    async fn capability_inventory_rejects_input_and_returns_closed_output() {
        assert!(execute(CAPABILITY_INVENTORY_ID, &json!({"extra": true}))
            .await
            .is_err());
        assert!(execute("unknown.module.v1", &json!({})).await.is_err());

        let output = execute(CAPABILITY_INVENTORY_ID, &json!({}))
            .await
            .expect("execute capability inventory");
        let object = output.as_object().expect("output object");
        assert_eq!(object.len(), 4);
        assert!(object["operating_system"].is_string());
        assert!(object["architecture"].is_string());
        assert!(object["logical_cpu_count"]
            .as_u64()
            .is_some_and(|count| count > 0));
        assert!(object["total_memory_bytes"].as_u64().is_some());
    }
}
