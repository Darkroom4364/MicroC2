use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::fmt;

pub const TASK_SCHEMA_VERSION: u32 = 1;
pub const MAX_TASK_TIMEOUT_SECONDS: u64 = 3_600;
pub const MAX_SHELL_COMMAND_CHARS: usize = 8_192;
pub const MAX_MODULE_INPUT_BYTES: usize = 64 << 10;
pub const MAX_MODULE_OUTPUT_BYTES: usize = 64 << 10;
pub const MAX_TASK_OUTPUT_CHARS: usize = 1_048_576;
pub const MAX_TASK_ERROR_CHARS: usize = 8_192;
const GOVERNED_MODULE_MAX_INPUT_BYTES: usize = 1024;
const GOVERNED_MODULE_MAX_OUTPUT_BYTES: usize = 1024;
const GOVERNED_MODULE_MAX_TIMEOUT_SECONDS: u64 = 5;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskType {
    Shell,
    Module,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Queued,
    Dispatched,
    Running,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskArguments {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub schema_version: u32,
    pub id: String,
    pub agent_id: String,
    #[serde(rename = "type")]
    pub task_type: TaskType,
    pub arguments: TaskArguments,
    pub timeout_seconds: u64,
    pub status: TaskStatus,
    pub created_at: String,
    pub queued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatched_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<TaskResult>,
}

impl Task {
    pub fn validate_for_agent(&self, expected_agent_id: &str) -> Result<(), TaskValidationError> {
        if self.schema_version != TASK_SCHEMA_VERSION {
            return Err(TaskValidationError::new(format!(
                "unsupported task schema version {}; expected {}",
                self.schema_version, TASK_SCHEMA_VERSION
            )));
        }
        validate_identifier("id", &self.id)?;
        validate_identifier("agent_id", &self.agent_id)?;
        validate_identifier("runtime agent_id", expected_agent_id)?;
        if self.agent_id != expected_agent_id {
            return Err(TaskValidationError::new(format!(
                "task agent_id {:?} does not match runtime agent {:?}",
                self.agent_id, expected_agent_id
            )));
        }
        if self.status != TaskStatus::Dispatched {
            return Err(TaskValidationError::new(format!(
                "polled task must have dispatched status, got {:?}",
                self.status
            )));
        }
        if self.result.is_some() {
            return Err(TaskValidationError::new(
                "dispatched task must not already contain a result",
            ));
        }
        if self.dispatched_at.is_none() {
            return Err(TaskValidationError::new(
                "dispatched task must include dispatched_at",
            ));
        }
        if self.started_at.is_some() {
            return Err(TaskValidationError::new(
                "dispatched task must not include started_at",
            ));
        }
        if self.completed_at.is_some() {
            return Err(TaskValidationError::new(
                "dispatched task must not include completed_at",
            ));
        }
        if self.expires_at.is_none() {
            return Err(TaskValidationError::new(
                "dispatched task must include expires_at",
            ));
        }
        match self.task_type {
            TaskType::Shell => {
                if self.arguments.module_id.is_some() || self.arguments.input.is_some() {
                    return Err(TaskValidationError::new(
                        "shell task arguments must contain only command",
                    ));
                }
                if self.arguments.command.trim().is_empty() {
                    return Err(TaskValidationError::new(
                        "shell task arguments.command is required",
                    ));
                }
                if self.arguments.command.chars().count() > MAX_SHELL_COMMAND_CHARS {
                    return Err(TaskValidationError::new(format!(
                        "shell task arguments.command must be at most {} characters",
                        MAX_SHELL_COMMAND_CHARS
                    )));
                }
            }
            TaskType::Module => {
                if !self.arguments.command.is_empty() {
                    return Err(TaskValidationError::new(
                        "module task arguments.command is not valid",
                    ));
                }
                let module_id = self.arguments.module_id.as_deref().ok_or_else(|| {
                    TaskValidationError::new("module task arguments.module_id is required")
                })?;
                if module_id != crate::modules::CAPABILITY_INVENTORY_ID {
                    return Err(TaskValidationError::new("unsupported module task"));
                }
                let input = self.arguments.input.as_ref().ok_or_else(|| {
                    TaskValidationError::new("module task arguments.input is required")
                })?;
                if !input.as_object().is_some_and(|object| object.is_empty()) {
                    return Err(TaskValidationError::new(
                        "module task arguments.input must be an empty object",
                    ));
                }
                let input_bytes = serde_json::to_vec(input).map_err(|_| {
                    TaskValidationError::new("module task arguments.input must be JSON")
                })?;
                if input_bytes.len() > GOVERNED_MODULE_MAX_INPUT_BYTES {
                    return Err(TaskValidationError::new(format!(
                        "module task arguments.input must be at most {} bytes",
                        GOVERNED_MODULE_MAX_INPUT_BYTES
                    )));
                }
            }
        }
        let max_timeout_seconds = if matches!(self.task_type, TaskType::Module) {
            GOVERNED_MODULE_MAX_TIMEOUT_SECONDS
        } else {
            MAX_TASK_TIMEOUT_SECONDS
        };
        if !(1..=max_timeout_seconds).contains(&self.timeout_seconds) {
            return Err(TaskValidationError::new(format!(
                "timeout_seconds must be between 1 and {}",
                max_timeout_seconds
            )));
        }

        validate_timestamp("created_at", &self.created_at)?;
        validate_timestamp("queued_at", &self.queued_at)?;
        validate_optional_timestamp("dispatched_at", self.dispatched_at.as_deref())?;
        validate_optional_timestamp("started_at", self.started_at.as_deref())?;
        validate_optional_timestamp("completed_at", self.completed_at.as_deref())?;
        validate_optional_timestamp("expires_at", self.expires_at.as_deref())?;

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskOutcome {
    Completed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskOutput {
    pub stdout: String,
    pub stderr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResult {
    pub schema_version: u32,
    pub task_id: String,
    pub agent_id: String,
    pub outcome: TaskOutcome,
    pub started_at: String,
    pub completed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub output: TaskOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl TaskResult {
    pub fn validate(&self) -> Result<(), TaskValidationError> {
        if self.schema_version != TASK_SCHEMA_VERSION {
            return Err(TaskValidationError::new(format!(
                "unsupported result schema version {}; expected {}",
                self.schema_version, TASK_SCHEMA_VERSION
            )));
        }
        validate_identifier("task_id", &self.task_id)?;
        validate_identifier("agent_id", &self.agent_id)?;
        validate_timestamp("started_at", &self.started_at)?;
        validate_timestamp("completed_at", &self.completed_at)?;
        let started_at = DateTime::parse_from_rfc3339(&self.started_at)
            .map_err(|_| TaskValidationError::new("started_at must be an RFC3339 timestamp"))?;
        let completed_at = DateTime::parse_from_rfc3339(&self.completed_at)
            .map_err(|_| TaskValidationError::new("completed_at must be an RFC3339 timestamp"))?;
        if completed_at < started_at {
            return Err(TaskValidationError::new(
                "completed_at must not precede started_at",
            ));
        }
        if self.output.stdout.chars().count() > MAX_TASK_OUTPUT_CHARS {
            return Err(TaskValidationError::new(format!(
                "output.stdout must be at most {} characters",
                MAX_TASK_OUTPUT_CHARS
            )));
        }
        if self.output.stderr.chars().count() > MAX_TASK_OUTPUT_CHARS {
            return Err(TaskValidationError::new(format!(
                "output.stderr must be at most {} characters",
                MAX_TASK_OUTPUT_CHARS
            )));
        }
        if let Some(data) = &self.output.data {
            if !data.is_object() {
                return Err(TaskValidationError::new(
                    "output.data must be a JSON object",
                ));
            }
            let data_bytes = serde_json::to_vec(data)
                .map_err(|_| TaskValidationError::new("output.data must be JSON"))?;
            if data_bytes.len() > GOVERNED_MODULE_MAX_OUTPUT_BYTES {
                return Err(TaskValidationError::new(format!(
                    "output.data must be at most {} bytes",
                    GOVERNED_MODULE_MAX_OUTPUT_BYTES
                )));
            }
        }
        if self
            .error
            .as_deref()
            .is_some_and(|error| error.chars().count() > MAX_TASK_ERROR_CHARS)
        {
            return Err(TaskValidationError::new(format!(
                "error must be at most {} characters",
                MAX_TASK_ERROR_CHARS
            )));
        }
        match &self.outcome {
            TaskOutcome::Completed => {
                if self.exit_code != Some(0) {
                    return Err(TaskValidationError::new(
                        "completed result must include exit_code 0",
                    ));
                }
                if self.error.is_some() {
                    return Err(TaskValidationError::new(
                        "completed result must not include error",
                    ));
                }
            }
            TaskOutcome::Failed => {
                if !self
                    .error
                    .as_deref()
                    .is_some_and(|error| !error.trim().is_empty())
                {
                    return Err(TaskValidationError::new(
                        "failed result must include a nonblank error",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskStatusUpdate {
    pub schema_version: u32,
    pub task_id: String,
    pub agent_id: String,
    pub status: TaskStatus,
    pub timestamp: String,
}

impl TaskStatusUpdate {
    pub fn running(task: &Task, timestamp: String) -> Self {
        Self {
            schema_version: TASK_SCHEMA_VERSION,
            task_id: task.id.clone(),
            agent_id: task.agent_id.clone(),
            status: TaskStatus::Running,
            timestamp,
        }
    }

    pub fn validate(&self) -> Result<(), TaskValidationError> {
        if self.schema_version != TASK_SCHEMA_VERSION {
            return Err(TaskValidationError::new(format!(
                "unsupported status schema version {}; expected {}",
                self.schema_version, TASK_SCHEMA_VERSION
            )));
        }
        validate_identifier("task_id", &self.task_id)?;
        validate_identifier("agent_id", &self.agent_id)?;
        if self.status != TaskStatus::Running {
            return Err(TaskValidationError::new(
                "agent status updates may only transition a task to running",
            ));
        }
        validate_timestamp("timestamp", &self.timestamp)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskValidationError {
    message: String,
}

impl TaskValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TaskValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for TaskValidationError {}

fn validate_timestamp(field: &str, value: &str) -> Result<(), TaskValidationError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| TaskValidationError::new(format!("{field} must be an RFC3339 timestamp")))?;
    let zero = DateTime::parse_from_rfc3339("0001-01-01T00:00:00Z")
        .map_err(|_| TaskValidationError::new("internal zero timestamp is invalid"))?;
    if parsed == zero {
        return Err(TaskValidationError::new(format!(
            "{field} must not be the zero instant"
        )));
    }
    Ok(())
}

pub fn validate_identifier(field: &str, value: &str) -> Result<(), TaskValidationError> {
    if value.is_empty() {
        return Err(TaskValidationError::new(format!("{field} is required")));
    }
    if value.len() > 128 {
        return Err(TaskValidationError::new(format!(
            "{field} must be at most 128 bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(TaskValidationError::new(format!(
            "{field} contains unsupported characters"
        )));
    }
    Ok(())
}

fn validate_optional_timestamp(
    field: &str,
    value: Option<&str>,
) -> Result<(), TaskValidationError> {
    if let Some(value) = value {
        validate_timestamp(field, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const GOLDEN_TASK: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/schemas/examples/task-v1.json"
    ));
    const GOLDEN_RESULT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/schemas/examples/task-result-v1.json"
    ));
    const GOLDEN_DISPATCHED_TASK: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/schemas/examples/task-dispatched-v1.json"
    ));
    const GOLDEN_FAILED_RESULT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/schemas/examples/task-result-failed-v1.json"
    ));
    const GOLDEN_STATUS_UPDATE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/schemas/examples/task-status-update-v1.json"
    ));
    const GOLDEN_MODULE_DISPATCHED_TASK: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/schemas/examples/task-module-dispatched-v1.json"
    ));
    const GOLDEN_MODULE_RESULT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/schemas/examples/task-module-result-v1.json"
    ));

    fn sample_task() -> Task {
        Task {
            schema_version: TASK_SCHEMA_VERSION,
            id: "task-one".to_string(),
            agent_id: "agent-one".to_string(),
            task_type: TaskType::Shell,
            arguments: TaskArguments {
                command: "echo hello".to_string(),
                ..TaskArguments::default()
            },
            timeout_seconds: 30,
            status: TaskStatus::Dispatched,
            created_at: "2026-07-23T16:00:00Z".to_string(),
            queued_at: "2026-07-23T16:00:01Z".to_string(),
            dispatched_at: Some("2026-07-23T16:00:02Z".to_string()),
            started_at: None,
            completed_at: None,
            expires_at: Some("2026-07-23T16:00:32Z".to_string()),
            result: None,
        }
    }

    #[test]
    fn task_v1_round_trips_with_normative_wire_names() {
        let task = sample_task();
        let encoded = serde_json::to_value(&task).expect("serialize task");

        assert_eq!(encoded["schema_version"], 1);
        assert_eq!(encoded["type"], "shell");
        assert_eq!(encoded["status"], "dispatched");
        assert_eq!(encoded["arguments"]["command"], "echo hello");
        assert!(encoded.get("started_at").is_none());

        let decoded: Task = serde_json::from_value(encoded).expect("deserialize task");
        assert_eq!(decoded, task);
        decoded.validate_for_agent("agent-one").expect("valid task");
    }

    #[test]
    fn shared_golden_examples_deserialize_and_round_trip() {
        let task: Task = serde_json::from_str(GOLDEN_TASK).expect("deserialize golden task");
        assert_eq!(
            serde_json::to_value(&task).expect("serialize golden task"),
            serde_json::from_str::<serde_json::Value>(GOLDEN_TASK).expect("parse task JSON")
        );

        let result: TaskResult =
            serde_json::from_str(GOLDEN_RESULT).expect("deserialize golden result");
        result.validate().expect("validate golden result");
        assert_eq!(
            serde_json::to_value(&result).expect("serialize golden result"),
            serde_json::from_str::<serde_json::Value>(GOLDEN_RESULT).expect("parse result JSON")
        );

        let update: TaskStatusUpdate =
            serde_json::from_str(GOLDEN_STATUS_UPDATE).expect("deserialize golden status update");
        update.validate().expect("validate golden status update");
        assert_eq!(
            serde_json::to_value(&update).expect("serialize golden status update"),
            serde_json::from_str::<serde_json::Value>(GOLDEN_STATUS_UPDATE)
                .expect("parse status update JSON")
        );

        let dispatched: Task =
            serde_json::from_str(GOLDEN_DISPATCHED_TASK).expect("deserialize dispatched task");
        dispatched
            .validate_for_agent("agent-01")
            .expect("validate dispatched task");

        let failed: TaskResult =
            serde_json::from_str(GOLDEN_FAILED_RESULT).expect("deserialize failed result");
        failed.validate().expect("validate failed result");

        let module_task: Task =
            serde_json::from_str(GOLDEN_MODULE_DISPATCHED_TASK).expect("deserialize module task");
        module_task
            .validate_for_agent("agent-01")
            .expect("validate dispatched module task");
        assert_eq!(
            serde_json::to_value(&module_task).expect("serialize module task"),
            serde_json::from_str::<serde_json::Value>(GOLDEN_MODULE_DISPATCHED_TASK)
                .expect("parse module task JSON")
        );

        let module_result: TaskResult =
            serde_json::from_str(GOLDEN_MODULE_RESULT).expect("deserialize module result");
        module_result
            .validate()
            .expect("validate module result envelope");
        assert_eq!(
            serde_json::to_value(&module_result).expect("serialize module result"),
            serde_json::from_str::<serde_json::Value>(GOLDEN_MODULE_RESULT)
                .expect("parse module result JSON")
        );
    }

    #[test]
    fn task_parser_rejects_unsupported_types() {
        let mut encoded = serde_json::to_value(sample_task()).expect("serialize task");
        encoded["type"] = json!("pivot");

        let err = serde_json::from_value::<Task>(encoded).expect_err("unsupported task type");
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn module_task_requires_closed_arguments_and_bounds_input() {
        let mut task = sample_task();
        task.task_type = TaskType::Module;
        task.arguments = TaskArguments {
            command: String::new(),
            module_id: Some("agent.capability_inventory.v1".to_string()),
            input: Some(json!({})),
        };
        task.timeout_seconds = GOVERNED_MODULE_MAX_TIMEOUT_SECONDS;
        task.validate_for_agent("agent-one")
            .expect("valid module task envelope");

        task.arguments.command = "whoami".to_string();
        assert!(task.validate_for_agent("agent-one").is_err());

        task.arguments.command.clear();
        task.arguments.module_id = Some("unknown.module.v1".to_string());
        assert!(task.validate_for_agent("agent-one").is_err());

        task.arguments.module_id = Some(crate::modules::CAPABILITY_INVENTORY_ID.to_string());
        task.arguments.input = Some(json!({"unexpected": true}));
        assert!(task.validate_for_agent("agent-one").is_err());

        task.arguments.input = Some(json!({}));
        task.timeout_seconds = GOVERNED_MODULE_MAX_TIMEOUT_SECONDS + 1;
        assert!(task.validate_for_agent("agent-one").is_err());
    }

    #[test]
    fn task_validation_rejects_wrong_agent_empty_command_and_timeout_bounds() {
        let task = sample_task();
        assert!(task.validate_for_agent("agent-two").is_err());

        let mut empty_command = task.clone();
        empty_command.arguments.command = "  ".to_string();
        assert!(empty_command.validate_for_agent("agent-one").is_err());

        let mut zero_timeout = task.clone();
        zero_timeout.timeout_seconds = 0;
        assert!(zero_timeout.validate_for_agent("agent-one").is_err());

        let mut queued = task.clone();
        queued.status = TaskStatus::Queued;
        assert!(queued.validate_for_agent("agent-one").is_err());

        let mut missing_dispatch = task.clone();
        missing_dispatch.dispatched_at = None;
        assert!(missing_dispatch.validate_for_agent("agent-one").is_err());

        let mut already_started = task.clone();
        already_started.started_at = Some("2026-07-23T16:00:03Z".to_string());
        assert!(already_started.validate_for_agent("agent-one").is_err());

        let mut already_completed = task.clone();
        already_completed.completed_at = Some("2026-07-23T16:00:04Z".to_string());
        assert!(already_completed.validate_for_agent("agent-one").is_err());

        let mut missing_expiry = task.clone();
        missing_expiry.expires_at = None;
        assert!(missing_expiry.validate_for_agent("agent-one").is_err());

        let mut invalid_id = task.clone();
        invalid_id.id = "task/one".to_string();
        assert!(invalid_id.validate_for_agent("agent-one").is_err());

        let mut excessive_timeout = task;
        excessive_timeout.timeout_seconds = MAX_TASK_TIMEOUT_SECONDS + 1;
        assert!(excessive_timeout.validate_for_agent("agent-one").is_err());
    }

    #[test]
    fn result_and_status_update_round_trip() {
        let task = sample_task();
        let update = TaskStatusUpdate::running(&task, "2026-07-23T16:00:03Z".to_string());
        update.validate().expect("valid status update");
        let encoded_update = serde_json::to_string(&update).expect("serialize update");
        assert!(encoded_update.contains("\"status\":\"running\""));
        assert_eq!(
            serde_json::from_str::<TaskStatusUpdate>(&encoded_update).expect("deserialize update"),
            update
        );

        let result = TaskResult {
            schema_version: TASK_SCHEMA_VERSION,
            task_id: task.id,
            agent_id: task.agent_id,
            outcome: TaskOutcome::Completed,
            started_at: "2026-07-23T16:00:03Z".to_string(),
            completed_at: "2026-07-23T16:00:04Z".to_string(),
            exit_code: Some(0),
            output: TaskOutput {
                stdout: "hello\n".to_string(),
                stderr: String::new(),
                data: None,
            },
            error: None,
        };
        result.validate().expect("valid result");
        let mut oversized_data = result.clone();
        oversized_data.output.data = Some(json!({"evidence": "x".repeat(1024)}));
        assert!(oversized_data.validate().is_err());
        let encoded_result = serde_json::to_string(&result).expect("serialize result");
        assert!(encoded_result.contains("\"outcome\":\"completed\""));
        assert_eq!(
            serde_json::from_str::<TaskResult>(&encoded_result).expect("deserialize result"),
            result
        );

        let invalid_result = TaskResult {
            started_at: "2026-07-23T16:00:04Z".to_string(),
            completed_at: "2026-07-23T16:00:03Z".to_string(),
            ..result
        };
        assert!(invalid_result.validate().is_err());
    }

    #[test]
    fn result_and_status_update_reject_zero_timestamps() {
        let task = sample_task();
        let update = TaskStatusUpdate::running(&task, "0001-01-01T00:00:00Z".to_string());
        assert!(update.validate().is_err());

        let result = TaskResult {
            schema_version: TASK_SCHEMA_VERSION,
            task_id: task.id,
            agent_id: task.agent_id,
            outcome: TaskOutcome::Completed,
            started_at: "0001-01-01T00:00:00Z".to_string(),
            completed_at: "2026-07-23T16:00:04Z".to_string(),
            exit_code: Some(0),
            output: TaskOutput {
                stdout: String::new(),
                stderr: String::new(),
                data: None,
            },
            error: None,
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn result_validation_enforces_caps_and_outcome_coherence() {
        let valid = TaskResult {
            schema_version: TASK_SCHEMA_VERSION,
            task_id: "task-one".to_string(),
            agent_id: "agent-one".to_string(),
            outcome: TaskOutcome::Completed,
            started_at: "2026-07-23T16:00:03Z".to_string(),
            completed_at: "2026-07-23T16:00:04Z".to_string(),
            exit_code: Some(0),
            output: TaskOutput {
                stdout: String::new(),
                stderr: String::new(),
                data: None,
            },
            error: None,
        };
        valid.validate().expect("coherent completed result");

        let mut oversized_stdout = valid.clone();
        oversized_stdout.output.stdout = "x".repeat(MAX_TASK_OUTPUT_CHARS + 1);
        assert!(oversized_stdout.validate().is_err());

        let mut oversized_error = valid.clone();
        oversized_error.outcome = TaskOutcome::Failed;
        oversized_error.error = Some("x".repeat(MAX_TASK_ERROR_CHARS + 1));
        assert!(oversized_error.validate().is_err());

        let mut completed_with_error = valid.clone();
        completed_with_error.error = Some("unexpected".to_string());
        assert!(completed_with_error.validate().is_err());

        let mut completed_without_zero = valid.clone();
        completed_without_zero.exit_code = Some(1);
        assert!(completed_without_zero.validate().is_err());

        let mut failed_without_error = valid;
        failed_without_error.outcome = TaskOutcome::Failed;
        failed_without_error.exit_code = Some(1);
        assert!(failed_without_error.validate().is_err());
    }

    #[test]
    fn task_parser_rejects_unknown_fields_for_schema_v1() {
        let mut encoded = serde_json::to_value(sample_task()).expect("serialize task");
        encoded["future_metadata"] = json!({"key": "value"});

        let err = serde_json::from_value::<Task>(encoded).expect_err("strict v1 task");
        assert!(err.to_string().contains("unknown field"));

        let mut nested = serde_json::to_value(sample_task()).expect("serialize task");
        nested["arguments"]["future_argument"] = json!(true);
        let err = serde_json::from_value::<Task>(nested).expect_err("strict v1 arguments");
        assert!(err.to_string().contains("unknown field"));

        let mut result =
            serde_json::from_str::<serde_json::Value>(GOLDEN_RESULT).expect("parse result");
        result["future_result_field"] = json!(true);
        let err = serde_json::from_value::<TaskResult>(result).expect_err("strict v1 task result");
        assert!(err.to_string().contains("unknown field"));

        let mut update = serde_json::from_str::<serde_json::Value>(GOLDEN_STATUS_UPDATE)
            .expect("parse status update");
        update["future_status_field"] = json!(true);
        let err = serde_json::from_value::<TaskStatusUpdate>(update)
            .expect_err("strict v1 task status update");
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn identifier_policy_is_ascii_and_bounded() {
        for value in ["agent-one", "agent_1", "agent.1", "agent:1", "A9"] {
            validate_identifier("agent_id", value).expect("contract-valid identifier");
        }
        let too_long = "a".repeat(129);
        for value in ["", "agent one", "agent/one", "agént", too_long.as_str()] {
            assert!(
                validate_identifier("agent_id", value).is_err(),
                "unexpected valid identifier {value:?}"
            );
        }
    }

    #[test]
    fn task_validation_enforces_shell_command_size() {
        let mut task = sample_task();
        task.arguments.command = "x".repeat(MAX_SHELL_COMMAND_CHARS);
        task.validate_for_agent("agent-one")
            .expect("command at character cap");

        task.arguments.command = "é".repeat(MAX_SHELL_COMMAND_CHARS + 1);
        assert!(task.validate_for_agent("agent-one").is_err());
    }

    #[test]
    fn v1_contract_conformance_vectors() {
        const CORPUS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../docs/schemas/contract-vectors-v1.json"
        ));

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VectorEntry {
            id: String,
            schema_target: String,
            expected: String,
            value: serde_json::Value,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Corpus {
            schema_version: u32,
            vectors: Vec<VectorEntry>,
        }

        let corpus: Corpus =
            serde_json::from_str(CORPUS).expect("deserialize contract vectors corpus");

        assert_eq!(corpus.schema_version, 1, "corpus schema_version must be 1");
        assert!(
            !corpus.vectors.is_empty(),
            "corpus vectors must be nonempty"
        );

        let mut seen = std::collections::HashSet::new();
        for v in &corpus.vectors {
            assert!(!v.id.is_empty(), "vector id must be nonempty");
            assert!(seen.insert(&v.id), "duplicate vector id {:?}", v.id);

            assert!(
                v.schema_target == "task-result-v1.schema.json"
                    || v.schema_target == "task-status-update-v1.schema.json",
                "unknown schema_target {:?} in vector {:?}",
                v.schema_target,
                v.id
            );

            assert!(
                v.expected == "accept" || v.expected == "reject",
                "invalid expected value {:?} in vector {:?}",
                v.expected,
                v.id
            );
        }

        for v in &corpus.vectors {
            let accepted = match v.schema_target.as_str() {
                "task-result-v1.schema.json" => {
                    match serde_json::from_value::<TaskResult>(v.value.clone()) {
                        Ok(result) => result.validate().is_ok(),
                        Err(_) => false,
                    }
                }
                "task-status-update-v1.schema.json" => {
                    match serde_json::from_value::<TaskStatusUpdate>(v.value.clone()) {
                        Ok(update) => update.validate().is_ok(),
                        Err(_) => false,
                    }
                }
                _ => unreachable!("schema_target already validated"),
            };

            let want_accept = v.expected == "accept";
            assert_eq!(
                accepted, want_accept,
                "vector {:?} target {}: expected accepted={}, got accepted={}",
                v.id, v.schema_target, want_accept, accepted
            );
        }
    }
}
